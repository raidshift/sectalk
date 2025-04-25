use crossterm::{
    cursor::{MoveToColumn, MoveToNextLine},
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use futures_util::StreamExt;
use hex::ToHex;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{
    io::{Write, stdout},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message},
};

// const WS_URL: &str = "ws://sectalk.my.to/ws";

const WS_URL: &str = "ws://127.0.0.1:3030/ws/";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    let mut input = String::new();
    let mut cursor_pos = 0;

    let should_exit = Arc::new(AtomicBool::new(false));
    let should_exit_ws = should_exit.clone();

    let (tx, rx) = mpsc::channel();

    let thread_tx = tx.clone();
    let request = WS_URL.into_client_request()?;

    let ws_connection = connect_async(request).await?;

    let (mut ws_write, mut ws_read) = ws_connection.0.split();

    println!("WebSocket connected!");

    let runtime = tokio::runtime::Runtime::new()?;

    thread::spawn(move || {
        runtime.block_on(async {
            while let Some(msg) = ws_read.next().await {
                if let Ok(msg) = msg {
                    match msg {
                        Message::Binary(msg) => {
                            thread_tx.send(format!("Server: {}", msg.encode_hex::<String>())).unwrap();
                        }
                        _ => {
                            break;
                        }
                    }
                }
            }
        });
        should_exit_ws.store(true, Ordering::SeqCst);
    });

    print_prompt(&input, cursor_pos);

    loop {
        if should_exit.load(Ordering::SeqCst) {
            break;
        }
        if let Ok(message) = rx.try_recv() {
            let current_input = input.clone();
            let current_pos = cursor_pos;
            execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine)).unwrap();

            println!("> {}", message);

            print_prompt(&current_input, current_pos);
            input = current_input;
            cursor_pos = current_pos;

            stdout.flush().unwrap();
        }

        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key_event) = event::read().unwrap() {
                match key_event.code {
                    KeyCode::Char(c) => {
                        input.insert(cursor_pos, c);
                        cursor_pos += 1;
                    }
                    KeyCode::Left => {
                        if cursor_pos > 0 {
                            cursor_pos -= 1;
                        }
                    }
                    KeyCode::Right => {
                        if cursor_pos < input.len() {
                            cursor_pos += 1;
                        }
                    }
                    KeyCode::Backspace => {
                        if cursor_pos > 0 {
                            input.remove(cursor_pos - 1);
                            cursor_pos -= 1;
                        }
                    }
                    KeyCode::Enter => {
                        if !input.is_empty() {
                            execute!(stdout, MoveToNextLine(1), Clear(ClearType::CurrentLine), MoveToColumn(0)).unwrap();
                            tx.clone().send(input.clone()).unwrap();
                            input.clear();
                            cursor_pos = 0;
                        }
                    }
                    KeyCode::Esc => {
                        should_exit.store(true, Ordering::SeqCst);
                    }
                    _ => {}
                }
                print_prompt(&input, cursor_pos);
            }
        }
    }

    disable_raw_mode().unwrap();

    Ok(())
}

fn print_prompt(input: &str, cursor_pos: usize) {
    let mut stdout = stdout();
    execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine)).unwrap();

    print!("> {}", input);
    let prompt_len = 2; // "> "
    let target_col = (prompt_len + cursor_pos) as u16;
    execute!(stdout, MoveToColumn(target_col)).unwrap();

    stdout.flush().unwrap();
}
