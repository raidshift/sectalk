use crossterm::{
    cursor::{MoveToColumn, MoveToNextLine},
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use futures_util::{SinkExt, StreamExt};
use hex::ToHex;
use sha2::Digest;
use sha2::Sha256;
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

use k256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
};

// const WS_URL: &str = "ws://sectalk.my.to/ws";

const WS_URL: &str = "ws://127.0.0.1:3030/ws/";

enum State {
    Init,
    AwaitSecretKeyFromUser,
    AwaitPeerPubKeyFromUser,
    AwaitingRoomIdFromServer,
    AwaitMessages,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("sectalk\nA peer-to-peer, end-to-end encrypted messaging protocol");

    // **********+

    let secret = b"a";

    let mut hasher = Sha256::new();
    hasher.update(secret);

    let secret_key = SecretKey::from_bytes(&hasher.finalize().into()).unwrap();

    let public_key: [u8; 33] = secret_key.public_key().to_encoded_point(true).as_bytes().try_into().unwrap();

    println!("Your public key: {}", public_key.encode_hex::<String>());

    // Create signing key
    // let signing_key = SigningKey::from(&secret_key);

    // Sign a message
    let message = b"hello world";
    let signature: Signature = SigningKey::from(&secret_key).sign(message);

    // ***********

    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    let mut input = String::new();
    let mut cursor_pos = 0;

    let should_exit = Arc::new(AtomicBool::new(false));
    let mut state = Arc::new(State::Init);

    let should_exit_ws = should_exit.clone();

    let (tx, rx) = mpsc::channel();
    // tx.send(format!("Let'sgo")).unwrap();

    // let thread_tx = tx.clone();
    let request = WS_URL.into_client_request()?;

    let ws_connection = connect_async(request).await?;

    let (mut ws_write, mut ws_read) = ws_connection.0.split();

    // println!("WebSocket connected!");

    let runtime = tokio::runtime::Runtime::new()?;

    thread::spawn(move || {
        runtime.block_on(async {
            while let Some(msg) = ws_read.next().await {
                if let Ok(msg) = msg.map(|msg| msg.into_data()) {
                    let new_state: Arc<State>;
                    match *state {
                        State::Init => {
                            tx.send(format!("verify_sig_msg = {}", msg.encode_hex::<String>())).unwrap();
                            new_state = Arc::new(State::AwaitingRoomIdFromServer);
                        }
                        // State::AwaitSecretKeyFromUser => {
                        //     tx.send("Server: Awaiting secret key from user...".to_string()).unwrap();
                        //     new_state = Arc::new(State::AwaitSecretKeyFromUser);

                        // }
                        // State::AwaitPeerPubKeyFromUser => {
                        //     tx.send("Server: Awaiting peer public key from user...".to_string()).unwrap();
                        //     new_state = Arc::new(State::AwaitSecretKeyFromUser);

                        // }
                        State::AwaitingRoomIdFromServer => {
                            tx.send("Server: Awaiting room ID from server...".to_string()).unwrap();
                            new_state = Arc::new(State::AwaitMessages);
                        }
                        State::AwaitMessages => {
                            tx.send(format!("Server: {}", msg.encode_hex::<String>())).unwrap();
                            new_state = Arc::new(State::AwaitMessages);
                        }
                        _ => {
                            break;
                        }
                    }

                    state = new_state;
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

            // println!("> {}", message);
            println!("{message}");

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
                            ws_write.send(Message::Binary((input.clone()).into_bytes().into())).await.unwrap();
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
