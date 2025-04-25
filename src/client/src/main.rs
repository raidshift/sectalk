use crossterm::{
    cursor::{MoveToColumn, MoveToNextLine},
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use futures_util::{SinkExt, StreamExt};
use hex::ToHex;
use k256::sha2::{Digest, Sha256};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{
    io::{Write, stdout},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message},
};

use secp256k1::{self, PublicKey, Secp256k1, SecretKey};

// const WS_URL: &str = "ws://sectalk.my.to/ws";

const WS_URL: &str = "ws://127.0.0.1:3030/ws/";

enum State {
    AwaiutVerifyMsg,
    AwaitRoomIdFromServer,
    AwaitMessages,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("sectalk\nA peer-to-peer, end-to-end encrypted messaging protocol");

    // **********+

    let secret = b"a";

    let mut hasher = Sha256::new();
    hasher.update(secret);

    let hash_result: [u8; 32] = hasher.finalize().try_into().unwrap();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array(&hash_result).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize();

    let public_key_b: [u8; 33] = hex::decode("0310c283aac7b35b4ae6fab201d36e8322c3408331149982e16013a5bcb917081c").unwrap().try_into().unwrap();

    println!("Your public key: {}", public_key.encode_hex::<String>());

    // Create signing key
    // let signing_key = SigningKey::from(&secret_key);

    // Sign a message

    // ***********

    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    let mut input = String::new();
    let mut cursor_pos = 0;

    let should_exit = Arc::new(AtomicBool::new(false));
    let mut state = Arc::new(State::AwaiutVerifyMsg);

    let should_exit_ws = should_exit.clone();

    let (tx, rx) = mpsc::channel();
    // tx.send(format!("Let'sgo")).unwrap();

    // let thread_tx = tx.clone();
    let request = WS_URL.into_client_request()?;

    let ws_connection = connect_async(request).await?;

    let (ws_write, mut ws_read) = ws_connection.0.split();

    let ws_write = Arc::new(Mutex::new(ws_write));
    let thread_ws_write = ws_write.clone();

    let runtime = tokio::runtime::Runtime::new()?;

    thread::spawn(move || {
        runtime.block_on(async {
            while let Some(msg) = ws_read.next().await {
                if let Ok(msg) = msg.map(|msg| msg.into_data()) {
                    let new_state: Arc<State>;
                    match *state {
                        State::AwaiutVerifyMsg => {
                            tx.send(format!("verify_sig_msg = {}", msg.encode_hex::<String>())).unwrap();

                            // let message_hash = Sha256::digest(msg);
                            let msg = secp256k1::Message::from_digest(msg.as_ref().try_into().unwrap());

                            let signature_bytes = secp.sign_ecdsa(&msg, &secret_key).serialize_compact();
                            let signature = signature_bytes.as_ref();

                            let ret_msg: Vec<u8> = public_key.iter().copied().chain(public_key_b.iter().copied()).chain(signature.iter().copied()).collect();

                            tx.send(format!("verified = {} ({})", ret_msg.encode_hex::<String>(), ret_msg.len())).unwrap();

                            thread_ws_write.lock().unwrap().send(Message::Binary(ret_msg.into())).await.unwrap();

                            new_state = Arc::new(State::AwaitRoomIdFromServer);
                        }
                        State::AwaitRoomIdFromServer => {
                            // tx.send("Server: Awaiting room ID from server...".to_string()).unwrap();
                            new_state = Arc::new(State::AwaitMessages);
                        }
                        State::AwaitMessages => {
                            // tx.send(format!("Server: {}", msg.encode_hex::<String>())).unwrap();
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
                            ws_write.lock().unwrap().send(Message::Binary((input.clone()).into_bytes().into())).await.unwrap();
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
