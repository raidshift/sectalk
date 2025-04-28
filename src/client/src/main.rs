use crossterm::{
    cursor::{MoveToColumn, MoveToNextLine},
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use futures_util::{SinkExt, StreamExt};
use hex::ToHex;
use sectalk::{NONCE_LEN, SEC_KEY_LEN, ZeroizableHash, ZeroizableSecretKey, decrypt, derive_shared_secret};
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
use zeroize::Zeroizing;

use secp256k1::SecretKey;
use secp256k1::hashes::Hash;
use secp256k1::{self, PublicKey, Secp256k1};

// const WS_URL: &str = "ws://sectalk.my.to/ws";
const WS_URL: &str = "ws://127.0.0.1:3030/ws/";

enum State {
    AwaitVerifyMsg,
    AwaitRoomIdFromServer,
    AwaitMessages,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    println!("sectalk\nA peer-to-peer, end-to-end encrypted messaging protocol");

    let secret = Zeroizing::new(String::from("a").into_bytes()); //unsafe - read via prompt

    let hash = Zeroizing::new(ZeroizableHash(Hash::hash(&*secret)));

    let secret_key = Zeroizing::new(ZeroizableSecretKey(
        SecretKey::from_byte_array(*hash.0.as_byte_array()).unwrap(),
    )); // there is no Drop !!

    let public_key = PublicKey::from_secret_key(&secp, &secret_key.0).serialize();

    let public_key_b: [u8; 33] = hex::decode("0310c283aac7b35b4ae6fab201d36e8322c3408331149982e16013a5bcb917081c")
        .unwrap()
        .try_into()
        .unwrap();

    let shared_secret =
        Zeroizing::new(derive_shared_secret(&secp, hash.0.as_byte_array(), &public_key_b).map_err(|e| e.to_string())?);

    println!("Your public key: {}", public_key.encode_hex::<String>());
    println!("Peer public key: {}", public_key_b.encode_hex::<String>());
    println!("Shared secret: {}", shared_secret.encode_hex::<String>());

    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    let mut input = String::new();
    let mut cursor_pos = 0;

    let should_exit = Arc::new(AtomicBool::new(false));
    let mut state = Arc::new(State::AwaitVerifyMsg);

    let should_exit_ws = should_exit.clone();

    let (tx, rx) = mpsc::channel();

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
                        State::AwaitVerifyMsg => {
                            tx.send(format!("verify_sig_msg = {}", msg.encode_hex::<String>()))
                                .unwrap();

                            let msg = secp256k1::Message::from_digest(msg.as_ref().try_into().unwrap());
                            let signature_bytes = secp.sign_ecdsa(msg, &secret_key.0).serialize_compact();
                            let signature = signature_bytes.as_ref();
                            let ret_msg: Vec<u8> = public_key
                                .iter()
                                .copied()
                                .chain(public_key_b.iter().copied())
                                .chain(signature.iter().copied())
                                .collect();

                            tx.send(format!(
                                "verified = {} ({})",
                                ret_msg.encode_hex::<String>(),
                                ret_msg.len()
                            ))
                            .unwrap();

                            thread_ws_write
                                .lock()
                                .unwrap()
                                .send(Message::Binary(ret_msg.into()))
                                .await
                                .unwrap();

                            new_state = Arc::new(State::AwaitRoomIdFromServer);
                        }
                        State::AwaitRoomIdFromServer => {
                            tx.send(format!("Entered room {}", msg.encode_hex::<String>())).unwrap();
                            new_state = Arc::new(State::AwaitMessages);
                        }
                        State::AwaitMessages => {
                            // tx.send(format!("Server: {}", msg.encode_hex::<String>())).unwrap();

                            if msg.len() > NONCE_LEN {
                                if let Ok(plain) = decrypt(
                                    &shared_secret,
                                    &msg[0..NONCE_LEN].try_into().unwrap(),
                                    &msg[NONCE_LEN..],
                                ) {
                                    let prefix = match plain[0] {
                                        b'A' => ">",
                                        b'B' => "<",
                                        _ => "?",
                                    };
                                    tx.send(format!(
                                        "{} {}",
                                        prefix,
                                        String::from_utf8_lossy(&plain[1..]).to_string()
                                    ))
                                    .unwrap();
                                } else {
                                    tx.send(format!("Failed to decrypt message: {}", msg.encode_hex::<String>()))
                                        .unwrap();
                                }
                            }

                            new_state = Arc::new(State::AwaitMessages);
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
                            execute!(
                                stdout,
                                MoveToNextLine(1),
                                Clear(ClearType::CurrentLine),
                                MoveToColumn(0)
                            )
                            .unwrap();
                            ws_write
                                .lock()
                                .unwrap()
                                .send(Message::Binary((input.clone()).into_bytes().into()))
                                .await
                                .unwrap();
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
