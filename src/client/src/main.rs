use crossterm::{
    cursor::{MoveToColumn, MoveToNextLine},
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use futures_util::{SinkExt, StreamExt};
use hex::ToHex;
use log::debug;
use native_tls::TlsConnector;
use sectalk::{NONCE_LEN, ZeroizableHash, ZeroizableSecretKey, decrypt, derive_shared_secret, get_message_prefix};
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
    Connector, connect_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, protocol::Message},
};
use zeroize::Zeroizing;

use env_logger;
use secp256k1::SecretKey;
use secp256k1::hashes::Hash;
use secp256k1::{self, PublicKey, Secp256k1}; // Add this line at the top of the file

const WS_URL: &str = "wss://sectalk.my.to/ws/";
// const WS_URL: &str = "ws://127.0.0.1:3030/ws/";

enum State {
    AwaitVerifyMsg,
    AwaitRoomIdFromServer,
    AwaitMessages,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init(); // Initialize the logger

    let secp = Secp256k1::new();

    println!("sectalk\nchat peer-to-peer with full end-to-end encryption");

    let secret = Zeroizing::new(String::from("a").into_bytes()); //unsafe - read via prompt

    let hash = Zeroizing::new(ZeroizableHash(Hash::hash(&*secret)));

    let secret_key = Zeroizing::new(ZeroizableSecretKey(SecretKey::from_byte_array(
        *hash.0.as_byte_array(),
    )?)); //  Drop for SecretKey !?

    let public_key = PublicKey::from_secret_key(&secp, &secret_key.0).serialize();

    let public_key_peer: [u8; 33] = bs58::decode("upNfYNr7AxPAstsK16GTm9xSRtH1HvgCwTkADMLUjkDy")
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.as_slice().try_into().ok())
        .ok_or("invalid peer public key")?;

    let shared_secret = Zeroizing::new(
        derive_shared_secret(&secp, hash.0.as_byte_array(), &public_key_peer).map_err(|e| e.to_string())?,
    );

    println!("your public key: {}", bs58::encode(public_key).into_string());
    println!("peer public key: {}", bs58::encode(public_key_peer).into_string());
    debug!("shared secret: {}", shared_secret.encode_hex::<String>());

    struct RawModeGuard;

    impl RawModeGuard {
        fn new() -> Self {
            enable_raw_mode().unwrap();
            debug!("raw mode enabled");
            Self
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            execute!(
                stdout(),
                MoveToNextLine(1),
                Clear(ClearType::CurrentLine),
                MoveToColumn(0)
            ).unwrap();
          

            disable_raw_mode().unwrap();
            debug!("raw mode disabled");
        }
    }

    let _guard = RawModeGuard::new();

    let mut stdout = stdout();
    let mut input = String::new();
    let mut cursor_pos = 0;

    let should_exit = Arc::new(AtomicBool::new(false));
    let mut state = Arc::new(State::AwaitVerifyMsg);

    let should_exit_ws = should_exit.clone();

    let (tx, rx) = mpsc::channel();

    let tls_connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;

    let connector = Connector::NativeTls(tls_connector);

    let request = WS_URL.into_client_request()?;

    let ws_connection = connect_async_tls_with_config(request, None, false, Some(connector)).await?;

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
                            // tx.send(format!("verify_sig_msg = {}", msg.encode_hex::<String>()))
                            //     .unwrap();

                            let msg = secp256k1::Message::from_digest(msg.as_ref().try_into().unwrap());
                            let signature_bytes = secp.sign_ecdsa(msg, &secret_key.0).serialize_compact();
                            let signature = signature_bytes.as_ref();
                            let ret_msg: Vec<u8> = public_key
                                .iter()
                                .copied()
                                .chain(public_key_peer.iter().copied())
                                .chain(signature.iter().copied())
                                .collect();

                            // tx.send(format!(
                            //     "verified = {} ({})",
                            //     ret_msg.encode_hex::<String>(),
                            //     ret_msg.len()
                            // ))
                            // .unwrap();

                            thread_ws_write
                                .lock()
                                .unwrap()
                                .send(Message::Binary(ret_msg.into()))
                                .await
                                .unwrap();

                            new_state = Arc::new(State::AwaitRoomIdFromServer);
                        }
                        State::AwaitRoomIdFromServer => {
                            tx.send(format!("room id: {}", msg.encode_hex::<String>())).unwrap();
                            //     Zeroizing::new(derive_shared_secret(&secp, hash.0.as_byte_array(), &public_key_b).map_err(|e| e.to_string())?);
                            // shared_secret = Zeroizing::new(
                            //     derive_shared_secret(&secp, hash.0.as_byte_array(), &public_key_b).unwrap(),
                            // );
                            new_state = Arc::new(State::AwaitMessages);
                        }
                        State::AwaitMessages => {
                            if msg.len() > NONCE_LEN {
                                if let Ok(plain_text) = decrypt(
                                    &shared_secret,
                                    &msg[0..NONCE_LEN].try_into().unwrap(),
                                    &msg[NONCE_LEN..],
                                ) {
                                    tx.send(format!(
                                        "{} {}",
                                        get_message_prefix(&(plain_text[0] as char)),
                                        String::from_utf8_lossy(&plain_text[1..]).to_string()
                                    ))
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

    execute!(
        stdout,
        MoveToNextLine(1),
        Clear(ClearType::CurrentLine),
        MoveToColumn(0)
    )
    .unwrap();
    println!("disconnected from server");
    // execute!(
    //     stdout,
    //     MoveToNextLine(1),
    //     Clear(ClearType::CurrentLine),
    //     MoveToColumn(0)
    // )
    // .unwrap();

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
