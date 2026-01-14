use crossterm::{
    cursor::{MoveToColumn, MoveToNextLine},
    event::{self, Event, KeyCode},
    execute,
    terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use futures_util::{SinkExt, StreamExt};
// use hex::ToHex;
use log::debug;
use native_tls::TlsConnector;
use sectalk::{
    MSG_LEN, NONCE_LEN, PROMPT_LEN, PUB_KEY_LEN, ZeroizableHash, ZeroizableSecretKey, decrypt, derive_shared_secret,
    get_byte_idx,
};
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
use unicode_segmentation::UnicodeSegmentation;
use zeroize::Zeroizing;

use env_logger;
use secp256k1::SecretKey;
use secp256k1::hashes::Hash;
use secp256k1::{self, PublicKey, Secp256k1}; // Add this line at the top of the file

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use unicode_width::UnicodeWidthStr;

// const WS_URL: &str = "wss://sectalk.my.to/ws/";
const WS_URL: &str = "ws://127.0.0.1:3030/ws/";

enum State {
    AwaitVerifyMsg,
    AwaitRoomIdFromServer,
    AwaitMessages,
}

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
        disable_raw_mode().unwrap();
        debug!("raw mode disabled");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .target(env_logger::Target::Pipe(Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("sectalk.log")?,
        )))
        .init();

    let mut rng = ChaCha20Rng::try_from_os_rng()?;

    let secp = Secp256k1::new();

    println!("sectalk\nchat peer-to-peer with full end-to-end encryption");

    let secret = Zeroizing::new(String::from("a").into_bytes()); //unsafe - read via prompt

    let hash = Zeroizing::new(ZeroizableHash(Hash::hash(&*secret)));

    let secret_key = Zeroizing::new(ZeroizableSecretKey(SecretKey::from_byte_array(
        *hash.0.as_byte_array(),
    )?)); //  Drop for SecretKey !?

    let public_key = PublicKey::from_secret_key(&secp, &secret_key.0).serialize();
    let public_key_peer: [u8; PUB_KEY_LEN] = bs58::decode("upNfYNr7AxPAstsK16GTm9xSRtH1HvgCwTkADMLUjkDy")
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.as_slice().try_into().ok())
        .ok_or("invalid peer public key")?;

    // let mut shared_secret = Zeroizing::new([0u8; ROOM_ID_LEN + SECRET_KEY_SIZE]);

    // shared_secret[ROOM_ID_LEN..].copy_from_slice(&derive_shared_secret(
    //     &secp,
    //     hash.0.as_byte_array(),
    //     &public_key_peer,
    // )?);

    // let mut shared_secret = Zeroizing::new(derive_shared_secret(&secp, hash.0.as_byte_array(), &public_key_peer)?);

    let shared_secret = Arc::new(Mutex::new(Zeroizing::new(derive_shared_secret(
        &secp,
        hash.0.as_byte_array(),
        &public_key_peer,
    )?)));

    // let mut room_id = Zeroizing::new([0u8; ROOM_ID_LEN]);

    // let mut room_id: Vec<u8> = Vec::new(); // obtain from server

    println!("your public key: {}", bs58::encode(public_key).into_string());
    println!("peer public key: {}", bs58::encode(public_key_peer).into_string());
    // debug!("shared secret right: {}", shared_secret.encode_hex::<String>());

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

    let thread_shared_secret = shared_secret.clone();
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
                            let ret_msg: Vec<u8> = [public_key.as_ref(), &public_key_peer, signature].concat();

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
                            // tx.send(format!("room id: {}", &msg.encode_hex::<String>())).unwrap();

                            let mut shared_secret_guard = thread_shared_secret.lock().unwrap();

                            let tmp = Zeroizing::new([&msg, shared_secret_guard.as_ref()].concat());
                            let hash = Zeroizing::new(ZeroizableHash(Hash::hash(&*tmp)));
                            shared_secret_guard.copy_from_slice(hash.0.as_byte_array());

                            new_state = Arc::new(State::AwaitMessages);
                        }
                        State::AwaitMessages => {
                            if msg.len() > NONCE_LEN {
                                let shared_secret_guard = thread_shared_secret.lock().unwrap();
                                let tmp = Zeroizing::new([&msg[0..NONCE_LEN], shared_secret_guard.as_ref()].concat());

                                let hash = Zeroizing::new(ZeroizableHash(Hash::hash(&*tmp)));
                                if let Ok(plain_text) = decrypt(
                                    hash.0.as_byte_array().try_into().unwrap(),
                                    &msg[0..NONCE_LEN].try_into().unwrap(),
                                    &msg[NONCE_LEN..],
                                ) {
                                    tx.send(format!("< {}", String::from_utf8_lossy(&plain_text).to_string()))
                                        .unwrap();

                                    thread_ws_write
                                        .lock()
                                        .unwrap()
                                        .send(Message::Binary(msg[0..NONCE_LEN].to_vec().into()))
                                        .await
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
            execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine)).unwrap();
            println!("{}", message.trim());
            print_prompt(&input, cursor_pos);
        }

        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key_event) = event::read().unwrap() {
                match key_event.code {
                    KeyCode::Char(c) => {
                        if !(input.is_empty() && c == ' ') && input.len() + c.len_utf8() <= MSG_LEN {
                            input.insert(get_byte_idx(&input, cursor_pos), c);
                            cursor_pos += 1;
                        }
                    }
                    KeyCode::Left => {
                        if cursor_pos > 0 {
                            cursor_pos -= 1;
                        }
                    }
                    KeyCode::Right => {
                        if cursor_pos < input.graphemes(true).count() {
                            cursor_pos += 1;
                        }
                    }
                    KeyCode::Backspace => {
                        if cursor_pos > 0 {
                            input.remove(get_byte_idx(&input, cursor_pos - 1));
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

                            let mut nonce = [0u8; NONCE_LEN];
                            rng.fill_bytes(&mut nonce);

                            let mut msg = Zeroizing::new([0x20u8; MSG_LEN]);

                            msg[..input.len()]
                                .copy_from_slice(input[..std::cmp::min(input.len(), MSG_LEN)].trim().as_bytes());

                            let shared_secret_guard = shared_secret.lock().unwrap();

                            let tmp = Zeroizing::new([nonce.as_ref(), shared_secret_guard.as_ref()].concat());
                            let hash = Zeroizing::new(ZeroizableHash(Hash::hash(&*tmp)));

                            let ciphertext = sectalk::encrypt(&hash.0.as_byte_array(), &nonce, msg.as_ref()).unwrap();

                            //    let ret_msg: Vec<u8> = public_key
                            // .iter()
                            // .copied()
                            // .chain(public_key_peer.iter().copied())
                            // .chain(signature.iter().copied())
                            // .collect();

                            //     let combined = nonce.iter()
                            //         .copied()

                            // let ciphertext = sectalk::encrypt(&shared_secret_guard, &nonce, input.as_bytes()).unwrap();

                            ws_write.lock().unwrap().send(ciphertext.into()).await.unwrap();
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
    execute!(
        stdout,
        MoveToNextLine(1),
        Clear(ClearType::CurrentLine),
        MoveToColumn(0)
    )
    .unwrap();

    Ok(())
}

fn print_prompt(input: &str, cursor_pos: usize) {
    let mut stdout = stdout();
    execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine)).unwrap();

    print!("> {}", input);

    let display_width = input.graphemes(true).take(cursor_pos).collect::<String>().width();
    let target_col = (PROMPT_LEN + display_width) as u16;

    execute!(stdout, MoveToColumn(target_col)).unwrap();
    stdout.flush().unwrap();
}
