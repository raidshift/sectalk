use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info};
use once_cell::sync::Lazy;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use secp256k1::{self, PublicKey, Secp256k1};
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warp::ws::{Message, WebSocket};
use warp::Filter;

const SERVER_ADDRESS: ([u8; 4], u16) = ([127, 0, 0, 1], 3030);
const PUB_KEY_LEN: usize = 33;
const SIG_LEN: usize = 64;
const SIG_MSG_LEN: usize = 32;
const WS_MSG_LEN: usize = 140;

struct Msg(pub [u8; WS_MSG_LEN]);
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct RoomKey(u64);
struct Room {
    peer_txs: Vec<Arc<Mutex<SplitSink<WebSocket, Message>>>>,
}
struct Rooms(HashMap<RoomKey, Arc<Mutex<Room>>>);

impl RoomKey {
    pub fn new(pub_key_a: &[u8; PUB_KEY_LEN], pub_key_b: &[u8; PUB_KEY_LEN]) -> Self {
        let mut xored = [0u8; PUB_KEY_LEN];

        for i in 0..PUB_KEY_LEN {
            xored[i] = pub_key_a[i] ^ pub_key_b[i];
        }

        let mut hasher = DefaultHasher::new();
        xored.hash(&mut hasher);
        RoomKey(hasher.finish())
    }
}

impl Hash for RoomKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0);
    }
}

impl Room {
    pub fn new() -> Self {
        Room { peer_txs: Vec::new() }
    }

    pub fn add_tx(&mut self, tx: Arc<Mutex<SplitSink<WebSocket, Message>>>) {
        self.peer_txs.push(tx);
    }

    pub fn remove_tx(&mut self, tx: Arc<Mutex<SplitSink<WebSocket, Message>>>) -> usize {
        self.peer_txs.remove(
            self.peer_txs
                .iter()
                .position(|tx_in_room: &Arc<Mutex<SplitSink<WebSocket, Message>>>| Arc::ptr_eq(&tx_in_room, &tx))
                .unwrap(),
        );
        self.peer_txs.len()
    }

    pub fn peer_txs(&self) -> impl Iterator<Item = Arc<Mutex<SplitSink<WebSocket, Message>>>> + '_ {
        self.peer_txs.iter().cloned()
    }
}

impl Rooms {
    pub fn new() -> Self {
        Rooms(HashMap::new())
    }

    pub fn enroll(&mut self, room_key: RoomKey) -> Arc<Mutex<Room>> {
        self.0
            .entry(room_key)
            .or_insert_with(|| Arc::new(Mutex::new(Room::new())))
            .clone()
    }

    pub fn remove(&mut self, room_key: RoomKey) {
        self.0.remove(&room_key);
    }
}

static ROOMS: Lazy<Arc<Mutex<Rooms>>> = Lazy::new(|| Arc::new(Mutex::new(Rooms::new())));

fn verify_signature(pka: &[u8], sig: &[u8], message: &[u8]) -> bool {
    let secp256k1_context = Secp256k1::verification_only();

    PublicKey::from_slice(pka)
        .and_then(|public_key| {
            secp256k1::ecdsa::Signature::from_compact(sig).and_then(|signature| {
                secp256k1::Message::from_digest_slice(message).and_then(|message| {
                    secp256k1_context
                        .verify_ecdsa(&message, &signature, &public_key)
                        .map(|_| true)
                })
            })
        })
        .unwrap_or(false)
}

#[tokio::main]
async fn main() {
    env_logger::init();

    info!(
        "Starting WebSocket server on {}:{}",
        SERVER_ADDRESS
            .0
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        SERVER_ADDRESS.1
    );

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| ws.on_upgrade(handle_session));

    warp::serve(ws_route).run(SERVER_ADDRESS).await;
}

async fn send(tx: &mut SplitSink<WebSocket, Message>, id: &Uuid, message: &[u8]) {
    tx.send(Message::binary(message)).await.unwrap_or_else(|e| {
        error!("{}: Failed to send message {:?} ({})", id, message, e);
    })
}

async fn handle_session(ws: WebSocket) {
    let session_id = Uuid::new_v4();
    let mut room: Option<Arc<Mutex<Room>>> = None;
    let mut room_key: Option<RoomKey> = None;
    let mut verify_sig_msg: [u8; SIG_MSG_LEN] = [0u8; SIG_MSG_LEN];

    let mut rng = ChaCha20Rng::from_os_rng();
    rng.fill_bytes(&mut verify_sig_msg);

    let (tx, mut rx) = ws.split();
    let tx = Arc::new(Mutex::new(tx));

    info!("{:?}: Session established", session_id);

    {
        let mut tx_guard = tx.lock().await;
        send(&mut tx_guard, &session_id, &verify_sig_msg).await;
    }

    while let Some(Ok(ws_message)) = rx.next().await {
        let ws_message_bytes = ws_message.as_bytes();

        match room {
            None => {
                if ws_message_bytes.len() == 2 * PUB_KEY_LEN + SIG_LEN {
                    let pka: [u8; PUB_KEY_LEN] = ws_message_bytes[..PUB_KEY_LEN].try_into().unwrap();
                    let pkb: [u8; PUB_KEY_LEN] = ws_message_bytes[PUB_KEY_LEN..2 * PUB_KEY_LEN].try_into().unwrap();

                    if !verify_signature(&pka, &ws_message_bytes[2 * PUB_KEY_LEN..], &verify_sig_msg) {
                        debug!("{:?}: Authentication failed", session_id);
                        break;
                    }

                    room_key = Some(RoomKey::new(&pka, &pkb));
                    {
                        let mut rooms_guard = ROOMS.lock().await;
                        room = Some(rooms_guard.enroll(room_key.unwrap()));
                    }

                    {
                        let mut room_guard = room.as_ref().unwrap().lock().await;
                        room_guard.add_tx(tx.clone());
                    }

                    debug!("{:?}: Enrolled in room: {:?}", session_id, &room_key.unwrap().0);

                    let mut tx_guard = tx.lock().await;
                    send(&mut tx_guard, &session_id, &room_key.unwrap().0.to_be_bytes()).await;
                } else {
                    debug!(
                        "{:?}: Message length: {} expected: {}",
                        session_id,
                        ws_message_bytes.len(),
                        2 * PUB_KEY_LEN + SIG_LEN
                    );
                    break;
                }
            }
            Some(ref room) => {
                if ws_message_bytes.len() == WS_MSG_LEN {
                    let message = Msg(ws_message_bytes.try_into().unwrap());

                    let room_guard = room.lock().await;
                    for peer_tx in room_guard.peer_txs() {
                        let mut peer_tx_guard = peer_tx.lock().await;
                        send(&mut peer_tx_guard, &session_id, &message.0).await;
                    }
                } else {
                    debug!(
                        "{:?}: Message length: {} expected: {}",
                        session_id,
                        ws_message_bytes.len(),
                        WS_MSG_LEN
                    );
                    break;
                }
            }
        }
    }

    if let Some(room) = room {
        let mut room_guard = room.lock().await;
        if room_guard.remove_tx(tx.clone()) == 0 {
            if let Some(room_key) = room_key {
                let mut rooms_guard = ROOMS.lock().await;
                rooms_guard.remove(room_key);
                debug!("{:?}: Removed room: {:?}", session_id, &room_key.0);
            }
        }
    }
    info!("{:?}: Session closed", session_id);
}
