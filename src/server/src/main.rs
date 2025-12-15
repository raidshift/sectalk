use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info};
use once_cell::sync::Lazy;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use secp256k1::{self, PublicKey, Secp256k1};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use uuid::Uuid;
use warp::Filter;
use warp::ws::{Message, WebSocket};

const SERVER_ADDRESS: ([u8; 4], u16) = ([0, 0, 0, 0], 3030);
const SESSION_TIMEOUT_SEC: u64 = 5 * 60;
const MAX_PEERS: usize = 2;
const PUB_KEY_LEN: usize = 33;
const SIG_LEN: usize = 64;
const SIG_MSG_LEN: usize = 32;
const ENCRYPTED_MSG_LEN: usize = 24 + 100 + 16; // nonce + ciphertext + auth tag
const ENCRYPTED_MSG_RECEIVED_CONF_LEN: usize = 24; // nonce
const ABORT_MSG_LEN: usize = 1;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct RoomKey(u64);
#[derive(Clone)]
struct RoomId(u64);
struct Room {
    key: RoomKey,
    id: RoomId,
    peer_txs: [Option<Arc<Mutex<SplitSink<WebSocket, Message>>>>; 2],
    session_ids: [Option<Uuid>; MAX_PEERS],
}

struct Rooms(HashMap<RoomKey, Arc<Mutex<Room>>>);

impl RoomKey {
    fn new(pub_key_a: &[u8; PUB_KEY_LEN], pub_key_b: &[u8; PUB_KEY_LEN]) -> Self {
        let mut xored = [0u8; PUB_KEY_LEN];

        for i in 0..PUB_KEY_LEN {
            xored[i] = pub_key_a[i] ^ pub_key_b[i];
        }

        let mut hasher = DefaultHasher::new();
        xored.hash(&mut hasher);
        RoomKey(hasher.finish())
    }
}

impl RoomId {
    fn new() -> Self {
        let mut rng = ChaCha20Rng::from_os_rng();
        RoomId(rng.next_u64())
    }
}

impl Hash for RoomKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0);
    }
}

impl Room {
    fn new(key: RoomKey) -> Self {
        Room {
            key: key,
            id: RoomId::new(),
            peer_txs: [None, None],
            session_ids: [None, None],
        }
    }
}

impl Rooms {
    fn new() -> Self {
        Rooms(HashMap::new())
    }

    async fn enter_room(
        &mut self,
        pka: &[u8; PUB_KEY_LEN],
        pkb: &[u8; PUB_KEY_LEN],
        session_id: &Uuid,
        peer: usize,
        tx: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    ) -> (Arc<Mutex<Room>>, RoomId) {
        let room_key = RoomKey::new(pka, pkb);
        let room_id;

        let room = self
            .0
            .entry(room_key)
            .or_insert_with(|| Arc::new(Mutex::new(Room::new(room_key))))
            .clone();

        {
            let mut room_guard = room.lock().await;

            room_id = room_guard.id.clone();

            room_guard.session_ids[peer].replace(session_id.clone());

            let peer_tx = &mut room_guard.peer_txs[peer];

            if let Some(peer_tx) = peer_tx {
                let mut tx_guard = peer_tx.lock().await;
                send_message_no_error(&mut tx_guard, session_id, &[0x00]).await;
                debug!("{}: Replaced peer {} in room {}", session_id, peer, room_id.0);
            }

            *peer_tx = Some(tx);

            debug!("{}: Added peer {} to room {}", session_id, peer, room_id.0);
        }

        (room, room_id)
    }

    async fn leave_room(&mut self, room: &Arc<Mutex<Room>>, session_id: &Uuid) {
        let mut room_guard = room.lock().await;
        let mut room_is_empty = true;

        for i in 0..room_guard.session_ids.len() {
            if room_guard.session_ids[i].as_ref() == Some(session_id) {
                room_guard.session_ids[i] = None;
                room_guard.peer_txs[i] = None;
                debug!("{}: Removed peer {} from room {}", session_id, i, room_guard.id.0);
            }

            if room_guard.session_ids[i].is_some() {
                room_is_empty = false;
            }
        }

        if room_is_empty {
            self.0.remove(&room_guard.key);
            debug!("{}: Removed room {}", session_id, room_guard.id.0);
        }
    }
}

static ROOMS: Lazy<Arc<Mutex<Rooms>>> = Lazy::new(|| Arc::new(Mutex::new(Rooms::new())));

fn verify_signature(pka: &[u8; PUB_KEY_LEN], sig: &[u8; SIG_LEN], message: &[u8; SIG_MSG_LEN]) -> bool {
    let secp256k1_context = Secp256k1::verification_only();

    PublicKey::from_slice(pka)
        .and_then(|public_key| {
            secp256k1::ecdsa::Signature::from_compact(sig).and_then(|signature| {
                secp256k1_context
                    .verify_ecdsa(secp256k1::Message::from_digest(*message), &signature, &public_key)
                    .map(|_| true)
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

async fn send_message_no_error(tx: &mut SplitSink<WebSocket, Message>, id: &Uuid, message: &[u8]) {
    tx.send(Message::binary(message.to_vec())).await.unwrap_or_else(|e| {
        debug!("{}: Failed to send message ({})", id, e);
    });
}

async fn handle_session(ws: WebSocket) {
    let session_id = Uuid::new_v4();
    let mut room: Option<Arc<Mutex<Room>>> = None;
    let mut sig_msg: [u8; SIG_MSG_LEN] = [0u8; SIG_MSG_LEN];
    let mut this_peer: Option<usize>;
    let mut other_peer: Option<usize> = None;

    let mut rng = ChaCha20Rng::from_os_rng();
    rng.fill_bytes(&mut sig_msg);

    let (tx, mut rx) = ws.split();
    let tx = Arc::new(Mutex::new(tx));

    info!("{}: Session established", session_id);

    {
        let mut tx_guard = tx.lock().await;
        send_message_no_error(&mut tx_guard, &session_id, &sig_msg).await;
    }

    while let Ok(Some(Ok(ws_message))) = timeout(Duration::from_secs(SESSION_TIMEOUT_SEC), rx.next()).await {
        let ws_message_bytes = ws_message.as_bytes();

        if ws_message_bytes.len() <= ABORT_MSG_LEN {
            debug!("{}: Received abort message", session_id);
            break;
        }

        match room {
            None => {
                if ws_message_bytes.len() != 2 * PUB_KEY_LEN + SIG_LEN {
                    debug!("{}: Invalid authentication message length", session_id);
                    break;
                }

                let pka: &[u8; PUB_KEY_LEN] = ws_message_bytes[..PUB_KEY_LEN].try_into().unwrap();
                let pkb: &[u8; PUB_KEY_LEN] = ws_message_bytes[PUB_KEY_LEN..2 * PUB_KEY_LEN].try_into().unwrap();
                let sig: &[u8; SIG_LEN] = ws_message_bytes[2 * PUB_KEY_LEN..].try_into().unwrap();

                (this_peer, other_peer) = match pka.cmp(pkb) {
                    Ordering::Less => (Some(0), Some(1)),
                    Ordering::Greater => (Some(1), Some(0)),
                    _ => (None, None),
                };

                if this_peer.is_none() {
                    debug!("{}: Peers must be different", session_id);
                    break;
                }

                if !verify_signature(pka, sig, &sig_msg) {
                    debug!("{}: Authentication failed", session_id);
                    break;
                }

                let room_id: RoomId;

                {
                    let entered_room: Arc<Mutex<Room>>;
                    let mut rooms_guard: tokio::sync::MutexGuard<'_, Rooms> = ROOMS.lock().await;
                    (entered_room, room_id) = rooms_guard
                        .enter_room(pka, pkb, &session_id, this_peer.unwrap(), tx.clone())
                        .await;
                    room = Some(entered_room);
                }

                let mut tx_guard = tx.lock().await;
                send_message_no_error(&mut tx_guard, &session_id, &room_id.0.to_be_bytes()).await;
            }
            Some(ref room) => {
                if !matches!(
                    ws_message_bytes.len(),
                    ENCRYPTED_MSG_LEN | ENCRYPTED_MSG_RECEIVED_CONF_LEN | 0
                ) {
                    debug!("{}: Invalid message length {}", session_id, ws_message_bytes.len());
                    break;
                }

                if other_peer.is_none() {
                    error!("{}: Other peer nor set", session_id);
                    break;
                }

                let mut room_guard = room.lock().await;

                if let Some(peer_tx) = &mut room_guard.peer_txs[other_peer.unwrap()] {
                    let mut peer_tx_guard = peer_tx.lock().await;
                    send_message_no_error(&mut peer_tx_guard, &session_id, &ws_message_bytes).await;
                }
            }
        }
    }

    if let Some(room) = room {
        let mut rooms_guard = ROOMS.lock().await;
        rooms_guard.leave_room(&room, &session_id).await;
    }

    info!("{}: Session closed", session_id);
}
