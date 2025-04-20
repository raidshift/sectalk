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
use warp::ws::{Message, WebSocket};
use warp::Filter;

const SERVER_ADDRESS: ([u8; 4], u16) = ([127, 0, 0, 1], 3030);
const SESSION_TIMEOUT_SEC: u64 = 60;
const PUB_KEY_LEN: usize = 33;
const SIG_LEN: usize = 64;
const SIG_MSG_LEN: usize = 32;
const WS_MSG_LEN: usize = 140;

struct Msg(pub [u8; WS_MSG_LEN]);
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct RoomKey(u64);
struct Room {
    peer_a_tx: Option<Arc<Mutex<SplitSink<WebSocket, Message>>>>,
    peer_b_tx: Option<Arc<Mutex<SplitSink<WebSocket, Message>>>>,
    session_ids: Vec<Uuid>,
}

#[derive(Debug)]
enum Peer {
    A,
    B,
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
        Room {
            peer_a_tx: None,
            peer_b_tx: None,
            session_ids: Vec::new(),
        }
    }

    pub fn get_peer_tx(&mut self, peer: &Peer) -> &mut Option<Arc<Mutex<SplitSink<WebSocket, Message>>>> {
        return match peer {
            Peer::A => &mut self.peer_a_tx,
            Peer::B => &mut self.peer_b_tx,
        };
    }

    pub async fn add_session(&mut self, tx: Arc<Mutex<SplitSink<WebSocket, Message>>>, peer: &Peer, session_id: &Uuid) {
        self.session_ids.push(session_id.clone());
        self.session_ids.dedup();

        let peer_tx = self.get_peer_tx(peer);
        debug!(
            "{}: Peer = {:?}, Tx_old = {:?}, Tx_new = {:?}",
            session_id, peer, peer_tx, tx
        );

        if let Some(peer_tx) = peer_tx {
            let mut tx_guard = peer_tx.lock().await;
            send(&mut tx_guard, session_id, &[0x02]).await;
            debug!("{}: Kicked peer {:?}", session_id, peer);
        }
        debug!("{}: Add peer {:?}", session_id, peer);

        *peer_tx = Some(tx);
    }

    pub fn remove_session(&mut self, session_id: &Uuid) {
        // *self.get_peer_tx(peer) = None;
        if let Some(i) = self.session_ids.iter().position(|id| id == session_id) {
            self.session_ids.remove(i);
        }
    }
}

impl Rooms {
    pub fn new() -> Self {
        Rooms(HashMap::new())
    }

    pub fn get_room(&mut self, room_key: RoomKey) -> Arc<Mutex<Room>> {
        self.0
            .entry(room_key)
            .or_insert_with(|| Arc::new(Mutex::new(Room::new())))
            .clone()
    }

    pub fn remove_room(&mut self, room_key: RoomKey) {
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
    let mut this_peer: &Option<Peer> = &None;

    let mut rng = ChaCha20Rng::from_os_rng();
    rng.fill_bytes(&mut verify_sig_msg);

    let (tx, mut rx) = ws.split();
    let tx = Arc::new(Mutex::new(tx));

    info!("{}: Session established", session_id);

    {
        let mut tx_guard = tx.lock().await;
        send(&mut tx_guard, &session_id, &verify_sig_msg).await;
    }

    while let Ok(Some(Ok(ws_message))) = timeout(Duration::from_secs(SESSION_TIMEOUT_SEC), rx.next()).await {
        let ws_message_bytes = ws_message.as_bytes();

        match room {
            None => {
                if ws_message_bytes.len() != 2 * PUB_KEY_LEN + SIG_LEN {
                    debug!(
                        "{}: Message length: {} expected: {}",
                        session_id,
                        ws_message_bytes.len(),
                        2 * PUB_KEY_LEN + SIG_LEN
                    );
                    break;
                }

                let pka: [u8; PUB_KEY_LEN] = ws_message_bytes[..PUB_KEY_LEN].try_into().unwrap();
                let pkb: [u8; PUB_KEY_LEN] = ws_message_bytes[PUB_KEY_LEN..2 * PUB_KEY_LEN].try_into().unwrap();

                this_peer = match pka.cmp(&pkb) {
                    Ordering::Less => &Some(Peer::A),
                    Ordering::Greater => &Some(Peer::B),
                    _ => &None,
                };

                if this_peer.is_none() {
                    debug!("{}: Peers must be different", session_id);
                    break;
                }

                if !verify_signature(&pka, &ws_message_bytes[2 * PUB_KEY_LEN..], &verify_sig_msg) {
                    debug!("{}: Authentication failed", session_id);
                    break;
                }

                room_key = Some(RoomKey::new(&pka, &pkb));
                {
                    let mut rooms_guard = ROOMS.lock().await;
                    room = Some(rooms_guard.get_room(room_key.unwrap()));
                }

                {
                    let mut room_guard = room.as_ref().unwrap().lock().await;
                    room_guard
                        .add_session(tx.clone(), this_peer.as_ref().unwrap(), &session_id)
                        .await;
                }

                debug!("{}: Enrolled in room: {}", session_id, &room_key.unwrap().0);

                let mut tx_guard = tx.lock().await;
                send(&mut tx_guard, &session_id, &room_key.unwrap().0.to_be_bytes()).await;
            }
            Some(ref room) => {
                if ws_message_bytes.len() != WS_MSG_LEN {
                    debug!(
                        "{}: Message length: {} expected: {}",
                        session_id,
                        ws_message_bytes.len(),
                        WS_MSG_LEN
                    );
                    break;
                }

                if this_peer.is_none() {
                    error!("{}: Peer not set", session_id);
                    break;
                }

                let message = Msg(ws_message_bytes.try_into().unwrap());

                let this_peer = this_peer.as_ref().unwrap();

                let other_peer = match this_peer {
                    Peer::A => &Peer::B,
                    Peer::B => &Peer::A,
                };

                let mut room_guard = room.lock().await;

                if let Some(peer_tx) = room_guard.get_peer_tx(this_peer) {
                    let mut peer_tx_guard = peer_tx.lock().await;
                    send(&mut peer_tx_guard, &session_id, &message.0).await;
                }

                if let Some(peer_tx) = room_guard.get_peer_tx(other_peer) {
                    let mut peer_tx_guard = peer_tx.lock().await;
                    send(&mut peer_tx_guard, &session_id, &message.0).await;
                }
            }
        }
    }

    if let Some(room) = room {
        let mut room_guard = room.lock().await;
        if let Some(this_peer) = this_peer {
            room_guard.remove_session(&session_id);
            debug!(
                "{}: Peer {:?} removed from room {}",
                session_id,
                this_peer,
                &room_key.unwrap().0
            );
        }

        if room_guard.session_ids.len() == 0 {
            if let Some(room_key) = room_key {
                let mut rooms_guard = ROOMS.lock().await;
                rooms_guard.remove_room(room_key);
                debug!("{}: Removed room: {}", session_id, &room_key.0);
            }
        }
    }

    info!("{}: Session closed", session_id);
}
