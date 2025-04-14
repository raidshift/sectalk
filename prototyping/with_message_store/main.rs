use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::{debug, info};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::Rng;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Read, Seek, Write};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warp::ws::{Message, WebSocket};
use warp::Filter;

const SERVER_ADDRESS: ([u8; 4], u16) = ([127, 0, 0, 1], 3030);
const PUB_KEY_LEN: usize = 33;
const WS_MSG_LEN: u16 = 140;
const ROOM_MAX_LEN: u16 = 5;
const ROOMS_FOLDER: &str = "rooms";
const ROOM_FILE_HEADER_LEN: usize = 2;

#[derive(Clone)]
struct Msg(pub [u8; WS_MSG_LEN as usize]);
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct RoomKey(u64);
struct Room {
    file_path: String,
    first: u16,
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
    pub fn new(id: u64) -> Self {
        let mut first = 0;
        let file_path = format!("{}/{}", ROOMS_FOLDER, hex::encode(id.to_be_bytes()));
        std::fs::create_dir_all(ROOMS_FOLDER).unwrap();

        if let Ok(mut file) = std::fs::File::open(&file_path) {
            let mut file_integrity_check_passed = false;

            let mut header_bytes = [0; ROOM_FILE_HEADER_LEN];
            if file.read_exact(&mut header_bytes).is_ok() {
                first = u16::from_le_bytes(header_bytes);

                let body_len = file.seek(std::io::SeekFrom::End(0)).unwrap_or(0) - ROOM_FILE_HEADER_LEN as u64;

                if body_len % WS_MSG_LEN as u64 == 0 && (first as u64) < (body_len / WS_MSG_LEN as u64) {
                    file_integrity_check_passed = true;
                }
            }

            drop(file);

            if !file_integrity_check_passed {
                first = 0;
                std::fs::remove_file(&file_path).unwrap();
                debug!("File integrity check failed. Deleted {:?}", file_path);
            }
        }

        Room { file_path, first, peer_txs: Vec::new() }
    }

    pub fn add_message(&mut self, msg: &Msg) {
        let mut file = OpenOptions::new().write(true).create(true).open(&self.file_path).unwrap();

        file.seek(std::io::SeekFrom::Start(ROOM_FILE_HEADER_LEN as u64 + (self.first as u64 * WS_MSG_LEN as u64))).unwrap();
        file.write_all(&msg.0).unwrap();

        self.first = (self.first + 1) % ROOM_MAX_LEN;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        file.write_all(&self.first.to_le_bytes()).unwrap();
    }

    pub async fn send_all_messages(&self, id: &Uuid, tx: &mut SplitSink<WebSocket, Message>) {
        if let Ok(mut file) = OpenOptions::new().read(true).open(&self.file_path) {
            let mut buffer = [0u8; WS_MSG_LEN as usize];

            let file_len = file.seek(std::io::SeekFrom::End(0)).unwrap_or(0);

            let mut start: u16 = 0;

            if file_len >= ROOM_FILE_HEADER_LEN as u64 + (ROOM_MAX_LEN as u64 * WS_MSG_LEN as u64) {
                start = self.first;
            }

            for i in 0..ROOM_MAX_LEN {
                file.seek(std::io::SeekFrom::Start(ROOM_FILE_HEADER_LEN as u64 + (((start + i) as u64 % ROOM_MAX_LEN as u64) * WS_MSG_LEN as u64))).unwrap();
                if file.read_exact(&mut buffer).is_ok() {
                    send(tx, id, &Msg(buffer).0).await;
                } else {
                    break;
                }
            }
        }
    }

    pub fn add_tx(&mut self, tx: Arc<Mutex<SplitSink<WebSocket, Message>>>) {
        self.peer_txs.push(tx);
    }

    pub fn remove_tx(&mut self, tx: Arc<Mutex<SplitSink<WebSocket, Message>>>) -> usize {
        self.peer_txs
            .remove(self.peer_txs.iter().position(|tx_in_room: &Arc<Mutex<SplitSink<WebSocket, Message>>>| Arc::ptr_eq(&tx_in_room, &tx)).unwrap());
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
        self.0.entry(room_key).or_insert_with(|| Arc::new(Mutex::new(Room::new(room_key.0)))).clone()
    }

    pub fn remove(&mut self, room_key: RoomKey) {
        self.0.remove(&room_key);
    }
}

static ROOMS: Lazy<Arc<Mutex<Rooms>>> = Lazy::new(|| Arc::new(Mutex::new(Rooms::new())));

#[tokio::main]
async fn main() {
    env_logger::init();

    info!("Starting WebSocket server on {}:{}", SERVER_ADDRESS.0.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."), SERVER_ADDRESS.1);

    warp::serve(warp::ws().map(|ws: warp::ws::Ws| ws.on_upgrade(handle_session))).run(SERVER_ADDRESS).await;
}

async fn send(tx: &mut SplitSink<WebSocket, Message>, id: &Uuid, message: &[u8]) {
    tx.send(Message::binary(message)).await.unwrap_or_else(|e| {
        log::error!("{}: Failed to send message {:?} ({})", id, message, e);
    })
}

async fn handle_session(ws: WebSocket) {
    let session_id = Uuid::new_v4();
    let mut room: Option<Arc<Mutex<Room>>> = None;
    let mut room_key: Option<RoomKey> = None;
    let random_message: u64 = OsRng.gen();

    let (tx, mut rx) = ws.split();
    let tx = Arc::new(Mutex::new(tx));

    info!("{:?}: Session established", session_id);

    {
        let mut tx_guard = tx.lock().await;
        send(&mut tx_guard, &session_id, &random_message.to_be_bytes()).await;
    }

    while let Some(Ok(ws_message)) = rx.next().await {
        let ws_message_bytes = ws_message.as_bytes();

        match room {
            None => {
                if ws_message_bytes.len() == 2 * PUB_KEY_LEN {
                    let pka: [u8; PUB_KEY_LEN] = ws_message_bytes[..PUB_KEY_LEN].try_into().unwrap();
                    let pkb: [u8; PUB_KEY_LEN] = ws_message_bytes[PUB_KEY_LEN..].try_into().unwrap();

                    room_key = Some(RoomKey::new(&pka, &pkb));
                    {
                        let mut rooms_guard = ROOMS.lock().await;
                        room = Some(rooms_guard.enroll(room_key.unwrap()));
                    }

                    let mut room_guard = room.as_ref().unwrap().lock().await;
                    room_guard.add_tx(tx.clone());
                    debug!("{:?}: Enrolled in room: {:?}", session_id, room_guard.file_path);

                    let mut tx_guard = tx.lock().await;
                    send(&mut tx_guard, &session_id, &room_key.unwrap().0.to_be_bytes()).await;
                    room_guard.send_all_messages(&session_id, &mut tx_guard).await;
                } else {
                    log::debug!("{:?}: Message length: {} expected: {}", session_id, ws_message_bytes.len(), 2 * PUB_KEY_LEN);
                    break;
                }
            }
            Some(ref room) => {
                if ws_message_bytes.len() == WS_MSG_LEN as usize {
                    let message = Msg(ws_message_bytes.try_into().unwrap());

                    let mut room_guard: tokio::sync::MutexGuard<'_, Room> = room.lock().await;
                    room_guard.add_message(&message);

                    debug!("{:?}: Added message to room", session_id);

                    for peer_tx in room_guard.peer_txs() {
                        let mut peer_tx_guard = peer_tx.lock().await;
                        send(&mut peer_tx_guard, &session_id, &message.0).await;
                    }
                } else {
                    log::debug!("{:?}: Message length: {} expected: {}", session_id, ws_message_bytes.len(), WS_MSG_LEN);
                    break;
                }
            }
        }
    }

    let mut room_guard = room.as_ref().unwrap().lock().await;
    if room_guard.remove_tx(tx.clone()) == 0 {
        if let Some(room_key) = room_key {
            let mut rooms_guard = ROOMS.lock().await;
            rooms_guard.remove(room_key);
            debug!("{:?}: Removed room: {:?}", session_id, hex::encode(&room_key.0.to_be_bytes()));
        }
    }
    info!("{:?}: Session closed", session_id);
}
