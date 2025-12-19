import React, { useMemo, useEffect, useRef, useState, type ReactElement } from "react";
import ReactDOM from "react-dom/client";
import { minidenticon } from 'minidenticons'
import EC from 'elliptic';
import { sha256 } from 'js-sha256';
import sodium from 'libsodium-wrappers';
import bs58 from 'bs58';
import { version } from "../package.json";
import './index.css'

export const AppState = {
  INIT: 'INIT',
  AWAIT_SECRET_KEY_FROM_USER: 'AWAIT_SECRET_KEY_FROM_USER',
  AWAIT_PEER_PUB_KEY_FROM_USER: 'AWAIT_PEER_PUB_KEY_FROM_USER',
  AWAITING_ROOM_ID_FROM_SERVER: 'AWAITING_ROOM_ID_FROM_SERVER',
  AWAIT_MESSAGES: 'AWAIT_MESSAGES',
};

export type AppState = typeof AppState[keyof typeof AppState];

const MSG_LEN = 100;

const ABORT_MSG_LEN = 1;
const ENCRYPTED_MSG_LEN = 24 + 100 + 16; // nonce + ciphertext + auth tag
const ENCRYPTED_MSG_RECEIVED_CONF_LEN = 24; // nonce
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8');
const ELLIPTIC_CURVE = new EC.ec('secp256k1');
const WS_URL = `/ws/`;

let verifySigMsg: Uint8Array;
let keyPair: EC.ec.KeyPair;
let roomKey: Uint8Array;
let skaredKey: Uint8Array;
let publicKey: Uint8Array = new Uint8Array();
let peerPublicKey: Uint8Array = new Uint8Array();
let publicKey_base58: string = "";
let peerPublicKey_base58: string = "";
let signature: Uint8Array = new Uint8Array();



function shorten(str: string, by: number, start: number = 0, sep: string = "") {
  if (!by) { by = 5 }
  if (!start) { start = 0 }
  if (!sep) { sep = "..." }
  let short = str;
  return short.substring(start, by) + sep + short.substring(short.length - by, short.length);
}

function removeHistItemDivs() {
  const histItemDivs = document.querySelectorAll('div.histitem');
  histItemDivs.forEach(div => div.remove());
}

const MinidenticonImg = ({ username }: { username: string; }) => {
  const saturation = 70;
  const lightness = 50;
  const svgURI = useMemo(
    () => 'data:image/svg+xml;utf8,' + encodeURIComponent(minidenticon(username, saturation, lightness)),
    [username, saturation, lightness]
  )
  return (<img src={svgURI} alt={username} style={{ width: 18, height: 18 }} />)
}

function App() {
  const [hiddenTerminal, setHiddenTerminal] = useState(true);
  const [terminateApp, setTerminateApp] = useState(false);
  const [inputType, setInputType] = useState("password");
  const [inputMessage, setInputMessage] = useState('');
  const [showMsgBytes, setShowMsgBytes] = useState(false);
  const [placeholder, setPlaceHolder] = useState("")
  const [msgBytes, setMsgBytes] = useState(0);
  const handleMessageRef = useRef<(msg: string) => void>(() => { });
  const inputRef = useRef<HTMLInputElement>(null);

  let appState = AppState.INIT;

  useEffect(() => {
    inputRef.current!.focus();
  }, [inputType]);

  useEffect(() => {
    const socket = new WebSocket(WS_URL);
    socket.onopen = () => { appState = AppState.AWAIT_SECRET_KEY_FROM_USER; };

    function hideTerminal(hide: boolean) {
      setHiddenTerminal(hide);
      if (!hide) {
        setTimeout(() => {
          inputRef.current?.focus();
        }, 200);
      }
    }

    function addMessage(msg: ReactElement) {
      const hist = document.getElementById('hist') as HTMLElement;
      const node = document.createElement('div');
      node.className = 'histitem';
      ReactDOM.createRoot(node).render(msg);
      hist.appendChild(node);
    }

    new MutationObserver(() => {
      window.scrollTo({
        top: document.documentElement.scrollHeight,
        behavior: 'smooth'
      });
    }).observe(document.getElementById('hist') as HTMLElement, { childList: true });

    new MutationObserver(() => {
      window.scrollTo({
        top: document.documentElement.scrollHeight,
        behavior: 'smooth'
      });
    }).observe(inputRef.current as HTMLElement, { attributes: true });


    socket.onclose = () => {
      setTerminateApp(true);
      hideTerminal(true);
      removeHistItemDivs();
      addMessage(
        <div className="text-red-400 text-sm">
          disconnected from server
        </div>);
    };

    socket.onmessage = function (event) {
      const blob = event.data;
      blob.arrayBuffer().then((buffer: any) => {
        const bytes = new Uint8Array(buffer);

        if (appState === AppState.AWAIT_SECRET_KEY_FROM_USER) {
          verifySigMsg = Uint8Array.from(bytes);
          setPlaceHolder("enter your secret key");

        } else if (appState === AppState.AWAITING_ROOM_ID_FROM_SERVER) {
          const tmpSharedKey = new Uint8Array(keyPair.derive(ELLIPTIC_CURVE.keyFromPublic(peerPublicKey).getPublic()).toArray('be', 32));
          roomKey = Uint8Array.from(bytes);
          const combined = new Uint8Array(roomKey.length + tmpSharedKey.length);
          combined.set(roomKey, 0);
          combined.set(tmpSharedKey, roomKey.length);
          skaredKey = new Uint8Array(sha256.arrayBuffer(combined));
          addMessage(
            <div className="text-gray-400 text-sm">ready to send ephemeral messages to online peer</div>
          );
          setPlaceHolder("enter your message")
          appState = AppState.AWAIT_MESSAGES;
          setShowMsgBytes(true);

        } else if (appState === AppState.AWAIT_MESSAGES) {
          if (bytes.length === ABORT_MSG_LEN) {
            socket.close();
          } else if (bytes.length === ENCRYPTED_MSG_LEN) {
            const nonce = bytes.slice(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            const ciphertext = bytes.slice(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            const decryptedMsg = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, skaredKey);
            let decryptedString = TEXT_DECODER.decode(decryptedMsg);
            let hexNonce = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
            addMessage(
              <div className="text-sm">
                <span className="text-sky-400">&lt;&nbsp;</span><span className="text-sky-400" id={hexNonce}>{decryptedString.trim()}</span>
              </div>
            );
            socket.send(nonce); // send received confirmation back to sender
          }
          else if (bytes.length === ENCRYPTED_MSG_RECEIVED_CONF_LEN) {
            let hexNonce = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const msgElement = document.getElementById(hexNonce);
            if (msgElement) {
              msgElement.classList.replace('text-emerald-700', 'text-emerald-400');
            }
          }
        }
        hideTerminal(false);
      })
    };

    function handleMessage(msg: string) {
      msg = msg.trim();

      if (appState === AppState.AWAIT_SECRET_KEY_FROM_USER) {
        keyPair = ELLIPTIC_CURVE.keyFromPrivate(new Uint8Array(sha256.arrayBuffer(TEXT_ENCODER.encode(msg))));
        publicKey = new Uint8Array(keyPair.getPublic(true, 'array'));
        publicKey_base58 = bs58.encode(publicKey);
        const ecSig = keyPair.sign(verifySigMsg, { canonical: true });
        const rBytes = ecSig.r.toArray('be', 32);
        const sBytes = ecSig.s.toArray('be', 32);
        signature = new Uint8Array(64);
        signature.set(rBytes, 0);
        signature.set(sBytes, 32);
        addMessage(
          <div className="flex flex-row items-center text-gray-400 text-sm w-full">
            <div>
              your&nbsp;public&nbsp;key:&nbsp;
            </div>
            <MinidenticonImg username={publicKey_base58} />
            <div className="sm:hidden text-emerald-400 mr-1">{shorten(publicKey_base58, 7)}</div>
            <div className="hidden sm:block text-emerald-400 mr-1">{publicKey_base58}</div>
            <button className="text-xs px-2 py-1 border rounded-xl text-emerald-700 hover:text-emerald-500 ml-auto active:text-emerald-400" onClick={() => navigator.clipboard.writeText(publicKey_base58)}>
              <div className="flex flex-row justify-center items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" fill="currentColor" className="bi bi-clipboard-fill" viewBox="0 0 16 16">
                  <path fillRule="evenodd" d="M10 1.5a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5zm-5 0A1.5 1.5 0 0 1 6.5 0h3A1.5 1.5 0 0 1 11 1.5v1A1.5 1.5 0 0 1 9.5 4h-3A1.5 1.5 0 0 1 5 2.5zm-2 0h1v1A2.5 2.5 0 0 0 6.5 5h3A2.5 2.5 0 0 0 12 2.5v-1h1a2 2 0 0 1 2 2V14a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V3.5a2 2 0 0 1 2-2" />
                </svg>
              </div>
            </button>
          </div>
        );
        setInputType("text");
        setPlaceHolder("enter peer public key");
        appState = AppState.AWAIT_PEER_PUB_KEY_FROM_USER;

        let peerPublicKeyInUrl = window.location.hash.slice(1);
        if (peerPublicKeyInUrl) { handleMessage(peerPublicKeyInUrl) }
      }

      else if (appState === AppState.AWAIT_PEER_PUB_KEY_FROM_USER) {
        if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(msg)) {
          peerPublicKey = bs58.decode(msg);
          peerPublicKey_base58 = msg;
        }
        if (peerPublicKey.length === publicKey.length && !peerPublicKey.every((b, i) => b === publicKey[i]) && (peerPublicKey[0] === 2 || peerPublicKey[0] === 3)) {
          try {
            ELLIPTIC_CURVE.keyFromPublic(peerPublicKey);
            const combined = new Uint8Array([...publicKey, ...peerPublicKey, ...signature]);
            addMessage(
              <div className="flex flex-row items-center text-gray-400 text-sm w-full">
                <div>
                  peer&nbsp;public&nbsp;key:&nbsp;
                </div>
                <MinidenticonImg username={peerPublicKey_base58} />
                <div className="sm:hidden text-sky-400 mr-1">{shorten(peerPublicKey_base58, 7)}</div>
                <div className="hidden sm:block text-sky-400 mr-1">{peerPublicKey_base58}</div>
              </div>
            );
            hideTerminal(true);
            socket.send(combined);
            history.pushState(null, "", `#${peerPublicKey_base58}`);
            appState = AppState.AWAITING_ROOM_ID_FROM_SERVER;
          }
          catch (e) { }
        }
      }

      else if (appState === AppState.AWAIT_MESSAGES) {
        let origMesg = msg.trim();
        let encodedMsg = TEXT_ENCODER.encode(msg);
        if (encodedMsg.length < MSG_LEN) {
          const padding = MSG_LEN - encodedMsg.length;
          msg = msg + ' '.repeat(padding);
          encodedMsg = TEXT_ENCODER.encode(msg);
        } else if (encodedMsg.length > MSG_LEN) {
          encodedMsg = encodedMsg.slice(0, MSG_LEN);
        }
        const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(encodedMsg, null, null, nonce, skaredKey);
        const encryptedMsg = new Uint8Array(nonce.length + ciphertext.length);
        encryptedMsg.set(nonce);
        encryptedMsg.set(ciphertext, nonce.length);
        let hexNonce = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
        addMessage(
          <div className="text-sm">
            <span className="text-emerald-400">&gt;&nbsp;</span><span className="text-emerald-700" id={hexNonce}>{origMesg}</span>
          </div>
        )

        socket.send(encryptedMsg);
      }
    }

    handleMessageRef.current = handleMessage;
  }, []);

  const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    let newValue = event.target.value.trimStart();
    let len = TEXT_ENCODER.encode(newValue).length;
    while (len > MSG_LEN) {
      newValue = newValue.slice(0, -1);
      len = TEXT_ENCODER.encode(newValue).length;
    }
    setInputMessage(newValue);
    setMsgBytes(TEXT_ENCODER.encode(newValue).length);
  };

  const handleFormSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (inputMessage.trim() !== '') {
      handleMessageRef.current(inputMessage);
      setMsgBytes(0);
      setInputMessage('');
    }
  };

  return (
    <>
      <div className="flex text-gray-400 justify-between">
        <div>
          <span className="text-sm font-bold">sectalk</span>
        </div>
        <div className="text-xs text-gray-700">
          <span className="text-xs"><a href="https://github.com/raidshift/sectalk" target="_blank" className="text-gray-700 hover:text-gray-600">build {version}</a></span>
        </div>
      </div>
      <div className=" text-gray-400 text-sm">
        chat peer-to-peer with end-to-end encryption and ephemeral messages
      </div>
      <div id="hist">
      </div>
      <div className="text-sm" style={{ display: hiddenTerminal || terminateApp ? 'none' : 'block' }}>
        {inputType === "password" ? (
          <form onSubmit={handleFormSubmit} className="flex flex-row justify-center align-center text-emerald-400" id="password_form">
            <div>&gt;&nbsp;</div>
            <input
              key="password-input"
              type="password"
              value={inputMessage}
              onChange={handleInputChange}
              ref={inputRef}
              placeholder={placeholder}
              className="text-emerald-400 placeholder-emerald-700"
              autoComplete="current-password"
              id="password-input"
            />
          </form>
        ) : (
          <form onSubmit={handleFormSubmit} className="flex flex-row justify-center align-center text-emerald-400" id="text_form">
            <div>&gt;&nbsp;</div>
            <input
              key="text-input"
              type="text"
              value={inputMessage}
              onChange={handleInputChange}
              ref={inputRef}
              placeholder={placeholder}
              className="text-emerald-400 placeholder-emerald-700"
              autoComplete="off"
              id="text-input"
            />
          </form>
        )}
        {showMsgBytes && msgBytes > 0 ? (
          <div className="text-xs text-gray-500 ps-3">
            ({msgBytes}/{MSG_LEN} bytes)
          </div>
        ) : null
        }
      </div>
      <div style={{ display: !hiddenTerminal || terminateApp ? 'none' : 'block' }} className="text-emerald-400">
        <div className="spinner"></div>
      </div>
    </>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root") as HTMLElement);
root.render(<App />);



