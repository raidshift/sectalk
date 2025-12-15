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

// const MSG_MAX_BYTES = 99;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');



// function removeTmpDivs() {
//   const tmpDivs = document.querySelectorAll('div.tmp');
//   tmpDivs.forEach(div => div.remove());
// }

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
  const [hideTerminal, setHideTerminal] = useState(true);
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
    const ec = new EC.ec('secp256k1');
    let verifySigMsg: Uint8Array;
    let keyPair: EC.ec.KeyPair;
    let roomKey: Uint8Array;
    let skaredKey: Uint8Array;
    let publicKey: Uint8Array = new Uint8Array();
    let peerPublicKey: Uint8Array = new Uint8Array();
    let publicKey_base58: string = "";
    let peerPublicKey_base58: string = "";
    let signature: Uint8Array = new Uint8Array();

    const wsUrl = `/ws/`;

    const socket = new WebSocket(wsUrl);

    function hideTerminal(hide: boolean) {
      setHideTerminal(hide);

      if (!hide) {
        setTimeout(() => {
          inputRef.current?.focus();
        }, 200);
      }
    }


    socket.onopen = () => {
      appState = AppState.AWAIT_SECRET_KEY_FROM_USER;
      // inputRef.current?.focus();
    };

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
          hideTerminal(false);

        } else if (appState === AppState.AWAITING_ROOM_ID_FROM_SERVER) {


          const tmpSharedKey = new Uint8Array(keyPair.derive(ec.keyFromPublic(peerPublicKey).getPublic()).toArray('be', 32));

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
          hideTerminal(false);


        } else if (appState === AppState.AWAIT_MESSAGES) {

          if (bytes.length === ABORT_MSG_LEN) {
            socket.close();
          } else if (bytes.length === ENCRYPTED_MSG_LEN) {

            const nonce = bytes.slice(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            const ciphertext = bytes.slice(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            const decryptedMsg = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, skaredKey);
            let decryptedString = decoder.decode(decryptedMsg);

            // let yourMsg: boolean = false;
            // if ((decryptedString.startsWith('A') && user === User.ALICE) || (decryptedString.startsWith('B') && user === User.BOB)) {
            //   yourMsg = true;
            // }

            // decryptedString = decryptedString.slice(1);
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
            console.log("received confirmation for nonce: ", hexNonce);

            const msgElement = document.getElementById(hexNonce);
            if (msgElement) {
              msgElement.classList.replace('text-emerald-700', 'text-emerald-400');
            }
          } else {
            console.log("received message with invalid length: ", bytes.length);
          }
          hideTerminal(false);
        }
      })
    };

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

    function handleMessage(msg: string) {
      msg = msg.trim();

      if (appState === AppState.AWAIT_SECRET_KEY_FROM_USER) {

        keyPair = ec.keyFromPrivate(new Uint8Array(sha256.arrayBuffer(encoder.encode(msg))));

        publicKey = new Uint8Array(keyPair.getPublic(true, 'array'));

        publicKey_base58 = bs58.encode(publicKey);

        const ecSig = keyPair.sign(verifySigMsg, { canonical: true });
        const rBytes = ecSig.r.toArray('be', 32);
        const sBytes = ecSig.s.toArray('be', 32);
        signature = new Uint8Array(64);
        signature.set(rBytes, 0);
        signature.set(sBytes, 32);

        // removeTmpDivs()
        addMessage(
          <div className="flex text-gray-400 text-sm w-full">
            <div>
              your&nbsp;public&nbsp;key:&nbsp;
            </div>
            <input
              type="text"
              value={publicKey_base58}
              readOnly
              className="text-sm bg-gray-900 text-emerald-400 text-left"
            />
            <MinidenticonImg username={publicKey_base58} />
          </div>
        );

        setInputType("text");
        setPlaceHolder("enter peer public key");

        appState = AppState.AWAIT_PEER_PUB_KEY_FROM_USER;
      }
      else if (appState === AppState.AWAIT_PEER_PUB_KEY_FROM_USER) {

        if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(msg)) {
          peerPublicKey = bs58.decode(msg);
          peerPublicKey_base58 = msg;
        }

        if (peerPublicKey.length === publicKey.length && !peerPublicKey.every((b, i) => b === publicKey[i]) && (peerPublicKey[0] === 2 || peerPublicKey[0] === 3)) {

          try {
            ec.keyFromPublic(peerPublicKey);


            const combined = new Uint8Array([...publicKey, ...peerPublicKey, ...signature]);

            addMessage(
              <div className="flex text-gray-400 text-sm w-full">
                <div>
                  peer&nbsp;public&nbsp;key:&nbsp;
                </div>
                <input
                  type="text"
                  value={peerPublicKey_base58}
                  readOnly
                  className="text-sm bg-gray-900 text-sky-400 text-left"
                />
                <MinidenticonImg username={peerPublicKey_base58} />
              </div>
            );
            hideTerminal(true);

            socket.send(combined);

            appState = AppState.AWAITING_ROOM_ID_FROM_SERVER;
          }
          catch (e) {}
        }
      }
      else if (appState === AppState.AWAIT_MESSAGES) {
        let origMesg = msg.trim();

        // msg = user === User.ALICE ? "A" + msg : "B" + msg;
        let encodedMsg = encoder.encode(msg);

        if (encodedMsg.length < MSG_LEN) {
          const padding = MSG_LEN - encodedMsg.length;
          msg = msg + ' '.repeat(padding);
          encodedMsg = encoder.encode(msg);
        } else if (encodedMsg.length > MSG_LEN) {
          encodedMsg = encodedMsg.slice(0, MSG_LEN);
        }

        const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(encodedMsg, null, null, nonce, skaredKey);
        const encryptedMsg = new Uint8Array(nonce.length + ciphertext.length);
        encryptedMsg.set(nonce);
        encryptedMsg.set(ciphertext, nonce.length);

        let hexNonce = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
        console.log("sending message with nonce: ", hexNonce);

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

    let len = encoder.encode(newValue).length;

    while (len > MSG_LEN) {
      newValue = newValue.slice(0, -1);
      len = encoder.encode(newValue).length;
    }
    setInputMessage(newValue);
    setMsgBytes(encoder.encode(newValue).length);
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
      <div className="text-sm" style={{ display: hideTerminal || terminateApp ? 'none' : 'block' }}>
        <form onSubmit={handleFormSubmit} className="flex flex-row justify-center align-center text-emerald-400">
          <div>&gt;&nbsp;</div>
          <input
            type={inputType}
            value={inputMessage}
            onChange={handleInputChange}
            ref={inputRef}
            placeholder={placeholder}
            className="text-emerald-400 placeholder-emerald-700 bg-gray-900"
          />
        </form>
        {showMsgBytes && msgBytes > 0 ? (
          <div className="text-xs text-gray-500 ps-3">
            ({msgBytes}/{MSG_LEN} bytes)
          </div>
        ) : null
        }
      </div>
      <div style={{ display: !hideTerminal || terminateApp ? 'none' : 'block' }} className="text-emerald-400">
        <div className="spinner"></div>
      </div>
    </>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root") as HTMLElement);
root.render(<App />);



