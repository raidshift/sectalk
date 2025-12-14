import React, { useMemo, useEffect, useRef, useState, type ReactElement } from "react";
import ReactDOM from "react-dom/client";
import { minidenticon } from 'minidenticons'
import EC from 'elliptic';
import { sha256 } from 'js-sha256';
import sodium from 'libsodium-wrappers';
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

export const User = {
  ALICE: 0,
  BOB: 1,
} as const;

export type User = typeof User[keyof typeof User];

const isHex = (str: string) => /^[0-9a-fA-F]+$/.test(str);

const MSG_LEN = 100;
const MSG_MAX_BYTES = 99;

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
  let user: User | undefined = undefined;

  useEffect(() => {
    const ec = new EC.ec('secp256k1');
    let verifySigMsg: Uint8Array;
    let keyPair: EC.ec.KeyPair;
    let roomKey: Uint8Array;
    let skaredKey: Uint8Array;
    let publicKey = '';
    let peerPublicKey = '';
    let signatureHex = '';

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

          roomKey = Uint8Array.from(bytes);

          const tmpSharedKey = new Uint8Array(keyPair.derive(ec.keyFromPublic(peerPublicKey, 'hex').getPublic()).toArray('be', 32));

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
          if (bytes.length === 1) {
            socket.close();
          } else {
            const decoder = new TextDecoder('utf-8');

            const nonce = bytes.slice(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            const ciphertext = bytes.slice(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            const decryptedMsg = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, skaredKey);
            let decryptedString = decoder.decode(decryptedMsg);

            let yourMsg: boolean = false;
            if ((decryptedString.startsWith('A') && user === User.ALICE) || (decryptedString.startsWith('B') && user === User.BOB)) {
              yourMsg = true;
            }

            let hexNonce = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');

            decryptedString = decryptedString.slice(1);

            if (yourMsg) {
              const msgElement = document.getElementById(hexNonce);
              if (msgElement) {
                // msgElement.innerHTML += ' ✓';
                msgElement.classList.replace('text-emerald-700', 'text-emerald-400');
              }
            } else {
              addMessage(
                <div className="text-sm">
                  <span className="text-sky-400">&lt;&nbsp;</span><span className="text-sky-400" id={hexNonce}>{decryptedString.trim()}</span>
                </div>
              );
            }
            hideTerminal(false);

          }
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
        const encoder = new TextEncoder();

        keyPair = ec.keyFromPrivate(new Uint8Array(sha256.arrayBuffer(encoder.encode(msg))));

        publicKey = keyPair.getPublic(true, 'hex',);

        const signature = keyPair.sign(verifySigMsg, { canonical: true });
        signatureHex = signature.r.toString('hex').padStart(64, '0') + signature.s.toString('hex').padStart(64, '0');

        // removeTmpDivs()
        addMessage(
          <div className="flex text-gray-400 text-sm w-full">
            <div>
              your&nbsp;public&nbsp;key:&nbsp;
            </div>
            <input
              type="text"
              value={publicKey}
              readOnly
              className="text-sm bg-gray-900 text-emerald-400 text-left"
            />
            <MinidenticonImg username={publicKey} />
          </div>
        );

        setInputType("text");
        setPlaceHolder("enter peer public key");

        appState = AppState.AWAIT_PEER_PUB_KEY_FROM_USER;
      }
      else if (appState === AppState.AWAIT_PEER_PUB_KEY_FROM_USER) {
        msg = msg.toLowerCase();

        if (!(msg.length != publicKey.length || msg === publicKey || !isHex(msg) || msg[0] !== '0' || (msg[1] !== '2' && msg[1] !== '3'))) {

          peerPublicKey = msg;

          user = publicKey > peerPublicKey ? User.ALICE : User.BOB;

          const combined = publicKey.concat(peerPublicKey).concat(signatureHex);
          const combinedBytes = new Uint8Array(
            combined.match(/.{2}/g)?.map(byte => parseInt(byte, 16)) || []
          );

          addMessage(
            <div className="flex text-gray-400 text-sm w-full">
              <div>
                peer&nbsp;public&nbsp;key:&nbsp;
              </div>
              <input
                type="text"
                value={peerPublicKey}
                readOnly
                className="text-sm bg-gray-900 text-sky-400 text-left"
              />
              <MinidenticonImg username={peerPublicKey} />
            </div>
          );
          hideTerminal(true);

          socket.send(combinedBytes);

          appState = AppState.AWAITING_ROOM_ID_FROM_SERVER;
        }
      }
      else if (appState === AppState.AWAIT_MESSAGES) {
        let origMesg = msg.trim();

        msg = user === User.ALICE ? "A" + msg : "B" + msg;
        const encoder = new TextEncoder();
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

    let len = new TextEncoder().encode(newValue).length;

    while (len > MSG_MAX_BYTES) {
      newValue = newValue.slice(0, -1);
      len = new TextEncoder().encode(newValue).length;
    }
    setInputMessage(newValue);
    setMsgBytes(new TextEncoder().encode(newValue).length);
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
            ({msgBytes}/{MSG_MAX_BYTES} bytes)
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



