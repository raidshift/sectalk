import React, { useEffect, useRef, useState, ReactElement } from "react";
import ReactDOM from "react-dom/client";
import EC from 'elliptic';
import { sha256 } from 'js-sha256';
import sodium from 'libsodium-wrappers';
import { version } from "../package.json";


enum AppState {
  INIT,
  AWAIT_SECRET_KEY_FROM_USER,
  AWAIT_PEER_PUB_KEY_FROM_USER,
  AWAITING_ROOM_ID_FROM_SERVER,
  AWAIT_MESSAGES,
}

enum User {
  ALICE = 0,
  BOB = 1,
}

const isHex = (str: string) => /^[0-9a-fA-F]+$/.test(str);

const MSG_LEN = 100;
const MSG_MAX_BYTES = 99;

function removeTmpDivs() {
  const tmpDivs = document.querySelectorAll('div.tmp');
  tmpDivs.forEach(div => div.remove());
}

function App() {
  const [hideTerminal, setHideTerminal] = useState(true);
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
    let sharedSecret = '';
    let publicKey = '';
    let signatureHex = '';


    // remote server url
    const wsUrl = "https://xchange.my.to/ws/"

    // local server url:
    // const wsUrl = `http://localhost:3030/ws/` 

    const socket = new WebSocket(wsUrl);


    socket.onopen = () => {
      appState = AppState.AWAIT_SECRET_KEY_FROM_USER;
      inputRef.current?.focus();
    };

    socket.onclose = () => {
      addMessage(
        <div className="text-red-500">
          Disconnected from server
        </div>);
      setHideTerminal(true);
    };

    socket.onmessage = function (event) {
      const blob = event.data;
      blob.arrayBuffer().then(buffer => {
        const bytes = new Uint8Array(buffer);


        if (appState === AppState.AWAIT_SECRET_KEY_FROM_USER) {
          verifySigMsg = Uint8Array.from(bytes);
          setPlaceHolder("Enter your secret key");
          setHideTerminal(false);

        } else if (appState === AppState.AWAITING_ROOM_ID_FROM_SERVER) {
          const roomId = Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

          addMessage(
            <div className="text-gray-400 text-xs">You can now send end-to-end encrypted messages to your online peer.</div>
          );

          setPlaceHolder("Enter your message")

          appState = AppState.AWAIT_MESSAGES;
          setShowMsgBytes(true);
          setHideTerminal(false);


        } else if (appState === AppState.AWAIT_MESSAGES) {
          const decoder = new TextDecoder('utf-8');

          const nonce = bytes.slice(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
          const ciphertext = bytes.slice(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
          const key = sodium.from_hex(sharedSecret);
          const decryptedMsg = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key);
          let decryptedString = decoder.decode(decryptedMsg);

          let yourMsg: boolean = false;
          if ((decryptedString.startsWith('A') && user === User.ALICE) || (decryptedString.startsWith('B') && user === User.BOB)) {
            yourMsg = true;
          }

          decryptedString = decryptedString.slice(1);

          yourMsg ?
            addMessage(
              <div className={`text-emerald-500`}>
                &gt;&nbsp;{decryptedString.trim()}
              </div>
            ) :
            addMessage(
              <div className={` text-sky-500`}>
                &lt;&nbsp;{decryptedString.trim()}
              </div>
            );
          setHideTerminal(false);

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

        removeTmpDivs()
        addMessage(
          <div className="border rounded-lg p-2 border-gray-400">
            <div className="text-gray-400 text-xs">Your public ID</div>
            {/* <div className="text-emerald-500 text-sm">{publicKey}</div> */}
            <input
              type="text"
              value={publicKey}
              readOnly
              className="text-sm text-emerald-500"
            />
          </div>
        );

        // addMessage(
        //   <div className="tmp">Enter ID of peer</div>
        // );

        setInputType("text");
        setPlaceHolder("Enter public ID of your peer");

        appState = AppState.AWAIT_PEER_PUB_KEY_FROM_USER;
      }
      else if (appState === AppState.AWAIT_PEER_PUB_KEY_FROM_USER) {
        msg = msg.toLowerCase();

        if (!(msg.length != publicKey.length || msg === publicKey || !isHex(msg) || msg[0] !== '0' || (msg[1] !== '2' && msg[1] !== '3'))) {
          try {
            sharedSecret = keyPair.derive(ec.keyFromPublic(msg, 'hex').getPublic()).toString(16);
          } catch (err) { console.log("no pub key !!!") }
        }

        if (sharedSecret) {
          user = publicKey > msg ? User.ALICE : User.BOB;

          const combined = publicKey.concat(msg).concat(signatureHex);
          const combinedBytes = new Uint8Array(
            combined.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
          );
          removeTmpDivs()
          addMessage(
            <div className="border rounded-lg p-2 border-gray-400">
              <div className="text-gray-400 text-xs">Peer public ID</div>
              {/* <div className="text-sky-500 text-sm">{msg}</div> */}
              <input
                type="text"
                value={msg}
                readOnly
                className="text-sm text-sky-500"
              />
            </div>
          );

          socket.send(combinedBytes);
          setHideTerminal(true);

          appState = AppState.AWAITING_ROOM_ID_FROM_SERVER;
        }
      }
      else if (appState === AppState.AWAIT_MESSAGES) {

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
        const key = sodium.from_hex(sharedSecret);
        const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(encodedMsg, null, null, nonce, key);
        const encryptedMsg = new Uint8Array(nonce.length + ciphertext.length);
        encryptedMsg.set(nonce);
        encryptedMsg.set(ciphertext, nonce.length);

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
      <div id="hist">
        <div className="histitem">
          <div className="flex text-gray-400 justify-between">
            <div>
              sectalk <span className="text-xs">(<a href="https://github.com/raidshift/sectalk" target="_blank" className="text-gray-400 hover:text-gray-300">github.com/raidshift/sectalk</a>)</span>
            </div>
            <div className="text-xs text-gray-700">
              (build {version})
            </div>
          </div>
        </div>
      </div>
      <div style={{ display: hideTerminal ? 'none' : 'block' }}>
        <form onSubmit={handleFormSubmit} className="flex flex-row justify-center align-center text-emerald-500">
          <div>&gt;&nbsp;</div>
          <input
            type={inputType}
            value={inputMessage}
            onChange={handleInputChange}
            ref={inputRef}
            placeholder={placeholder}
            className="text-emerald-500 placeholder-emerald-700"
          />
        </form>
        {showMsgBytes && msgBytes > 0 ? (
          <div className="text-xs text-gray-500 ps-3">
            ({msgBytes}/{MSG_MAX_BYTES} bytes)
          </div>
        ) : null
        }
      </div>
      <div style={{ display: !hideTerminal ? 'none' : 'block' }} className="text-emerald-500">
        <div className="spinner"></div>
      </div>
    </>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root") as HTMLElement);
root.render(<App />);
