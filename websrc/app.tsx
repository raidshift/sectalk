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

// function removeTmpDivs() {
//   const tmpDivs = document.querySelectorAll('div.tmp');
//   tmpDivs.forEach(div => div.remove());
// }

function removeHistItemDivs() {
  const histItemDivs = document.querySelectorAll('div.histitem');
  histItemDivs.forEach(div => div.remove());
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
    let sharedSecret = '';
    let publicKey = '';
    let signatureHex = '';


    // remote server url
    // const wsUrl = "https://sectalk.my.to/ws/"

    // local server url:
    const wsUrl = `http://neo.local/ws/:3030`

    const socket = new WebSocket(wsUrl);

    function hideTerminal(hide: boolean) {
      setHideTerminal(hide);

      if (!hide) {
        setTimeout(() => {
          inputRef.current?.focus();
          console.log("FOCUSING");
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
          Disconnected from server
        </div>);
    };

    socket.onmessage = function (event) {
      const blob = event.data;
      blob.arrayBuffer().then(buffer => {
        const bytes = new Uint8Array(buffer);

        if (appState === AppState.AWAIT_SECRET_KEY_FROM_USER) {
          verifySigMsg = Uint8Array.from(bytes);
          setPlaceHolder("Enter your secret key");
          hideTerminal(false);

        } else if (appState === AppState.AWAITING_ROOM_ID_FROM_SERVER) {
          const roomId = Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

          addMessage(
            <div className="text-gray-400 text-sm">Ready to send messages to online peer</div>
          );

          setPlaceHolder("Enter your message")

          appState = AppState.AWAIT_MESSAGES;
          setShowMsgBytes(true);
          hideTerminal(false);


        } else if (appState === AppState.AWAIT_MESSAGES) {
          if (bytes.length === 1) {
            socket.close();
          }
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
              // <div className={`text-emerald-500`}>
              //   &gt;&nbsp;{decryptedString.trim()}
              // </div>

              <div className="flex justify-start">
                <div className=" bg-gray-900 rounded-2xl w-full">
                  {/* <div className="text-emerald-500 text-xs text-start">You</div> */}
                  <div className="text-sm text-emerald-400 bg-gray-900 text-left">
                    &gt;&nbsp;{decryptedString.trim()}
                  </div>
                </div>
              </div>
            ) :
            addMessage(
              // <div className={` text-sky-500`}>
              //   &lt;&nbsp;{decryptedString.trim()}
              // </div>
              <div className="flex justify-start">
                <div className=" bg-gray-900 rounded-2xl w-full">
                  {/* <div className="text-sky-500 text-xs text-start">Peer</div> */}
                  <div className="text-sm text-sky-400 bg-gray-900 text-left">
                    &lt;&nbsp;{decryptedString.trim()}
                  </div>
                </div>
              </div>
            );
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
        const encoder = new TextEncoder();

        keyPair = ec.keyFromPrivate(new Uint8Array(sha256.arrayBuffer(encoder.encode(msg))));
        publicKey = keyPair.getPublic(true, 'hex',);

        const signature = keyPair.sign(verifySigMsg, { canonical: true });
        signatureHex = signature.r.toString('hex').padStart(64, '0') + signature.s.toString('hex').padStart(64, '0');

        // removeTmpDivs()
        addMessage(
          <div className="flex text-gray-400 text-sm w-full">
            <div>
              Your&nbsp;public&nbsp;key:&nbsp;
            </div>
            <input
              type="text"
              value={publicKey}
              readOnly
              className="text-sm bg-gray-900 text-emerald-400 text-left"
            />
          </div>
        );

        setInputType("text");
        setPlaceHolder("Enter peer public key");

        appState = AppState.AWAIT_PEER_PUB_KEY_FROM_USER;
      }
      else if (appState === AppState.AWAIT_PEER_PUB_KEY_FROM_USER) {
        msg = msg.toLowerCase();

        if (!(msg.length != publicKey.length || msg === publicKey || !isHex(msg) || msg[0] !== '0' || (msg[1] !== '2' && msg[1] !== '3'))) {
          try {
            sharedSecret = keyPair.derive(ec.keyFromPublic(msg, 'hex').getPublic()).toString(16);

            console.log("shared secret: ", sharedSecret);
            console.log("shared secret length: ", sharedSecret.length);
          } catch (err) { console.log("no pub key !!!") }
        }

        if (sharedSecret) {
          user = publicKey > msg ? User.ALICE : User.BOB;

          const combined = publicKey.concat(msg).concat(signatureHex);
          const combinedBytes = new Uint8Array(
            combined.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
          );
          // removeTmpDivs()
          addMessage(
            <div className="flex text-gray-400 text-sm w-full">
              <div>
                Peer&nbsp;public&nbsp;key:&nbsp;
              </div>
              <input
                type="text"
                value={msg}
                readOnly
                className="text-sm bg-gray-900 text-sky-400 text-left"
              />
            </div>
          );

          socket.send(combinedBytes);
          hideTerminal(true);

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
      <div className="flex text-gray-400 justify-between">
        <div>
          <span className="text-xl font-bold">sectalk</span>
        </div>
        <div className="text-xs text-gray-700">
          <span className="text-xs"><a href="https://github.com/raidshift/sectalk" target="_blank" className="text-gray-700 hover:text-gray-600">build 1.0.{version}</a></span>
        </div>
      </div>
      <div className=" text-gray-400 text-sm">
        A peer-to-peer, end-to-end encrypted messaging protocol
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
