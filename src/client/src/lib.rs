use std::error::Error;

pub const NONCE_LEN: usize = 24;
pub const SEC_KEY_LEN: usize = 32;
pub const PUB_KEY_LEN: usize = 33;

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use secp256k1::{self, All, PublicKey, Scalar, Secp256k1};

pub fn decrypt(
    shared_secret: &[u8; PUB_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    msg_enc: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    XChaCha20Poly1305::new(Key::from_slice(shared_secret))
        .decrypt(XNonce::from_slice(nonce), msg_enc)
        .map_err(|e| e.to_string().into())
}

pub fn derive_shared_secret(
    secp: &Secp256k1<All>,
    secret_key: [u8; SEC_KEY_LEN],
    public_key: &[u8; PUB_KEY_LEN],
) -> Result<[u8; PUB_KEY_LEN], Box<dyn Error>> {
    Ok(PublicKey::from_slice(public_key)
        .map_err(|e| e.to_string())?
        .mul_tweak(secp, &Scalar::from_be_bytes(secret_key).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?
        .serialize())
}
