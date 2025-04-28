use std::{error::Error, mem, ptr, sync::atomic};

pub const NONCE_LEN: usize = 24;
pub const SEC_KEY_LEN: usize = 32;
pub const PUB_KEY_LEN: usize = 33;

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use secp256k1::hashes::sha256::Hash;
use secp256k1::{self, All, PublicKey, Scalar, Secp256k1, SecretKey};
use zeroize::{Zeroize, Zeroizing};

pub struct ZeroizableSecretKey(pub SecretKey);
pub struct ZeroizableHash(pub Hash);
struct ZeroizablePublicKey(PublicKey);
struct ZeroizableScalar(Scalar);

impl Zeroize for ZeroizableSecretKey {
    fn zeroize(&mut self) {
        zeroize(&mut self.0);
    }
}

impl Zeroize for ZeroizablePublicKey {
    fn zeroize(&mut self) {
        zeroize(&mut self.0);
    }
}

impl Zeroize for ZeroizableScalar {
    fn zeroize(&mut self) {
        zeroize(&mut self.0);
    }
}

impl Zeroize for ZeroizableHash {
    fn zeroize(&mut self) {
        zeroize(&mut self.0);
    }
}

pub fn zeroize<T>(z: &mut T) {
    atomic::compiler_fence(atomic::Ordering::SeqCst);

    let ptr = z as *mut _ as *mut u8;

    println!("bytes before zeroizing: {:?}", unsafe {
        std::slice::from_raw_parts(ptr, mem::size_of_val(z))
    });

    unsafe {
        for i in 0..mem::size_of_val(z) {
            ptr::write_volatile(ptr.add(i), 0);
        }
    }
    atomic::compiler_fence(atomic::Ordering::SeqCst);
    println!("zeroized {} bytes", mem::size_of_val(z));
    println!("bytes after zeroizing: {:?}", unsafe {
        std::slice::from_raw_parts(ptr, mem::size_of_val(z))
    });
}

pub fn encrypt(
    shared_secret: &[u8; SEC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    XChaCha20Poly1305::new(Key::from_slice(shared_secret))
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|e| e.to_string().into())
}

pub fn decrypt(
    shared_secret: &[u8; SEC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    XChaCha20Poly1305::new(Key::from_slice(shared_secret))
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| e.to_string().into())
}

pub fn derive_shared_secret(
    secp: &Secp256k1<All>,
    secret_key: &[u8; SEC_KEY_LEN],
    public_key: &[u8; PUB_KEY_LEN],
) -> Result<[u8; SEC_KEY_LEN], Box<dyn Error>> {
    let scalar = Zeroizing::new(ZeroizableScalar(
        Scalar::from_be_bytes(*secret_key).map_err(|e| e.to_string())?,
    ));

    let shared_secret_public_key = Zeroizing::new(ZeroizablePublicKey(
        PublicKey::from_slice(public_key)
            .map_err(|e| e.to_string())?
            .mul_tweak(secp, &scalar.0)
            .map_err(|e| e.to_string())?,
    ));

    let shared_secret_public_key_serialized = Zeroizing::new(shared_secret_public_key.0.serialize());

    Ok(shared_secret_public_key_serialized[1..SEC_KEY_LEN + 1]
        .try_into()
        .unwrap())
}
