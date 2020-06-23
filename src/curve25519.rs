use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::ffi::{
    EverCrypt_Curve25519_ecdh, EverCrypt_Curve25519_scalarmult,
    EverCrypt_Curve25519_secret_to_public,
};

const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
pub const KEY_LEN: usize = 32;

#[derive(Debug)]
pub struct PublicKey {
    key: [u8; KEY_LEN],
}

#[derive(Debug)]
pub struct PrivateKey {
    key: [u8; KEY_LEN],
}

#[derive(Debug)]
pub struct SharedSecret {
    key: [u8; KEY_LEN],
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub fn keypair() -> (PublicKey, PrivateKey) {
    let priv_key = PrivateKey::new();
    let mut pub_key = [0u8; KEY_LEN];

    unsafe {
        EverCrypt_Curve25519_scalarmult(
            pub_key.as_mut_ptr(),
            priv_key.key.as_ptr(),
            BASEPOINT.as_ptr(),
        );

        EverCrypt_Curve25519_secret_to_public(pub_key.as_mut_ptr(), priv_key.key.as_ptr());
    }
    dbg!(&BASEPOINT);

    let pub_key = PublicKey { key: pub_key };

    (pub_key, priv_key)
}

impl PrivateKey {
    pub fn new() -> Self {
        let mut buf = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut buf);

        // Curve25519 secret key scalar calculation
        buf[0] &= 248;
        buf[31] &= 127;
        buf[31] |= 64;

        Self { key: buf }
    }

    pub fn ecdh(&self, public_key: &PublicKey) -> SharedSecret {
        let mut ss = [0u8; KEY_LEN];
        unsafe {
            EverCrypt_Curve25519_ecdh(ss.as_mut_ptr(), self.key.as_ptr(), public_key.key.as_ptr());
        }
        SharedSecret { key: ss }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_test() {
        let (pub_key1, priv_key1) = keypair();
        let (pub_key2, priv_key2) = keypair();
        assert_eq!(priv_key1.ecdh(&pub_key2).key, priv_key2.ecdh(&pub_key1).key);
    }
}
