use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::ffi::{
    EverCrypt_Curve25519_ecdh, EverCrypt_Curve25519_scalarmult,
    EverCrypt_Curve25519_secret_to_public,
};

pub const KEY_LEN: usize = 32;

#[derive(Debug, Default)]
pub struct PublicKey {
    key: [u8; KEY_LEN],
}

#[derive(Debug, Default)]
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
        EverCrypt_Curve25519_secret_to_public(pub_key.as_mut_ptr(), priv_key.key.as_ptr());
    }

    let pub_key = PublicKey { key: pub_key };

    (pub_key, priv_key)
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl PrivateKey {
    pub fn new() -> Self {
        let mut buf = [0u8; KEY_LEN];

        OsRng.fill_bytes(&mut buf);
        PrivateKey::scalar(&mut buf);

        Self { key: buf }
    }

    fn scalar(buf: &mut [u8; KEY_LEN]) {
        buf[0] &= 248;
        buf[31] &= 127;
        buf[31] |= 64;
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn from_slice(mut slice: [u8; KEY_LEN]) -> Self {
        PrivateKey::scalar(&mut slice);
        Self { key: slice }
    }

    pub fn ecdh(&self, public_key: &PublicKey) -> SharedSecret {
        let mut ss = [0u8; KEY_LEN];
        unsafe {
            EverCrypt_Curve25519_ecdh(ss.as_mut_ptr(), self.key.as_ptr(), public_key.key.as_ptr());
        }
        SharedSecret { key: ss }
    }
}

impl From<[u8; KEY_LEN]> for PrivateKey {
    fn from(pk: [u8; KEY_LEN]) -> PrivateKey {
        let mut pk = PrivateKey { key: pk };
        PrivateKey::scalar(&mut pk.key);
        pk
    }
}

impl From<[u8; KEY_LEN]> for PublicKey {
    fn from(pk: [u8; KEY_LEN]) -> PublicKey {
        PublicKey { key: pk }
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(privkey: &PrivateKey) -> PublicKey {
        let mut pubkey = PublicKey { key: [0; KEY_LEN] };
        unsafe {
            EverCrypt_Curve25519_secret_to_public(pubkey.key.as_mut_ptr(), privkey.key.as_ptr());
        }
        pubkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_test() {
        crate::skymd_init();
        let (pub_key1, priv_key1) = keypair();
        let (pub_key2, priv_key2) = keypair();
        assert_eq!(priv_key1.ecdh(&pub_key2).key, priv_key2.ecdh(&pub_key1).key);
    }
}
