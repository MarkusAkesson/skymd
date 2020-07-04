use crate::ffi::{
    EverCrypt_Chacha20Poly1305_aead_decrypt, EverCrypt_Chacha20Poly1305_aead_encrypt,
};

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    associated_data: &[u8],
    plaintext: &mut [u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), ()> {
    let res = unsafe {
        EverCrypt_Chacha20Poly1305_aead_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            associated_data.len() as u32,
            associated_data.as_ptr(),
            ciphertext.len() as u32,
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            tag.as_ptr(),
        )
    };

    match res {
        0 => Ok(()),
        _ => Err(()),
    }
}

pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    associated_data: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) {
    unsafe {
        EverCrypt_Chacha20Poly1305_aead_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            associated_data.len() as u32,
            associated_data.as_ptr(),
            plaintext.len() as u32,
            plaintext.as_ptr(),
            ciphertext.as_mut_ptr(),
            tag.as_mut_ptr(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        crate::skymd_init();
        let key = [1; KEY_LEN];
        let nonce = [1; NONCE_LEN];
        let associated_data = [1; 10];
        let plaintext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut decrypted = [0; 10];
        let mut ciphertext = [0; 10];
        let mut tag = [0; TAG_LEN];

        encrypt(
            &key,
            &nonce,
            &associated_data,
            &plaintext,
            &mut ciphertext,
            &mut tag,
        );

        let res = decrypt(
            &key,
            &nonce,
            &associated_data,
            &mut decrypted,
            &ciphertext,
            &tag,
        );

        assert!(res.is_ok());
        assert_eq!(&plaintext, &decrypted);
    }
}
