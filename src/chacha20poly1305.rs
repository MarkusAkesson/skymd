use crate::ffi::{
    EverCrypt_Chacha20Poly1305_aead_decrypt, EverCrypt_Chacha20Poly1305_aead_encrypt,
};

const KEY_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 24;

pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    associated_data: &[u8],
    plaintext: &mut [u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_SIZE],
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
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    associated_data: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; TAG_SIZE],
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
        let key = [1; KEY_SIZE];
        let nonce = [1; NONCE_SIZE];
        let associated_data = [1; 10];
        let plaintext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut decrypted = [0; 10];
        let mut ciphertext = [0; 10];
        let mut tag = [0; TAG_SIZE];

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
