mod ffi;

pub mod chacha20poly1305;
pub mod curve25519;

pub fn skymd_init() {
    unsafe {
        ffi::EverCrypt_AutoConfig2_init();
    }
}
