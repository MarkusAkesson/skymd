#[allow(dead_code)]
#[link(name = "evercrypt", kind = "static")]
extern "C" {
    // Auto config
    pub(crate) fn EverCrypt_AutoConfig2_init();

    // ChaChaPoly AEAD
    pub(crate) fn EverCrypt_Chacha20Poly1305_aead_encrypt(
        k: *const u8,
        n1: *const u8,
        aadlen: u32,
        aad: *const u8,
        mlen: u32,
        m: *const u8,
        cipher: *const u8,
        tag: *const u8,
    );

    pub(crate) fn EverCrypt_Chacha20Poly1305_aead_decrypt(
        k: *const u8,
        n1: *const u8,
        aadlen: u32,
        aad: *const u8,
        mlen: u32,
        m: *const u8,
        cipher: *const u8,
        tag: *const u8,
    ) -> u8;

    // Curve25519
    pub(crate) fn EverCrypt_Curve25519_scalarmult(
        shared: *mut u8,
        my_priv: *const u8,
        their_pub: *const u8,
    );

    pub(crate) fn EverCrypt_Curve25519_secret_to_public(public: *mut u8, private: *const u8);

    pub(crate) fn EverCrypt_Curve25519_ecdh(
        shared: *mut u8,
        my_private: *const u8,
        their_public: *const u8,
    );
}
