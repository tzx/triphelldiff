use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::PublicKey;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

type HkdfSha256 = Hkdf<Sha256>;
type HmacSha256 = Hmac<Sha256>;

// Difference from Signal Protocol: We don't store the previous sending chain length (PN).
// Reason: Only advance chain to get message keys when we receive them using chain index only.
// We would know which chain to use since each message gives a corresponding diffie-hellman ratchet public key.

pub struct EncryptedMessage {
    chain_index: u64,
    ciphertext: Vec<u8>,
    dh_ratchet_key: PublicKey,
    mac: Vec<u8>,
}

const HKDF_INFO: &[u8] = b"APPLICATION_SPECIFIC_BYTE_SEQ";

impl EncryptedMessage {
    // TODO: message_key type
    pub fn new(
        plaintext: &str,
        message_key: [u8; 32],
        chain_index: u64,
        dh_ratchet_key: PublicKey,
    ) -> Self {
        // Not providing salt is already zero-filled byte sequence
        let hk = HkdfSha256::new(None, &message_key);
        let mut okm = [0u8; 80];
        hk.expand(HKDF_INFO, &mut okm).expect("valid length must be used");

        // TODO: LOL THIS CRYPTO IS TOO ADVANCED, might want a new module
        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&okm[0..32]);
        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&okm[32..64]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&okm[64..80]);

        let cipher = Aes256CbcEnc::new(&encryption_key.into(), &iv.into());
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

        // Right now associated data is just chain_index and public ratchet_key
        let hmac_input = [
            chain_index.to_be_bytes().as_ref(),
            &dh_ratchet_key.to_bytes(),
            &ciphertext,
        ]
        .concat();

        let mut mac = HmacSha256::new_from_slice(&auth_key).expect("HMAC can take key of any size");
        mac.update(&hmac_input);
        let result = mac.finalize();

        Self {
            chain_index,
            ciphertext,
            dh_ratchet_key,
            mac: result.into_bytes().to_vec(),
        }
    }
}
