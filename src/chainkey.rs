use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type HkdfSha256 = Hkdf<Sha256>;

pub struct ChainKey {
    key: [u8; 32],
    index: u64,
}

use crate::encrypted_message::EncryptedMessage;

// Derive new key using HMAC with SHA-256 with key as HMAC key and
// 0x01 for input for message key and 0x02 for next chain key
const MESSAGE_KEY_SEED: &[u8; 1] = b"\x01";
const NEXT_CHAIN_KEY_SEED: &[u8; 1] = b"\x02";

impl ChainKey {
    fn from_bytes_and_index(bytes: [u8; 32], index: u64) -> Self {
        Self { key: bytes, index }
    }

    fn advance(&mut self) {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(NEXT_CHAIN_KEY_SEED);
        let new_key = mac.finalize().into_bytes();
        self.key.copy_from_slice(new_key.as_slice());
    }

    // TODO: Message key should probably be abstracted as own thing rather than array of bytes
    fn get_message_key(&self) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(MESSAGE_KEY_SEED);
        mac.finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("SHA256 output should return 32 bytes")
    }

    // TODO: Seperate Message key
    // fn encrypt_message(&self, plaintext: &str) -> EncryptedMessage {
    //     let message_key = self.get_message_key();
    //     EncryptedMessage::new(plaintext, message_key, self.index, dh_ratchet_key)
    // }
}
