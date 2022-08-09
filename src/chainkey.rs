use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type HkdfSha256 = Hkdf<Sha256>;

pub struct ChainKey {
    key: [u8; 32],
    index: u64,
}

impl ChainKey {
    pub fn index(&self) -> u64 {
        self.index
    }
}

pub struct MessageKey([u8; 32]);

impl MessageKey {
    pub fn as_byte_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

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
        self.index += 1;
    }

    // Gets the next message key by advancing the chain key to produce a new chain key and a
    // corresponding message key
    pub fn next_message_key(&mut self) -> MessageKey {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(MESSAGE_KEY_SEED);
        let bytes: [u8; 32] = mac.finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("SHA256 output should return 32 bytes");
        self.advance();
        MessageKey(bytes)
    }

    // TODO: Seperate Message key
    // fn encrypt_message(&self, plaintext: &str) -> EncryptedMessage {
    //     let message_key = self.get_message_key();
    //     EncryptedMessage::new(plaintext, message_key, self.index, dh_ratchet_key)
    // }
}

impl From<[u8; 32]> for ChainKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            key: bytes,
            index: 0
        }
    }
}
