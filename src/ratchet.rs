use hkdf::Hkdf;
use rand::thread_rng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{chainkey::{ChainKey, MessageKey}, account::X3DHSharedSecret};

const KDF_RK_INFO: &[u8] = b"KDF_RK_INFO";

pub struct PrivateRatchetKey(StaticSecret);
pub struct PublicRatchetKey(PublicKey);
pub struct RootKey(pub [u8; 32]);

impl PrivateRatchetKey {
    fn new() -> Self {
        PrivateRatchetKey(StaticSecret::new(thread_rng()))
    }
}
// Uses kdf to get 64 bytes, splits them into two 32 byte keys: new_root_key, new_chain_key
fn kdf(
    root_key: &RootKey,
    priv_key: &PrivateRatchetKey,
    pub_key: &PublicRatchetKey,
) -> ([u8; 32], [u8; 32]) {
    let dh_output = priv_key.0.diffie_hellman(&pub_key.0);
    let hkdf = Hkdf::<Sha256>::new(Some(&root_key.0), dh_output.as_bytes());
    let mut okm = [0u8; 64];
    hkdf.expand(KDF_RK_INFO, &mut okm)
        .expect("64 should be valid length");

    let mut new_root_key = [0u8; 32];
    new_root_key.copy_from_slice(&okm[0..32]);
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&okm[32..64]);

    (new_root_key, chain_key)
}

pub struct SendingRatchet {
    private_ratchet_key: PrivateRatchetKey,
    root_key: RootKey,
    chain_key: ChainKey,
}

impl SendingRatchet {
    // Advances ratchet and returns new keys the new root key and the receving chain key
    pub fn advance(&self, public_ratchet_key: PublicRatchetKey) -> (RootKey, ChainKey) {
        let (rk_bytes, ck_bytes) = kdf(
            &self.root_key,
            &self.private_ratchet_key,
            &public_ratchet_key,
        );
        (RootKey(rk_bytes), ck_bytes.into())
    }

    // This advance the chain key
    fn next_message_key(&mut self) -> MessageKey {
        self.chain_key.next_message_key()
    }
}

pub struct ReceivingRatchet {
    public_ratchet_key: PublicRatchetKey,
    root_key: RootKey,
}

// A receiving ratchet take a public ratchet key and then generates a private ratchet key.
// It then performs diffie hellman to generate that can be used for the key derivation function.
// The ratchet can then be a SendingRatchet to send stuff
impl ReceivingRatchet {
    pub fn advance(&self) -> (RootKey, ChainKey, PrivateRatchetKey) {
        let priv_rat_key = PrivateRatchetKey::new();
        let (new_root_key, sending_chain_key) =
            kdf(&self.root_key, &priv_rat_key, &self.public_ratchet_key);
        (RootKey(new_root_key), sending_chain_key.into(), priv_rat_key)
    }
}

enum DoubleRatchetState {
    Sending(SendingRatchet),
    Receiving(ReceivingRatchet),
}

pub struct DoubleRatchet {
    inner: DoubleRatchetState
}

impl DoubleRatchet {
    pub fn new_sending_ratchet(shared_secret: X3DHSharedSecret) -> Self {
        // Shared Secret needs to be put into a kdf to output the root key and chain key
        // Signal docs says SK should be salt? Idk
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_byte_ref());
        let mut okm = [0u8; 64];
        hkdf.expand(b"NEW_INBOUND_SESSION", &mut okm);

        let mut root_key_bytes = [0u8; 32];
        let mut chain_key_bytes = [0u8; 32];
        root_key_bytes.copy_from_slice(&okm[..32]);
        chain_key_bytes.copy_from_slice(&okm[32..64]);
        let root_key =  RootKey(root_key_bytes);
        let chain_key = ChainKey::from(chain_key_bytes);
        let ratchet = SendingRatchet {
            private_ratchet_key: PrivateRatchetKey::new(),
            root_key,
            chain_key
        };
        Self {
            inner: DoubleRatchetState::Sending(ratchet)
        }
    }
}
