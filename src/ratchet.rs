use hkdf::Hkdf;
use rand::thread_rng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::chainkey::ChainKey;

const KDF_RK_INFO: &[u8] = b"KDF_RK_INFO";

pub struct PrivateRatchetKey(StaticSecret);
pub struct PublicRatchetKey(PublicKey);
pub struct RootKey([u8; 32]);

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
    // TODO: we should type this
    pub fn advance(&self, public_ratchet_key: PublicRatchetKey) -> ([u8; 32], [u8; 32]) {
        // TODO: probably want separate types for stuff but this is (rootkey, recv_chain_key)
        kdf(
            &self.root_key,
            &self.private_ratchet_key,
            &public_ratchet_key,
        )
    }

    // TODO: advance using chain_key
}

struct ReceivingRatchet {
    public_ratchet_key: PublicRatchetKey,
    root_key: RootKey,
}

// A receiving ratchet take a public ratchet key and then generates a private ratchet key.
// It then performs diffie hellman to generate that can be used for the key derivation function.
// The ratchet can then be a SendingRatchet to send stuff
impl ReceivingRatchet {
    pub fn advance(&self) -> ([u8; 32], [u8; 32], PrivateRatchetKey) {
        let priv_rat_key = PrivateRatchetKey::new();
        let (new_root_key, sending_chain_key) =
            kdf(&self.root_key, &priv_rat_key, &self.public_ratchet_key);
        (new_root_key, sending_chain_key, priv_rat_key)
    }
}

// TODO: we probably want a Enum that alternates between the SendingRatchet and ReceivingRatchet.
// This would be the double ratchet
