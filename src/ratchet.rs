// TODO: this needs types

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{StaticSecret, PublicKey};


const KDF_RK_INFO: &[u8] = b"KDF_RK_INFO";

struct PrivateRatchetKey(StaticSecret);
struct RootKey([u8; 32]);

pub struct SendingRatchet {
    private_ratchet_key: PrivateRatchetKey,
    root_key: RootKey,
}

impl SendingRatchet {
    // Advances ratchet and returns new keys the new root key and the receving chain key
    // TODO: we should type this
    pub fn advance(&self, public_ratchet_key: PublicKey) -> ([u8; 32], [u8; 32]) {
        let dh_output = self.private_ratchet_key.0.diffie_hellman(&public_ratchet_key);
        let hkdf = Hkdf::<Sha256>::new(Some(&self.root_key.0), dh_output.as_bytes());
        let mut okm = [0u8; 64];
        hkdf.expand(KDF_RK_INFO, &mut okm).expect("64 should be valid length");
        let mut new_root_key = [0u8; 32];
        new_root_key.copy_from_slice(&okm[0..32]);
        let mut recv_chain_key = [0u8; 32];
        recv_chain_key.copy_from_slice(&okm[32..64]);
        
        (new_root_key, recv_chain_key)
    }
}

struct ReceivingRatchet {
}
