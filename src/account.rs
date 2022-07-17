use ed25519_dalek::{Keypair, Signer, Signature};
use rand::thread_rng;
use x25519_dalek::{StaticSecret, EphemeralSecret, PublicKey, SharedSecret};

pub struct Account {
    signing_key: Keypair,
    diffie_hellman_key: StaticSecret,
    one_time_keys: Vec<EphemeralSecret>,
    // XXX: maybe backup key later
} 

const NUM_ONE_TIME_KEYS: usize = 100;

impl Account {
    pub fn new() -> Self {
        let signing_key = Keypair::generate(&mut thread_rng());
        let diffie_hellman_key = StaticSecret::new(thread_rng());
        let one_time_keys = (0..100).map(|_| EphemeralSecret::new(thread_rng())).collect();

        Account {
            signing_key,
            diffie_hellman_key,
            one_time_keys,
        }
    }

    pub fn sign(&self, message: &str) -> Signature {
        self.signing_key.sign(message.as_bytes())
    }
    
    // IK_a <-> OPK_b
    // EPH_a <-> IK_b
    // EPH_a <-> OPK_b
    // Eve intercepts b and gives back malicious OPK_b and IK_b
    // Can they calculate ECDH(IK_a, OPK_b) || ECDH(EPH_a, IK_b) || ECDH(EPH_a, OPK_b)?
    // no because Eve is unable to calculate ECH(EPH_a, IK_b)
    // But if Eve compromises IK_b, then they can decrypt it eventually
    /// create a Session given some other user's diffie_hellman_key and one-time-key
    pub fn create_outbound_session(&self, dh_key: PublicKey, one_time_key: PublicKey) -> [u8; 96] {
        let eph_key = StaticSecret::new(thread_rng());
        let dh1 = self.diffie_hellman_key.diffie_hellman(&one_time_key);
        let dh2 = eph_key.diffie_hellman(&dh_key);
        let dh3 = eph_key.diffie_hellman(&one_time_key);
        merge_secrets(dh1, dh2, dh3)
    }
}

fn merge_secrets(secret1: SharedSecret, secret2: SharedSecret, secret3: SharedSecret) -> [u8; 96] {
    // Each secret is 32 bytes, so concatentating them would be 96 bytes
    let mut combined_secret = [0u8; 96];
    combined_secret[0..32].copy_from_slice(secret1.as_bytes());
    combined_secret[32..64].copy_from_slice(secret1.as_bytes());
    combined_secret[64..96].copy_from_slice(secret1.as_bytes());
    combined_secret
}
