use ed25519_dalek::{Keypair, Signature, Signer, PublicKey as PublicSigningKey};
use rand::thread_rng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::session::Session;

pub struct Account {
    signing_key: PrivateIdentityKey,
    diffie_hellman_key: PrivateDHKey,
    one_time_keys: Vec<PrivateDHKey>,
    // XXX: maybe backup key later
}

struct PrivateIdentityKey(Keypair);
#[derive(Clone, Copy)]
pub struct PublicIdentityKey(PublicSigningKey);
struct PrivateDHKey(StaticSecret);
#[derive(Clone, Copy)]
pub struct PublicDHKey(pub(crate) PublicKey);

#[derive(Clone, Copy)]
pub struct PublicSessionKeys {
    identity_key: PublicIdentityKey,
    dh_key: PublicDHKey,
    one_time_key: PublicDHKey,
    pub(crate) eph_key: PublicDHKey,
}

const NUM_ONE_TIME_KEYS: usize = 100;

impl Account {
    pub fn new() -> Self {
        let signing_key = Keypair::generate(&mut thread_rng());
        let diffie_hellman_key = StaticSecret::new(thread_rng());
        let one_time_keys = (0..NUM_ONE_TIME_KEYS)
            .map(|_| PrivateDHKey(StaticSecret::new(thread_rng())))
            .collect();
        Account {
            signing_key: PrivateIdentityKey(signing_key),
            diffie_hellman_key: PrivateDHKey(diffie_hellman_key),
            one_time_keys,
        }
    }

    pub fn sign(&self, message: &str) -> Signature {
        self.signing_key.0.sign(message.as_bytes())
    }

    // TODO: Session should be it's own advance type now
    // Outbound and inbound make different ratchets
    // It would use the DoubleRatchet type we create
    // TODO: However, we need a message storage system to store old messages
    // This is for skipped or out of order messages

    // IK_a <-> OPK_b
    // EPH_a <-> IK_b
    // EPH_a <-> OPK_b
    // Eve intercepts b and gives back malicious OPK_b and IK_b
    // Can they calculate ECDH(IK_a, OPK_b) || ECDH(EPH_a, IK_b) || ECDH(EPH_a, OPK_b)?
    // no because Eve is unable to calculate ECH(EPH_a, IK_b)
    // But if Eve compromises IK_b, then they can decrypt it eventually
    /// create a Session given some other user's diffie_hellman_key and one-time-key
    pub fn create_outbound_session(
        &self,
        dh_key: PublicDHKey,
        one_time_key: PublicDHKey,
    ) -> Session {
        let eph_key = StaticSecret::new(thread_rng());
        let dh1 = self.diffie_hellman_key.0.diffie_hellman(&one_time_key.0);
        let dh2 = eph_key.diffie_hellman(&dh_key.0);
        let dh3 = eph_key.diffie_hellman(&one_time_key.0);
        let shared_secret = merge_secrets(dh1, dh2, dh3);
        let public_session_keys = PublicSessionKeys {
            eph_key: PublicDHKey(PublicKey::from(&eph_key)),
            dh_key,
            one_time_key,
            identity_key: PublicIdentityKey(self.signing_key.0.public),
        };

        Session::new_outbound_session(shared_secret, public_session_keys)
    }

    // create inbound_session
    // needs one-time-key they used from you, their diffie-hellman key, their ephermal key
    // TODO: this should be a message which contains the keys instead
    pub fn create_inbound_session(
        &self,
        used_otk: PublicDHKey,
        dh_key: PublicDHKey,
        eph_key: PublicDHKey,
        identity_key: PublicIdentityKey,
    ) -> Session {
        // TODO: this design is very bad, probably want hashmap for the public key
        let mut public_otks = self.one_time_keys.iter().map(|k| PublicKey::from(&k.0));
        // TODO: check if used_otk is even in your public key
        // TODO: you need to delete the one_time_key LOL
        let idx = public_otks.position(|k| k == used_otk.0).unwrap();
        let otk = &self.one_time_keys[idx];

        let dh1 = otk.0.diffie_hellman(&dh_key.0);
        let dh2 = self.diffie_hellman_key.0.diffie_hellman(&eph_key.0);
        let dh3 = otk.0.diffie_hellman(&eph_key.0);
        let shared_secret = merge_secrets(dh1, dh2, dh3);
        let public_session_keys = PublicSessionKeys {
            eph_key,
            dh_key,
            identity_key,
            one_time_key: used_otk,
        };

        Session::new_inbound_session(shared_secret, public_session_keys)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct X3DHSharedSecret([u8; 96]);

impl X3DHSharedSecret {
    pub fn as_byte_ref(&self) -> &[u8] {
        &self.0
    }
}

fn merge_secrets(secret1: SharedSecret, secret2: SharedSecret, secret3: SharedSecret) -> X3DHSharedSecret {
    // Each secret is 32 bytes, so concatentating them would be 96 bytes
    let mut combined_secret = [0u8; 96];
    combined_secret[0..32].copy_from_slice(secret1.as_bytes());
    combined_secret[32..64].copy_from_slice(secret1.as_bytes());
    combined_secret[64..96].copy_from_slice(secret1.as_bytes());
    X3DHSharedSecret(combined_secret)
}

// TODO: move tests to sessions and then compare sessions
// #[cfg(test)]
// mod test {
//     use super::*;
// 
//     #[test]
//     fn same_secrets() {
//         let alice = Account::new();
//         let bob = Account::new();
// 
//         // alice -> bob
//         let bob_secret_otk = &bob.one_time_keys[0];
//         let bob_public_dhk = PublicDHKey(PublicKey::from(&bob.diffie_hellman_key.0));
//         let bob_public_otk = PublicDHKey(PublicKey::from(&bob_secret_otk.0));
//         let (alice_ss, alice_public_session_keys) =
//             alice.create_outbound_session(bob_public_dhk, bob_public_otk);
// 
//         let alice_public_dhk = PublicDHKey(PublicKey::from(&alice.diffie_hellman_key.0));
//         let bob_ss = bob.create_inbound_session(bob_public_otk, alice_public_dhk, alice_public_session_keys.dh_key);
// 
//         assert_eq!(alice_ss, bob_ss);
//     }
// }
