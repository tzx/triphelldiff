use crate::account::PublicSessionKeys;
use crate::account::X3DHSharedSecret;
use crate::ratchet::DoubleRatchet;

pub struct Session {
    double_ratchet: DoubleRatchet,
    public_keys: PublicSessionKeys,
    // TODO: skipped messages
}


impl Session {
    pub fn new_outbound_session(shared_secret: X3DHSharedSecret, public_keys: PublicSessionKeys) -> Self {
        let double_ratchet = DoubleRatchet::new_sending_ratchet(shared_secret);
        Self {
            double_ratchet,
            public_keys
        }
    }

    pub fn new_inbound_session(shared_secret: X3DHSharedSecret, public_keys: PublicSessionKeys) -> Self {
        let double_ratchet = DoubleRatchet::new_receiving_ratchet(shared_secret, &public_keys);

        Self {
            double_ratchet,
            public_keys
        }
    }
}
