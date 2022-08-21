use crate::account::PublicSessionKeys;
use crate::account::X3DHSharedSecret;
use crate::encrypted_message::InitialMessage;
use crate::encrypted_message::Message;
use crate::ratchet::DoubleRatchet;

pub struct Session {
    double_ratchet: DoubleRatchet,
    public_keys: PublicSessionKeys,
    // TODO: skipped messages
}

impl Session {
    pub fn public_keys(&self) -> &PublicSessionKeys {
        &self.public_keys
    }

    pub fn new_outbound_session(
        shared_secret: X3DHSharedSecret,
        public_keys: PublicSessionKeys,
    ) -> Self {
        let double_ratchet = DoubleRatchet::new_sending_ratchet(shared_secret);
        Self {
            double_ratchet,
            public_keys,
        }
    }

    pub fn new_inbound_session(
        shared_secret: X3DHSharedSecret,
        public_keys: PublicSessionKeys,
    ) -> Self {
        let double_ratchet = DoubleRatchet::new_receiving_ratchet(shared_secret, &public_keys);

        Self {
            double_ratchet,
            public_keys,
        }
    }

    pub fn encrypt(&mut self, message: &str) -> Message {
        // TODO: right now this is only initial message
        let encrypted_message = self.double_ratchet.encrypt(message);
        let initial_message = InitialMessage::new(self.public_keys, encrypted_message);
        Message::Initial(initial_message)
    }
}
