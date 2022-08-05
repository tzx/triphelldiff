use crate::{ratchet::DoubleRatchet, account::PublicSessionKeys};

struct Session {
    double_ratchet: DoubleRatchet,
    public_keys: PublicSessionKeys,
}
