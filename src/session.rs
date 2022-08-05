use crate::ratchet::DoubleRatchet;

struct Session {
    double_ratchet: DoubleRatchet,
    public_keys: PublicSessionKeys,
}


