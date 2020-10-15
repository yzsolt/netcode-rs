use crate::crypto;

/// Key for the `ChaCha20Poly1305` and `XChaCha20Poly1305` AEAD algorithms used for encryption
pub type Key = [u8; 32];

pub const NETCODE_CONNECT_TOKEN_PRIVATE_BYTES: usize = 1024;

pub const NETCODE_MAX_SERVERS_PER_CONNECT: usize = 16;

/// Maximum size packet that is sent over the wire.
pub const NETCODE_MAX_PACKET_SIZE: usize = 1200;
/// Maximum size of a payload that can be sent(1175).
pub const NETCODE_MAX_PAYLOAD_SIZE: usize =
    NETCODE_MAX_PACKET_SIZE - crypto::NETCODE_ENCRYPT_EXTA_BYTES - 8 - 1;

pub const NETCODE_VERSION_LEN: usize = 13;
pub const NETCODE_VERSION_STRING: &[u8; NETCODE_VERSION_LEN] = b"NETCODE 1.02\0";
pub const NETCODE_CHALLENGE_TOKEN_BYTES: usize = 300;
