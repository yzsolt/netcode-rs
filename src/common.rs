use crate::crypto;

/// Unique game/application identifier
pub type ProtocolId = u64;

pub const CONNECT_TOKEN_PRIVATE_BYTES: usize = 1024;

/// Maximum number of server addresses a client can encode into a connection request packet
pub const MAX_SERVERS_PER_CONNECT: usize = 16;

/// Maximum size packet that is sent over the wire.
pub const MAX_PACKET_SIZE: usize = 1200;

/// Maximum size of a payload that can be sent (1175).
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - crypto::MAC_BYTES - 8 - 1;

/// Version string in the connection request packet
pub const VERSION_STRING: &[u8; 13] = b"NETCODE 1.02\0";

pub const CHALLENGE_TOKEN_BYTES: usize = 300;
