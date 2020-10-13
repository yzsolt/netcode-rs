use crate::crypto;

pub const NETCODE_KEY_BYTES: usize = 32;
pub const NETCODE_MAC_BYTES: usize = 16;
/// Maximum size of userdata included in `ConnectToken`.
pub const NETCODE_USER_DATA_BYTES: usize = 256;
pub const NETCODE_CONNECT_TOKEN_PRIVATE_BYTES: usize = 1024;

pub const NETCODE_TIMEOUT_SECONDS: i32 = 15;

pub const NETCODE_MAX_SERVERS_PER_CONNECT: usize = 16;

/// Maximum size packet that is sent over the wire.
pub const NETCODE_MAX_PACKET_SIZE: usize = 1200;
/// Maximum size of a payload that can be sent(1175).
pub const NETCODE_MAX_PAYLOAD_SIZE: usize =
    NETCODE_MAX_PACKET_SIZE - crypto::NETCODE_ENCRYPT_EXTA_BYTES - 8 - 1;

pub const NETCODE_VERSION_LEN: usize = 13;
pub const NETCODE_VERSION_STRING: &[u8; NETCODE_VERSION_LEN] = b"NETCODE 1.01\0";
pub const NETCODE_CHALLENGE_TOKEN_BYTES: usize = 300;

#[cfg(test)]
pub mod test {
    use std::sync::Mutex;

    lazy_static! {
        pub static ref FFI_LOCK: Mutex<()> = Mutex::new(());
    }
}
