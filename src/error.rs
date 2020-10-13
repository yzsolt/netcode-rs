use std::io;

use crate::packet;

/// Errors from calls to `next_event`().
#[derive(Debug)]
// TODO: rename these
#[cfg_attr(feature = "cargo-clippy", allow(stutter))]
pub enum UpdateError {
    /// Packet buffer was too small to recieve the largest packet(`NETCODE_MAX_PAYLOAD_LEN` = 1775)
    PacketBufferTooSmall,
    /// An error happened when receiving a packet.
    RecvError(RecvError),
    /// An error when sending(usually challenge response)
    SendError(SendError),
    /// An internal error occurred
    Internal(InternalError),
}

#[derive(Debug)]
/// Errors internal to netcode.
// TODO: rename this
#[cfg_attr(feature = "cargo-clippy", allow(stutter))]
pub enum InternalError {
    ChallengeEncodeError(packet::ChallengeEncodeError),
}

/// Errors from sending packets
#[derive(Debug)]
// TODO: fix me
#[cfg_attr(feature = "cargo-clippy", allow(stutter))]
pub enum SendError {
    /// Client Id used for sending didn't exist.
    InvalidClientId,
    /// Failed to encode the packet for sending.
    PacketEncodeError(packet::PacketError),
    /// Packet is larger than [PACKET_MAX_PAYLOAD_SIZE](constant.NETCODE_MAX_PAYLOAD_SIZE.html) or equals zero.
    PacketSize,
    /// Generic io error.
    SocketError(io::Error),
    /// Client/Server is disconnected and cannot send packets
    Disconnected,
}

/// Errors from receiving packets
#[derive(Debug)]
// TODO: rename this
#[cfg_attr(feature = "cargo-clippy", allow(stutter))]
pub enum RecvError {
    /// Failed to decode packet.
    PacketDecodeError(packet::PacketError),
    /// We've already received this packet before.
    DuplicateSequence,
    /// IO error occured on the socket.
    SocketError(io::Error),
}

impl From<packet::PacketError> for RecvError {
    fn from(err: packet::PacketError) -> Self {
        RecvError::PacketDecodeError(err)
    }
}

impl From<RecvError> for UpdateError {
    fn from(err: RecvError) -> Self {
        UpdateError::RecvError(err)
    }
}

impl From<packet::ChallengeEncodeError> for UpdateError {
    fn from(err: packet::ChallengeEncodeError) -> Self {
        UpdateError::Internal(InternalError::ChallengeEncodeError(err))
    }
}

impl From<SendError> for UpdateError {
    fn from(err: SendError) -> Self {
        UpdateError::SendError(err)
    }
}

impl From<packet::PacketError> for SendError {
    fn from(err: packet::PacketError) -> Self {
        SendError::PacketEncodeError(err)
    }
}

impl From<io::Error> for SendError {
    fn from(err: io::Error) -> Self {
        SendError::SocketError(err)
    }
}

impl From<io::Error> for RecvError {
    fn from(err: io::Error) -> Self {
        RecvError::SocketError(err)
    }
}
