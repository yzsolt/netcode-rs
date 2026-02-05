use std::io;

use crate::packet;

/// Errors from [`crate::server::Server::next_event`] and [`crate::client::Client::next_event`].
#[derive(Debug)]
pub enum UpdateError {
    /// Packet buffer was too small to recieve the largest packet ([`crate::MAX_PAYLOAD_SIZE`])
    PacketBufferTooSmall,
    /// An error happened when receiving a packet
    RecvError(RecvError),
    /// An error when sending (usually challenge response)
    SendError(SendError),
    /// An internal error occurred
    Internal(InternalError),
}

/// Errors internal to netcode
#[derive(Debug)]
pub enum InternalError {
    ChallengeEncodeError(packet::ChallengeEncodeError),
}

/// Errors from sending packets
#[derive(Debug)]
pub enum SendError {
    /// Client ID used for sending didn't exist
    InvalidClientId,
    /// Failed to encode the packet for sending
    PacketEncodeError(packet::PacketError),
    /// Packet is larger than [`crate::MAX_PAYLOAD_SIZE`] or equals zero
    PacketSize,
    /// Generic IO error
    SocketError(io::Error),
    /// Client/server is disconnected and cannot send packets
    Disconnected,
}

/// Errors from receiving packets
#[derive(Debug)]
pub enum RecvError {
    /// Failed to decode packet
    PacketDecodeError(packet::PacketError),
    /// We've already received this packet before
    DuplicateSequence,
    /// IO error occured on the socket
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
