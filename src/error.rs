use std::io;

use thiserror::Error;

use crate::packet;

/// Errors from [`crate::server::Server::next_event`] and [`crate::client::Client::next_event`]
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error(transparent)]
    RecvError(#[from] RecvError),

    #[error(transparent)]
    SendError(#[from] SendError),

    #[error(transparent)]
    ChallengeEncodeError(#[from] packet::ChallengeEncodeError),
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("client ID doesn't exist")]
    InvalidClientId,

    #[error("packet is too large or empty")]
    InvalidPacketSize,

    #[error("client/server is disconnected, can't send packets")]
    Disconnected,

    #[error(transparent)]
    PacketEncodeError(#[from] packet::PacketError),

    #[error(transparent)]
    SocketError(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum RecvError {
    #[error("packet was already received (replay attack mitigated)")]
    DuplicateSequence,

    #[error(transparent)]
    PacketDecodeError(#[from] packet::PacketError),

    #[error(transparent)]
    SocketError(#[from] io::Error),
}
