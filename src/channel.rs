use crate::common::*;
use crate::error::*;
use crate::packet::{self, KeepAlivePacket, Packet};
use crate::replay::ReplayProtection;
use crate::socket::SocketProvider;

use log::*;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

pub const TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_RETRY: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct KeepAliveState {
    pub last_sent: Instant,
    pub last_response: Instant,
}

impl KeepAliveState {
    pub fn new(current_time: Instant) -> Self {
        Self {
            last_sent: current_time,
            last_response: current_time,
        }
    }

    pub fn update_sent(&mut self, time: Instant) {
        self.last_sent = time;
    }

    pub fn update_response(&mut self, response: Instant) {
        self.last_response = response;
    }

    pub fn has_expired(&self, time: Instant) -> bool {
        self.last_response + TIMEOUT < time
    }

    pub fn should_send_keepalive(&self, time: Instant) -> bool {
        self.last_sent + KEEPALIVE_RETRY < time
    }
}

#[derive(Clone)]
pub struct Channel {
    keep_alive: KeepAliveState,
    send_key: Key,
    recv_key: Key,
    replay_protection: ReplayProtection,
    next_sequence: u64,
    addr: SocketAddr,
    protocol_id: u64,
    client_idx: u32,
    max_clients: u32,
}

pub enum UpdateResult {
    Noop,
    SentKeepAlive,
    Expired,
}

impl Channel {
    pub fn new(
        send_key: &Key,
        recv_key: &Key,
        addr: &SocketAddr,
        protocol_id: u64,
        client_idx: u32,
        max_clients: u32,
        time: Instant,
    ) -> Self {
        Self {
            keep_alive: KeepAliveState::new(time),
            send_key: *send_key,
            recv_key: *recv_key,
            replay_protection: ReplayProtection::new(),
            next_sequence: 0,
            addr: *addr,
            protocol_id,
            client_idx,
            max_clients,
        }
    }

    pub fn send<I>(
        &mut self,
        current_time: Instant,
        packet: &Packet,
        payload: Option<&[u8]>,
        socket: &mut I,
    ) -> Result<usize, SendError>
    where
        I: SocketProvider<I>,
    {
        let mut scratch = [0; MAX_PACKET_SIZE];
        let len = packet::encode(
            &mut scratch,
            self.protocol_id,
            packet,
            Some((self.next_sequence, &self.send_key)),
            payload,
        )?;

        socket.send_to(&scratch[..len], &self.addr)?;

        self.next_sequence += 1;
        self.keep_alive.update_sent(current_time);

        Ok(len)
    }

    pub fn recv(
        &mut self,
        current_time: Instant,
        packet: &[u8],
        out_payload: &mut [u8; MAX_PAYLOAD_SIZE],
    ) -> Result<Packet, RecvError> {
        let (seq, packet) =
            packet::decode(packet, self.protocol_id, Some(&self.recv_key), out_payload)?;

        match packet {
            Packet::KeepAlive(_) | Packet::Payload(_) | Packet::Disconnect => {
                if self.replay_protection.packet_already_received(seq) {
                    return Err(RecvError::DuplicateSequence);
                }

                self.replay_protection.advance_sequence(seq);
            }
            _ => {}
        }

        self.keep_alive.update_response(current_time);

        Ok(packet)
    }

    pub fn send_keep_alive<I>(
        &mut self,
        current_time: Instant,
        socket: &mut I,
    ) -> Result<usize, SendError>
    where
        I: SocketProvider<I>,
    {
        let keep_alive = KeepAlivePacket {
            client_idx: self.client_idx,
            max_clients: self.max_clients,
        };

        self.send(current_time, &Packet::KeepAlive(keep_alive), None, socket)
    }

    pub fn update<I>(
        &mut self,
        current_time: Instant,
        socket: &mut I,
        send_keep_alive: bool,
    ) -> Result<UpdateResult, SendError>
    where
        I: SocketProvider<I>,
    {
        if self.keep_alive.should_send_keepalive(current_time) {
            if send_keep_alive {
                trace!("Sending keep alive");
                self.send_keep_alive(current_time, socket)?;
            }

            return Ok(UpdateResult::SentKeepAlive);
        }

        if self.keep_alive.has_expired(current_time) {
            return Ok(UpdateResult::Expired);
        }

        Ok(UpdateResult::Noop)
    }

    pub fn get_addr(&self) -> &SocketAddr {
        &self.addr
    }
}
