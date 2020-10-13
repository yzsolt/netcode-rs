use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

// TODO: fix this
#[cfg_attr(feature = "cargo-clippy", allow(stutter))]
pub trait SocketProvider<I, S> {
    fn new_state() -> S;
    fn bind(addr: &SocketAddr, state: &mut S) -> Result<I, io::Error>;
    fn local_addr(&self) -> Result<SocketAddr, io::Error>;
    fn set_recv_timeout(&mut self, duration: Option<Duration>) -> Result<(), io::Error>;
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error>;
    fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<usize, io::Error>;
}

impl SocketProvider<UdpSocket, ()> for UdpSocket {
    fn new_state() -> () {
        ()
    }

    fn bind(addr: &SocketAddr, _state: &mut ()) -> Result<Self, io::Error> {
        let socket = Self::bind(addr)?;
        socket.set_nonblocking(true)?;

        Ok(socket)
    }

    fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        Self::local_addr(self)
    }

    fn set_recv_timeout(&mut self, duration: Option<Duration>) -> Result<(), io::Error> {
        match duration {
            Some(duration) => {
                self.set_read_timeout(Some(duration))?;
                self.set_nonblocking(false)
            }
            None => self.set_nonblocking(true),
        }
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        Self::recv_from(self, buf)
    }

    fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<usize, io::Error> {
        Self::send_to(self, buf, addr)
    }
}
