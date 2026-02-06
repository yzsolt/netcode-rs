use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::Nonce;
use thiserror::Error;

use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::crypto;
use crate::time::UtcTimestamp;
use crate::{ClientId, common::*};

#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("too many connect addresses encoded")]
    TooManyConnectAddresses,

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    Encrypt(#[from] crypto::EncryptError),
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("private key failed to decrypt auth data")]
    InvalidPrivateKey,

    #[error("unexpected version string")]
    InvalidVersion,

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    Decrypt(#[from] crypto::EncryptError),
}

enum HostAddressType {
    None = 0,
    IpV4 = 1,
    IpV6 = 2,
}

impl TryFrom<u8> for HostAddressType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::IpV4),
            2 => Ok(Self::IpV6),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown IP address type",
            )),
        }
    }
}

const ADDITIONAL_DATA_SIZE: usize = VERSION_STRING.len() + 8 + 8;

/// Nonce for encrypting private connect token data using the `XChaCha20Poly1305` AEAD primitive
pub type ConnectTokenNonce = [u8; 24];

/// Maximal length of `UserData`.
pub const USER_DATA_LEN: usize = 256;

/// User data included in `ConnectToken`
pub type UserData = [u8; USER_DATA_LEN];

/// Token used by clients to connect and authenticate to a netcode `Server`
pub struct ConnectToken {
    /// Protocol ID for messages relayed by netcode.
    pub protocol: u64,
    /// Token creation time
    pub created: UtcTimestamp,
    /// Token expire time
    pub expires: UtcTimestamp,
    /// Nonce for decoding private data.
    pub nonce: ConnectTokenNonce,
    /// Private data encryped with server's private key(separate from client <-> server keys).
    pub private_data: [u8; CONNECT_TOKEN_PRIVATE_BYTES],
    /// List of hosts this token supports connecting to.
    pub hosts: HostList,
    /// Private key for client -> server communcation.
    pub client_to_server_key: Key,
    /// Private key for server -> client communcation.
    pub server_to_client_key: Key,
    /// Time connection should wait before disconnecting
    pub timeout: Duration,
}

impl Clone for ConnectToken {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol,
            created: self.created,
            expires: self.expires,
            nonce: self.nonce,
            private_data: self.private_data,
            hosts: self.hosts.clone(),
            client_to_server_key: self.client_to_server_key,
            server_to_client_key: self.server_to_client_key,
            timeout: self.timeout,
        }
    }
}

/// Private data encapsulated by Connect token.
pub struct PrivateData {
    /// Unique client id, determined by the server.
    pub client_id: ClientId,
    /// Time connection should wait before disconnecting.
    pub timeout: Duration,
    /// Secondary host list to authoritatively determine which hosts clients can connect to.
    pub hosts: HostList,
    /// Private key for client -> server communcation.
    pub client_to_server_key: Key,
    /// Private key for server -> client communcation.
    pub server_to_client_key: Key,
    /// Server-specific user data.
    pub user_data: UserData,
}

#[derive(Clone, Debug)]
pub struct HostList {
    hosts: [Option<SocketAddr>; MAX_SERVERS_PER_CONNECT],
}

fn generate_user_data() -> UserData {
    let mut user_data = [0; USER_DATA_LEN];

    crypto::random_bytes(&mut user_data);

    user_data
}

fn generate_additional_data(
    protocol: u64,
    expires: &UtcTimestamp,
) -> Result<[u8; ADDITIONAL_DATA_SIZE], io::Error> {
    let mut scratch = [0; ADDITIONAL_DATA_SIZE];

    {
        let mut out = io::Cursor::new(&mut scratch[..]);

        out.write_all(VERSION_STRING)?;
        out.write_u64::<LittleEndian>(protocol)?;
        out.write_u64::<LittleEndian>((*expires).into())?;
    }

    Ok(scratch)
}

impl ConnectToken {
    /// Generates a new connection token
    ///
    /// # Arguments
    ///
    /// - `hosts`: List of allowed hosts to connect to in From<String> form.
    /// - `private_key`: Server private key that will be used to authenticate requests.
    /// - `expiration`: How long this token is valid for.
    /// - `timeout`: Time connection should wait before disconnecting.
    /// - `nonce`: Nonce to use. Should be randomly generated for every token.
    /// - `protocol`: Client specific protocol.
    /// - `client_id`: Unique client identifier.
    /// - `user_data`: Client specific userdata.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_with_string<H, I>(
        hosts: H,
        private_key: &Key,
        expiration: Duration,
        timeout: Duration,
        nonce: &ConnectTokenNonce,
        protocol: u64,
        client_id: ClientId,
        user_data: Option<&UserData>,
    ) -> Result<Self, GenerateError>
    where
        H: ExactSizeIterator<Item = I>,
        I: Into<String>,
    {
        if hosts.len() > MAX_SERVERS_PER_CONNECT {
            return Err(GenerateError::TooManyConnectAddresses);
        }

        let host_list = hosts.flat_map(|addr| {
            use std::net::ToSocketAddrs;
            addr.into()
                .to_socket_addrs()
                .unwrap_or_else(|_| vec![].into_iter())
        });

        Self::generate_internal(
            host_list,
            private_key,
            expiration,
            timeout,
            nonce,
            protocol,
            client_id,
            user_data,
        )
    }

    /// Generates a new connection token.
    ///
    /// # Arguments
    ///
    /// - `hosts`: List of allowed hosts to connect to.
    /// - `private_key`: Server private key that will be used to authenticate requests.
    /// - `expiration`: How long this token is valid for.
    /// - `timeout`: Time connection should wait before disconnecting.
    /// - `nonce`: Nonce to use. Should be randomly generated for every token.
    /// - `protocol`: Client specific protocol.
    /// - `client_id`: Unique client identifier.
    /// - `user_data`: Client specific userdata.
    #[allow(clippy::too_many_arguments)]
    pub fn generate<H>(
        hosts: H,
        private_key: &Key,
        expiration: Duration,
        timeout: Duration,
        nonce: &ConnectTokenNonce,
        protocol: u64,
        client_id: ClientId,
        user_data: Option<&UserData>,
    ) -> Result<Self, GenerateError>
    where
        H: ExactSizeIterator<Item = SocketAddr>,
    {
        if hosts.len() > MAX_SERVERS_PER_CONNECT {
            return Err(GenerateError::TooManyConnectAddresses);
        }

        Self::generate_internal(
            hosts,
            private_key,
            expiration,
            timeout,
            nonce,
            protocol,
            client_id,
            user_data,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_internal<H>(
        hosts: H,
        private_key: &Key,
        expiration: Duration,
        timeout: Duration,
        nonce: &ConnectTokenNonce,
        protocol: u64,
        client_id: ClientId,
        user_data: Option<&UserData>,
    ) -> Result<Self, GenerateError>
    where
        H: Iterator<Item = SocketAddr>,
    {
        let now = UtcTimestamp::now();
        let expires = now + expiration;

        let decoded_data = PrivateData::new(client_id, timeout, hosts, user_data);

        let mut private_data = [0; CONNECT_TOKEN_PRIVATE_BYTES];
        decoded_data.encode(&mut private_data, protocol, &expires, nonce, private_key)?;

        Ok(Self {
            protocol,
            nonce: *nonce,
            private_data,
            hosts: decoded_data.hosts.clone(),
            created: now,
            expires,
            client_to_server_key: decoded_data.client_to_server_key,
            server_to_client_key: decoded_data.server_to_client_key,
            timeout,
        })
    }

    /// Decodes the private data stored by this connection token.
    ///
    /// # Arguments
    ///
    /// - `private_key`: Server's private key used to generate this token.
    pub fn decode(&mut self, private_key: &Key) -> Result<PrivateData, DecodeError> {
        PrivateData::decode(
            &self.private_data,
            self.protocol,
            &self.expires,
            &self.nonce,
            private_key,
        )
    }

    /// Encodes a `ConnectToken` into a `io::Write`.
    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error>
    where
        W: io::Write,
    {
        out.write_all(VERSION_STRING)?;
        out.write_u64::<LittleEndian>(self.protocol)?;
        out.write_u64::<LittleEndian>(self.created.into())?;
        out.write_u64::<LittleEndian>(self.expires.into())?;
        out.write_all(&self.nonce)?;
        out.write_all(&self.private_data)?;
        out.write_u32::<LittleEndian>(self.timeout.as_secs() as u32)?;
        self.hosts.write(out)?;
        out.write_all(&self.client_to_server_key)?;
        out.write_all(&self.server_to_client_key)?;

        Ok(())
    }

    /// Decodes a `ConnectToken` from an `io::Read`.
    pub fn read<R>(source: &mut R) -> Result<Self, DecodeError>
    where
        R: io::Read,
    {
        let mut version = [0; VERSION_STRING.len()];
        source.read_exact(&mut version)?;

        if &version != VERSION_STRING {
            return Err(DecodeError::InvalidVersion);
        }

        let protocol = source.read_u64::<LittleEndian>()?;
        let create_utc = source.read_u64::<LittleEndian>()?;
        let expire_utc = source.read_u64::<LittleEndian>()?;

        let mut nonce = ConnectTokenNonce::default();
        source.read_exact(&mut nonce)?;

        let mut private_data = [0; CONNECT_TOKEN_PRIVATE_BYTES];
        source.read_exact(&mut private_data)?;

        let timeout_sec = source.read_u32::<LittleEndian>()?;

        let hosts = HostList::read(source)?;

        let mut client_to_server_key = Key::default();
        source.read_exact(&mut client_to_server_key)?;

        let mut server_to_client_key = Key::default();
        source.read_exact(&mut server_to_client_key)?;

        Ok(Self {
            hosts,
            created: UtcTimestamp::from(create_utc),
            expires: UtcTimestamp::from(expire_utc),
            protocol,
            nonce,
            private_data,
            client_to_server_key,
            server_to_client_key,
            timeout: Duration::from_secs(timeout_sec as u64),
        })
    }
}

impl PrivateData {
    pub fn new<H>(
        client_id: ClientId,
        timeout: Duration,
        hosts: H,
        user_data: Option<&UserData>,
    ) -> Self
    where
        H: Iterator<Item = SocketAddr>,
    {
        let final_user_data = match user_data {
            Some(u) => *u,
            None => generate_user_data(),
        };

        let client_to_server_key = crypto::generate_key();
        let server_to_client_key = crypto::generate_key();

        Self {
            client_id,
            timeout,
            client_to_server_key,
            server_to_client_key,
            hosts: HostList::new(hosts),
            user_data: final_user_data,
        }
    }

    pub fn decode(
        encoded: &[u8; CONNECT_TOKEN_PRIVATE_BYTES],
        protocol_id: u64,
        expires: &UtcTimestamp,
        nonce: &ConnectTokenNonce,
        private_key: &Key,
    ) -> Result<Self, DecodeError> {
        let additional_data = generate_additional_data(protocol_id, expires)?;
        let mut decoded = [0; CONNECT_TOKEN_PRIVATE_BYTES - crypto::MAC_BYTES];

        crypto::decode::<XChaCha20Poly1305>(
            &mut decoded,
            encoded,
            Some(&additional_data),
            Nonce::<XChaCha20Poly1305>::from_slice(nonce),
            private_key,
        )?;

        Ok(Self::read(&mut io::Cursor::new(&decoded[..]))?)
    }

    pub fn encode(
        &self,
        out: &mut [u8; CONNECT_TOKEN_PRIVATE_BYTES],
        protocol_id: u64,
        expiration: &UtcTimestamp,
        nonce: &ConnectTokenNonce,
        private_key: &Key,
    ) -> Result<(), GenerateError> {
        let additional_data = generate_additional_data(protocol_id, expiration)?;
        let mut scratch = [0; CONNECT_TOKEN_PRIVATE_BYTES - crypto::MAC_BYTES];

        self.write(&mut io::Cursor::new(&mut scratch[..]))?;

        crypto::encode::<XChaCha20Poly1305>(
            &mut out[..],
            &scratch,
            Some(&additional_data),
            Nonce::<XChaCha20Poly1305>::from_slice(nonce),
            private_key,
        )?;

        Ok(())
    }

    fn write<W>(&self, out: &mut W) -> Result<(), io::Error>
    where
        W: io::Write,
    {
        out.write_u64::<LittleEndian>(self.client_id)?;
        out.write_u32::<LittleEndian>(self.timeout.as_secs() as u32)?;

        self.hosts.write(out)?;
        out.write_all(&self.client_to_server_key)?;
        out.write_all(&self.server_to_client_key)?;

        out.write_all(&self.user_data)?;

        Ok(())
    }

    fn read<R>(source: &mut R) -> Result<Self, io::Error>
    where
        R: io::Read,
    {
        let client_id = source.read_u64::<LittleEndian>()?;
        let timeout_sec = source.read_u32::<LittleEndian>()?;

        let hosts = HostList::read(source)?;

        let mut client_to_server_key = Key::default();
        source.read_exact(&mut client_to_server_key)?;

        let mut server_to_client_key = Key::default();
        source.read_exact(&mut server_to_client_key)?;

        let mut user_data = [0; USER_DATA_LEN];
        source.read_exact(&mut user_data)?;

        Ok(Self {
            hosts,
            client_id,
            timeout: Duration::from_secs(timeout_sec as u64),
            client_to_server_key,
            server_to_client_key,
            user_data,
        })
    }
}

impl HostList {
    pub fn new<I>(hosts: I) -> Self
    where
        I: Iterator<Item = SocketAddr>,
    {
        let mut final_hosts = [None; MAX_SERVERS_PER_CONNECT];

        for (i, host) in hosts.enumerate().take(MAX_SERVERS_PER_CONNECT) {
            final_hosts[i] = Some(host);
        }

        Self { hosts: final_hosts }
    }

    pub fn read<R>(source: &mut R) -> Result<Self, io::Error>
    where
        R: io::Read,
    {
        let host_count = source.read_u32::<LittleEndian>()?;
        let mut hosts = [None; MAX_SERVERS_PER_CONNECT];

        for host in hosts.iter_mut().take(host_count as usize) {
            let host_type = HostAddressType::try_from(source.read_u8()?)?;
            match host_type {
                HostAddressType::IpV4 => {
                    let ip = source.read_u32::<BigEndian>()?;
                    let port = source.read_u16::<LittleEndian>()?;

                    *host = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
                }
                HostAddressType::IpV6 => {
                    let mut ip = [0; 16];
                    source.read_exact(&mut ip)?;
                    let port = source.read_u16::<LittleEndian>()?;

                    *host = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
                }
                HostAddressType::None => {} // Skip blanks
            }
        }

        Ok(Self { hosts })
    }

    pub fn iter(&self) -> HostIterator<'_> {
        HostIterator {
            hosts: self,
            idx: 0,
        }
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error>
    where
        W: io::Write,
    {
        out.write_u32::<LittleEndian>(self.iter().len() as u32)?;
        for host in self.iter() {
            match host {
                SocketAddr::V4(addr) => {
                    out.write_u8(HostAddressType::IpV4 as u8)?;
                    let ip = addr.ip().octets();

                    for i in ip.iter().take(4) {
                        out.write_u8(*i)?;
                    }
                }
                SocketAddr::V6(addr) => {
                    out.write_u8(HostAddressType::IpV6 as u8)?;
                    let ip = addr.ip().octets();

                    for i in ip.iter().take(16) {
                        out.write_u8(*i)?;
                    }
                }
            }
            out.write_u16::<LittleEndian>(host.port())?;
        }

        Ok(())
    }
}

impl PartialEq for HostList {
    fn eq(&self, other: &Self) -> bool {
        self.hosts == other.hosts
    }
}

/// Iterator for hosts held by a `ConnectToken`
pub struct HostIterator<'a> {
    hosts: &'a HostList,
    idx: usize,
}

impl<'a> Iterator for HostIterator<'a> {
    type Item = &'a SocketAddr;

    fn next(&mut self) -> Option<&'a SocketAddr> {
        if self.idx > self.hosts.hosts.len() {
            return None;
        }

        let idx = self.idx;
        self.idx += 1;

        self.hosts.hosts[idx].as_ref()
    }
}

impl<'a> ExactSizeIterator for HostIterator<'a> {
    fn len(&self) -> usize {
        if self.hosts.hosts[0].is_none() {
            return 0;
        }

        match self.hosts.hosts.iter().position(|h| h.is_none()) {
            Some(idx) => idx,
            None => self.hosts.hosts.len(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const CONNECT_TOKEN_BYTES: usize = 2048;

    #[test]
    fn read_write() {
        let mut private_key = Key::default();
        crypto::random_bytes(&mut private_key);

        let mut user_data = [0; USER_DATA_LEN];
        crypto::random_bytes(&mut user_data);

        let expire = Duration::from_secs(30);
        let timeout = Duration::from_secs(15);

        let mut nonce = ConnectTokenNonce::default();
        crypto::random_bytes(&mut nonce);

        let protocol = 0x112233445566;
        let client_id = 0x665544332211;

        let token = ConnectToken::generate_with_string(
            ["127.0.0.1:8080"].iter().cloned(),
            &private_key,
            expire,
            timeout,
            &nonce,
            protocol,
            client_id,
            Some(&user_data),
        )
        .unwrap();

        let mut scratch = [0; CONNECT_TOKEN_BYTES];
        token.write(&mut io::Cursor::new(&mut scratch[..])).unwrap();

        let read = ConnectToken::read(&mut io::Cursor::new(&scratch[..])).unwrap();

        assert_eq!(read.hosts, token.hosts);
        for i in 0..read.private_data.len() {
            assert_eq!(
                read.private_data[i], token.private_data[i],
                "Mismatch at index {}",
                i
            );
        }
        assert_eq!(read.expires, token.expires);
        assert_eq!(read.created, token.created);
        assert_eq!(read.nonce, token.nonce);
        assert_eq!(read.protocol, token.protocol);
        assert_eq!(read.timeout, token.timeout);
    }

    #[test]
    fn decode() {
        let mut private_key = Key::default();
        crypto::random_bytes(&mut private_key);

        let mut user_data = [0; USER_DATA_LEN];
        crypto::random_bytes(&mut user_data);

        let expire = Duration::from_secs(30);
        let timeout = Duration::from_secs(15);

        let mut nonce = ConnectTokenNonce::default();
        crypto::random_bytes(&mut nonce);

        let protocol = 0x112233445566;
        let client_id = 0x665544332211;

        let mut token = ConnectToken::generate_with_string(
            ["127.0.0.1:8080"].iter().cloned(),
            &private_key,
            expire,
            timeout,
            &nonce,
            protocol,
            client_id,
            Some(&user_data),
        )
        .unwrap();

        let decoded = token.decode(&private_key).unwrap();

        assert_eq!(decoded.hosts, token.hosts);
        assert_eq!(decoded.client_id, client_id);
        assert_eq!(decoded.client_to_server_key, token.client_to_server_key);
        assert_eq!(decoded.server_to_client_key, token.server_to_client_key);
        assert_eq!(decoded.user_data, user_data);
    }
}
