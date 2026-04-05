// SOCKS5 listener: handshake and CONNECT parsing.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Target address types per RFC 1928.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetAddr {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Domain(String),
}

/// Parsed SOCKS5 CONNECT request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    pub target_addr: TargetAddr,
    pub target_port: u16,
}

/// Errors that can occur during SOCKS5 handshake.
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),

    #[error("no acceptable authentication method")]
    NoAcceptableMethod,

    #[error("unsupported SOCKS command: {0:#04x}")]
    UnsupportedCommand(u8),

    #[error("invalid address type: {0:#04x}")]
    InvalidAddressType(u8),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const NO_ACCEPTABLE_METHOD: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Perform the SOCKS5 handshake on a stream, returning the parsed CONNECT request.
///
/// Implements the method negotiation and CONNECT request phases of RFC 1928.
/// Only NO AUTHENTICATION REQUIRED (0x00) is supported.
/// Only the CONNECT command (0x01) is supported.
pub async fn socks5_handshake<S>(stream: &mut S) -> Result<ConnectRequest, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- Method selection phase ---
    // Client: VER(1) | NMETHODS(1) | METHODS(NMETHODS)
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(SocksError::UnsupportedVersion(ver));
    }

    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&NO_AUTH) {
        // Server: VER(1) | METHOD(1) — accept NO AUTH
        stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await?;
    } else {
        // Server: VER(1) | METHOD(1) — reject
        stream.write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_METHOD]).await?;
        return Err(SocksError::NoAcceptableMethod);
    }

    // --- CONNECT request phase ---
    // Client: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2)
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(SocksError::UnsupportedVersion(ver));
    }

    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved byte

    if cmd != CMD_CONNECT {
        // Reply with command not supported (0x07)
        let atyp = stream.read_u8().await?;
        // Drain the rest of the request to be well-behaved
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4 + 2];
                stream.read_exact(&mut buf).await?;
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut buf = vec![0u8; len + 2];
                stream.read_exact(&mut buf).await?;
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16 + 2];
                stream.read_exact(&mut buf).await?;
            }
            _ => {}
        }
        socks5_reply(stream, 0x07).await?;
        return Err(SocksError::UnsupportedCommand(cmd));
    }

    let atyp = stream.read_u8().await?;
    let target_addr = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            TargetAddr::Ipv4(addr)
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain"))?;
            TargetAddr::Domain(domain)
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            TargetAddr::Ipv6(addr)
        }
        _ => return Err(SocksError::InvalidAddressType(atyp)),
    };

    let target_port = stream.read_u16().await?;

    Ok(ConnectRequest {
        target_addr,
        target_port,
    })
}

/// Send a SOCKS5 reply on the stream.
///
/// Sends: VER(0x05) | REP(reply_code) | RSV(0x00) | ATYP(0x01) | BND.ADDR(0.0.0.0) | BND.PORT(0)
pub async fn socks5_reply<S>(stream: &mut S, reply_code: u8) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    let reply = [
        SOCKS5_VERSION, // VER
        reply_code,     // REP
        0x00,           // RSV
        ATYP_IPV4,      // ATYP = IPv4
        0, 0, 0, 0,     // BND.ADDR = 0.0.0.0
        0, 0,           // BND.PORT = 0
    ];
    stream.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Build a valid SOCKS5 method selection + CONNECT request byte sequence.
    fn build_socks5_connect(atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        // Method selection: VER | NMETHODS | METHODS
        buf.push(SOCKS5_VERSION);
        buf.push(1); // 1 method
        buf.push(NO_AUTH);
        // CONNECT request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        buf.push(SOCKS5_VERSION);
        buf.push(CMD_CONNECT);
        buf.push(0x00); // RSV
        buf.push(atyp);
        buf.extend_from_slice(addr);
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    #[tokio::test]
    async fn test_handshake_ipv4() {
        let (mut client, mut server) = duplex(1024);
        let input = build_socks5_connect(ATYP_IPV4, &[127, 0, 0, 1], 80);

        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncWriteExt, AsyncReadExt};
            client.write_all(&input).await.unwrap();
            // Read method selection reply (2 bytes)
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, NO_AUTH]);
        });

        let req = socks5_handshake(&mut server).await.unwrap();
        assert_eq!(req.target_addr, TargetAddr::Ipv4([127, 0, 0, 1]));
        assert_eq!(req.target_port, 80);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_ipv6() {
        let (mut client, mut server) = duplex(1024);
        let addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1
        let input = build_socks5_connect(ATYP_IPV6, &addr, 443);

        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncWriteExt, AsyncReadExt};
            client.write_all(&input).await.unwrap();
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, NO_AUTH]);
        });

        let req = socks5_handshake(&mut server).await.unwrap();
        assert_eq!(req.target_addr, TargetAddr::Ipv6(addr));
        assert_eq!(req.target_port, 443);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_domain() {
        let (mut client, mut server) = duplex(1024);
        let domain = b"example.com";
        let mut addr = Vec::new();
        addr.push(domain.len() as u8);
        addr.extend_from_slice(domain);
        let input = build_socks5_connect(ATYP_DOMAIN, &addr, 8080);

        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncWriteExt, AsyncReadExt};
            client.write_all(&input).await.unwrap();
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, NO_AUTH]);
        });

        let req = socks5_handshake(&mut server).await.unwrap();
        assert_eq!(req.target_addr, TargetAddr::Domain("example.com".into()));
        assert_eq!(req.target_port, 8080);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_unsupported_version() {
        let (mut client, mut server) = duplex(1024);
        // Send SOCKS4 version byte
        let input = vec![0x04, 1, NO_AUTH];

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&input).await.unwrap();
        });

        let err = socks5_handshake(&mut server).await.unwrap_err();
        assert!(matches!(err, SocksError::UnsupportedVersion(0x04)));
    }

    #[tokio::test]
    async fn test_no_acceptable_method() {
        let (mut client, mut server) = duplex(1024);
        // Offer only username/password (0x02), no NO_AUTH
        let input = vec![SOCKS5_VERSION, 1, 0x02];

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&input).await.unwrap();
            // Read the rejection reply
            let mut reply = [0u8; 2];
            use tokio::io::AsyncReadExt;
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, NO_ACCEPTABLE_METHOD]);
        });

        let err = socks5_handshake(&mut server).await.unwrap_err();
        assert!(matches!(err, SocksError::NoAcceptableMethod));
    }

    #[tokio::test]
    async fn test_non_connect_command_rejected() {
        let (mut client, mut server) = duplex(1024);
        let mut input = Vec::new();
        // Method selection
        input.push(SOCKS5_VERSION);
        input.push(1);
        input.push(NO_AUTH);
        // Request with BIND command (0x02)
        input.push(SOCKS5_VERSION);
        input.push(0x02); // BIND
        input.push(0x00); // RSV
        input.push(ATYP_IPV4);
        input.extend_from_slice(&[127, 0, 0, 1]);
        input.extend_from_slice(&80u16.to_be_bytes());

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&input).await.unwrap();
            // Read method selection reply + command not supported reply
            let mut reply = [0u8; 12]; // 2 (method) + 10 (reply)
            use tokio::io::AsyncReadExt;
            client.read_exact(&mut reply).await.unwrap();
            // Method reply
            assert_eq!(reply[0], SOCKS5_VERSION);
            assert_eq!(reply[1], NO_AUTH);
            // Command not supported reply
            assert_eq!(reply[2], SOCKS5_VERSION); // VER
            assert_eq!(reply[3], 0x07);           // REP = command not supported
        });

        let err = socks5_handshake(&mut server).await.unwrap_err();
        assert!(matches!(err, SocksError::UnsupportedCommand(0x02)));
    }

    #[tokio::test]
    async fn test_socks5_reply_success() {
        let (mut client, mut server) = duplex(1024);

        tokio::spawn(async move {
            socks5_reply(&mut server, 0x00).await.unwrap();
        });

        let mut buf = [0u8; 10];
        use tokio::io::AsyncReadExt;
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], SOCKS5_VERSION);
        assert_eq!(buf[1], 0x00); // success
        assert_eq!(buf[2], 0x00); // RSV
        assert_eq!(buf[3], ATYP_IPV4);
        assert_eq!(&buf[4..8], &[0, 0, 0, 0]); // BND.ADDR
        assert_eq!(&buf[8..10], &[0, 0]);       // BND.PORT
    }

    #[tokio::test]
    async fn test_socks5_reply_error() {
        let (mut client, mut server) = duplex(1024);

        tokio::spawn(async move {
            socks5_reply(&mut server, 0x05).await.unwrap(); // connection refused
        });

        let mut buf = [0u8; 10];
        use tokio::io::AsyncReadExt;
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[1], 0x05); // connection refused
    }
}
