use crate::error::Result;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn bind(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn send_to(&self, peer: SocketAddr, buf: &[u8]) -> Result<usize> {
        let n = self.socket.send_to(buf, peer)?;
        Ok(n)
    }

    pub fn try_recv_from(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>> {
        match self.socket.recv_from(buf) {
            Ok((n, src)) => Ok(Some((n, src))),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
