use crate::error::Result;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};

pub struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl UdpTransport {
    pub fn bind(bind_addr: SocketAddr, peer: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(peer)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, peer })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        let n = self.socket.send(buf)?;
        Ok(n)
    }

    pub fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self.socket.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
