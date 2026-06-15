use crate::error::{Error, Result};
use std::io::ErrorKind;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use tun::AbstractDevice;

pub trait Device: Send {
    fn name(&self) -> &str;
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>>;
    fn write(&self, buf: &[u8]) -> Result<usize>;
}

pub struct TunDevice {
    inner: tun::Device,
    name: String,
}

impl TunDevice {
    pub fn create(name: &str) -> Result<Self> {
        let mut config = tun::Configuration::default();
        config.tun_name(name);
        let inner = tun::create(&config)?;
        inner.set_nonblock()?;
        let actual_name = inner.tun_name()?;
        Ok(Self {
            inner,
            name: actual_name,
        })
    }
}

impl Device for TunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self.inner.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let n = self.inner.send(buf)?;
        Ok(n)
    }
}

pub struct LoopbackDevice {
    name: String,
    to_kernel: Sender<Vec<u8>>,
    from_kernel: Receiver<Vec<u8>>,
}

impl LoopbackDevice {
    pub fn new(name: &str) -> (LoopbackDevice, LoopbackDevice) {
        let (a_to_b, b_from_a) = mpsc::channel();
        let (b_to_a, a_from_b) = mpsc::channel();
        let kernel = Self {
            name: name.to_string(),
            to_kernel: a_to_b,
            from_kernel: a_from_b,
        };
        let user = Self {
            name: format!("{name}-user"),
            to_kernel: b_to_a,
            from_kernel: b_from_a,
        };
        (kernel, user)
    }

    pub fn try_recv_raw(&self) -> Option<Vec<u8>> {
        match self.from_kernel.try_recv() {
            Ok(pkt) => Some(pkt),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }

    pub fn send_raw(&self, pkt: Vec<u8>) -> Result<()> {
        self.to_kernel
            .send(pkt)
            .map_err(|_| Error::NotReady)?;
        Ok(())
    }
}

impl Device for LoopbackDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self.from_kernel.try_recv() {
            Ok(pkt) => {
                if pkt.len() > buf.len() {
                    return Err(Error::BufferTooSmall {
                        needed: pkt.len(),
                        actual: buf.len(),
                    });
                }
                buf[..pkt.len()].copy_from_slice(&pkt);
                Ok(Some(pkt.len()))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Ok(None),
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.to_kernel
            .send(buf.to_vec())
            .map_err(|_| Error::NotReady)?;
        Ok(buf.len())
    }
}
