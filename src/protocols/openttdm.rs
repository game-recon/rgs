use errors;
use errors::Error;
use models;
use util;
use util::*;

use byteorder::{LittleEndian, NetworkEndian};
use futures;
use futures::prelude::*;
use num_traits::FromPrimitive;
use protocols::models as pmodels;
use serde_json;
use serde_json::Value;
use std;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Source: https://git.openttd.org/?p=trunk.git;a=blob;f=src/network/core/udp.h;hb=HEAD#l41
#[derive(Clone, Debug, PartialEq, Primitive)]
enum IPVer {
    V4 = 1,
    V6 = 2,
}

#[derive(Clone, Debug, PartialEq, Primitive)]
enum PktType {
    PacketUdpClientFindServer = 0,
    PacketUdpServerResponse = 1,
    PacketUdpClientDetailInfo = 2,
    PacketUdpServerDetailInfo = 3,
    PacketUdpServerRegister = 4,
    PacketUdpMasterAckRegister = 5,
    PacketUdpClientGetList = 6,
    PacketUdpMasterResponseList = 7,
    PacketUdpServerUnregister = 8,
    PacketUdpClientGetNewgrfs = 9,
    PacketUdpServerNewgrfs = 10,
    PacketUdpMasterSessionKey = 11,
    PacketUdpEnd = 12,
}

#[derive(Clone, Debug, Default)]
struct IPv4Parser {
    host_buf: VecDeque<u8>,
    port_buf: VecDeque<u8>,
}

impl IPv4Parser {
    fn host_buf_full(&self) -> bool {
        self.host_buf.len() >= 4
    }

    fn port_buf_full(&self) -> bool {
        self.port_buf.len() >= 2
    }
}

impl Sink for IPv4Parser {
    type SinkItem = u8;
    type SinkError = Error;

    fn poll_ready(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        if self.host_buf_full() && self.port_buf_full() {
            Ok(Async::Pending)
        } else {
            Ok(Async::Ready(()))
        }
    }

    fn start_send(&mut self, item: Self::SinkItem) -> Result<(), Self::SinkError> {
        if !self.host_buf_full() {
            self.host_buf.push_back(item);
            Ok(())
        } else {
            if !self.port_buf_full() {
                self.port_buf.push_back(item);
                Ok(())
            } else {
                unreachable!()
            }
        }
    }

    fn poll_flush(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }

    fn poll_close(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl Stream for IPv4Parser {
    type Item = SocketAddrV4;
    type Error = Error;

    fn poll_next(&mut self, cx: &mut task::Context) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.host_buf_full() || !self.port_buf_full() {
            Ok(Async::NotReady)
        } else {
            let ip = Ipv4Addr::new(
                self.host_buf.pop_front().unwrap(),
                self.host_buf.pop_front().unwrap(),
                self.host_buf.pop_front().unwrap(),
                self.host_buf.pop_front().unwrap(),
            );
            let port = util::to_u16::<LittleEndian>(&[
                self.port_buf.pop_front().unwrap(),
                self.port_buf.pop_front().unwrap(),
            ]);

            let addr = SocketAddrV4::new(ip, port);
            Ok(Async::Ready(Some(addr)))
        }
    }
}

struct DataParser {
    buf: VecDeque<u8>,
    hosts_left: u16,
    chunk_size: u8,
    byte_sink: Box<Sink<SinkItem = u8, SinkError = Error>>,
    inner_stream: Box<Stream<Item = SocketAddr, Error = Error>>,
}

impl DataParser {
    fn next(&mut self) -> Result<u8, Error> {
        self.buf
            .pop_front()
            .ok_or_else(|| Error::InvalidPacketError {
                reason: "Unexpected EOF".into(),
            })
    }
}

impl DataParser {
    fn new<T: Into<VecDeque<u8>>>(buf: T) -> Result<Self, Error> {
        let mut buf = buf.into();
        let hosts_left: u16;
        let chunk_size: u8;
        let byte_sink: Box<Sink<SinkItem = u8, SinkError = Error>>;
        let inner_stream: Box<Stream<Item = SocketAddr, Error = Error>>;
        {
            let mut next = || {
                buf.pop_front().ok_or_else(|| Error::InvalidPacketError {
                    reason: "Unexpected EOF".into(),
                })
            };

            let len = util::to_u16::<LittleEndian>(&[next()?, next()?]);

            {
                let num = next()?;
                let t = PktType::from_u8(num).ok_or_else(|| Error::InvalidPacketError {
                    reason: format!("Unknown packet type: {}", num),
                })?;

                if t != PktType::PacketUdpMasterResponseList {
                    return Err(Error::InvalidPacketError {
                        reason: format!("Invalid packet type: {:?}", t),
                    });
                }
            }

            let ip_ver = IPVer::from_u8(next()?).ok_or(Error::InvalidPacketError {
                reason: "Unknown IP type".into(),
            })?;

            hosts_left = util::to_u16::<LittleEndian>(&[next()?, next()?]);

            let (a, b, c): (
                Box<Stream<Item = SocketAddr, Error = Error>>,
                Box<Sink<SinkItem = u8, SinkError = Error>>,
                u8,
            ) = match ip_ver {
                IPVer::V4 => {
                    let (byte_sink, inner_stream) =
                        IPv4Parser::default().map(SocketAddr::V4).split();
                    let chunk_size = 6;
                    (Box::new(inner_stream), Box::new(byte_sink), chunk_size)
                }
                IPVer::V6 => (
                    Box::new(futures::stream::empty()),
                    Box::new(Vec::new().sink_map_err(|_| unreachable!())),
                    18,
                ),
            };
            inner_stream = a;
            byte_sink = b;
            chunk_size = c;
        }

        Ok(Self {
            buf,
            hosts_left,
            chunk_size,
            byte_sink,
            inner_stream,
        })
    }
}

impl Stream for DataParser {
    type Item = SocketAddr;
    type Error = Error;

    fn poll_next(&mut self, cx: &mut task::Context) -> Poll<Option<Self::Item>, Self::Error> {
        if self.hosts_left == 0 {
            Ok(Async::Ready(None))
        } else {
            for _ in 0..self.chunk_size {
                let b = self.next()?;
                self.byte_sink.start_send(b)?;
            }

            self.hosts_left -= 1;

            self.inner_stream.poll()
        }
    }
}

#[derive(Debug)]
pub struct Protocol {
    pub child: Option<pmodels::TProtocol>,
}

impl pmodels::Protocol for Protocol {
    fn make_request(&self, _state: Option<Value>) -> Vec<u8> {
        vec![5, 0, 6, 2, 2]
    }

    fn parse_response(
        &self,
        p: pmodels::Packet,
    ) -> Box<Stream<Item = pmodels::ParseResult, Error = Error>> {
        if let Some(child) = self.child.clone() {
            match DataParser::new(p.data) {
                Ok(parser) => Box::new(parser.map(move |addr| {
                    pmodels::ParseResult::FollowUp(pmodels::FollowUpQuery {
                        host: pmodels::Host::A(addr),
                        protocol: pmodels::FollowUpQueryProtocol::Child(child.clone()),
                        state: None,
                    })
                })),
                Err(e) => Box::new(futures::stream::iter_result(vec![Err(e)])),
            }
        } else {
            Box::new(futures::stream::iter_ok(vec![]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::str::FromStr;

    fn fixtures() -> (Vec<u8>, Vec<SocketAddr>) {
        let data = vec![
            0x42, 0x00, 0x07, 0x01, 0x0A, 0x00, 0x4A, 0xD0, 0x4B, 0xB7, 0x8B, 0x0F, 0xAC, 0xF9,
            0xB0, 0x91, 0x8B, 0x0F, 0x53, 0xC7, 0x18, 0x16, 0x8B, 0x0F, 0x3E, 0x8F, 0x2E, 0x44,
            0x8B, 0x0F, 0x79, 0x2A, 0xA0, 0x97, 0x3E, 0x0F, 0x5C, 0xDE, 0x6E, 0x7C, 0x8B, 0x0F,
            0x6C, 0x34, 0xE4, 0x4C, 0x8B, 0x0F, 0xB2, 0xEB, 0xB2, 0x57, 0x8B, 0x0F, 0x80, 0x48,
            0x4A, 0x71, 0x8B, 0x0F, 0x40, 0x8A, 0xE7, 0x36, 0x8B, 0x0F, 0x42, 0x00, 0x07, 0x01,
            0x01, 0x00, 0x4A, 0xD0, 0x4B, 0xB7, 0x8C, 0x0F,
        ];
        let srv_list = vec![
            "74.208.75.183:3979",
            "172.249.176.145:3979",
            "83.199.24.22:3979",
            "62.143.46.68:3979",
            "121.42.160.151:3902",
            "92.222.110.124:3979",
            "108.52.228.76:3979",
            "178.235.178.87:3979",
            "128.72.74.113:3979",
            "64.138.231.54:3979",
        ].into_iter()
            .map(|s| SocketAddr::from_str(s).unwrap())
            .collect::<Vec<SocketAddr>>();

        (data, srv_list)
    }

    #[test]
    fn test_p_parse_response() {
        let (data, srv_list) = fixtures();

        assert_eq!(
            DataParser::new(data)
                .unwrap()
                .inspect(|addr| println!("{}", addr))
                .collect()
                .wait()
                .unwrap(),
            srv_list
        )
    }
}
