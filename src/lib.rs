//!
//! Asynchronous utilities for querying game servers.
//!
//! The `rgs` crate provides tools to asynchronously retrieve game server information like
//! IP, server metadata, player list and more.

extern crate byteorder;
#[macro_use]
extern crate enum_primitive_derive;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate handlebars;
extern crate iso_country;
extern crate log;
extern crate num_traits;
extern crate rand;
extern crate resolve;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_dns;
extern crate tokio_timer;

use protocols::models;

use errors::Error;
use futures::channel::mpsc::Sender;
use futures::prelude::*;
use models::Server;
use pmodels::TProtocol;
use protocols::models as pmodels;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio_core::net::UdpSocket;

pub mod dns;
#[macro_use]
pub mod errors;
#[macro_use]
pub mod util;
pub mod protocols;

#[derive(Clone, Debug)]
pub struct ServerEntry {
    protocol: pmodels::TProtocol,
    data: Server,
}

impl std::hash::Hash for ServerEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.addr.hash(state)
    }
}

impl PartialEq for ServerEntry {
    fn eq(&self, other: &ServerEntry) -> bool {
        self.data.addr == other.data.addr
    }
}

impl Eq for ServerEntry {}

impl ServerEntry {
    pub fn new(protocol: pmodels::TProtocol, data: models::Server) -> ServerEntry {
        ServerEntry {
            protocol: protocol,
            data: data,
        }
    }

    pub fn into_inner(self) -> (pmodels::TProtocol, models::Server) {
        (self.protocol, self.data)
    }
}

type ProtocolMapping = Arc<Mutex<HashMap<SocketAddr, pmodels::TProtocol>>>;

pub enum FullParseResult {
    FollowUp(pmodels::Query),
    Output(ServerEntry),
    Error(Error),
}

pub struct ParseMuxer {
    results_stream: Option<Box<Stream<Item = FullParseResult, Error = Error>>>,
}

impl ParseMuxer {
    pub fn new() -> Self {
        Self {
            results_stream: Some(Box::new(futures::stream::iter_ok(vec![]))),
        }
    }
}

impl Sink for ParseMuxer {
    type SinkItem = IncomingPacket;
    type SinkError = Error;

    fn poll_ready(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }

    fn start_send(&mut self, item: Self::SinkItem) -> Result<(), Self::SinkError> {
        let (protocol, pkt) = item.into();

        let mut results_stream = self.results_stream.take().unwrap();
        results_stream = Box::new(
            results_stream.chain(
                pmodels::Protocol::parse_response(&**protocol, pkt)
                    .map(move |v| match v {
                        pmodels::ParseResult::FollowUp(q) => {
                            FullParseResult::FollowUp((q, TProtocol::clone(&protocol)).into())
                        }
                        pmodels::ParseResult::Output(s) => FullParseResult::Output(ServerEntry {
                            protocol: protocol.clone(),
                            data: s,
                        }),
                    })
                    .or_else(|e| Ok(FullParseResult::Error(e))),
            ),
        );
        self.results_stream = Some(results_stream);

        Ok(())
    }

    fn poll_flush(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }

    fn poll_close(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl Stream for ParseMuxer {
    type Item = FullParseResult;
    type Error = Error;

    fn poll_next(&mut self, cx: &mut task::Context) -> Poll<Option<Self::Item>, Self::Error> {
        self.results_stream.as_mut().unwrap().poll_next(cx)
    }
}

pub struct IncomingPacket {
    pub addr: SocketAddr,
    pub protocol: pmodels::TProtocol,
    pub data: Vec<u8>,
}

impl From<IncomingPacket> for (pmodels::TProtocol, pmodels::Packet) {
    fn from(v: IncomingPacket) -> Self {
        (
            v.protocol,
            pmodels::Packet {
                addr: v.addr,
                data: v.data,
            },
        )
    }
}

pub struct UdpQueryCodec {
    pub protocol_mapping: ProtocolMapping,
    pub dns_history: dns::History,
}

impl tokio_core::net::UdpCodec for UdpQueryCodec {
    type In = IncomingPacket;
    type Out = dns::ResolvedQuery;

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        let protocol = self.protocol_mapping
            .lock()
            .unwrap()
            .get(addr)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Could not determine server's protocol",
                )
            })?
            .clone();
        Ok(IncomingPacket {
            protocol,
            addr: *addr,
            data: buf.into(),
        })
    }

    fn encode(&mut self, v: Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        let mut data = v.protocol.make_request(v.state);
        println!("{} {:?}", v.addr, &data);
        self.protocol_mapping
            .lock()
            .unwrap()
            .insert(v.addr.clone(), v.protocol);
        into.append(&mut data);
        v.addr
    }
}

/// Represents a single request by user to query the servers fed into sink.
pub struct UdpQuery {
    query_to_dns: Box<Future<Item = (), Error = Error>>,
    dns_to_socket: Box<Future<Item = (), Error = Error>>,
    socket_to_parser: Box<Future<Item = (), Error = Error>>,

    parser_stream: Box<Stream<Item = FullParseResult, Error = Error>>,
    input_sink: Sender<pmodels::Query>,
    follow_up_sink: Sender<pmodels::Query>,
}

impl UdpQuery {
    fn new(
        dns_resolver: Arc<tokio_dns::Resolver + Send + Sync + 'static>,
        socket: UdpSocket,
    ) -> Self {
        let protocol_mapping = ProtocolMapping::default();
        let dns_history = dns::History::default();

        let (socket_sink, socket_stream) = socket
            .framed(UdpQueryCodec {
                protocol_mapping: protocol_mapping.clone(),
                dns_history: dns_history.clone(),
            })
            .split();

        let socket_sink = socket_sink.sink_map_err(|e| errors::Error::IOError {
            reason: format!("socket_sink error: {}", std::error::Error::description(&e)),
        });
        let socket_stream = socket_stream.map_err(|e| errors::Error::IOError {
            reason: format!(
                "socket_stream error: {}",
                std::error::Error::description(&e)
            ),
        });

        let (query_sink, query_stream) = futures::channel::mpsc::channel::<pmodels::Query>(1);
        let query_stream = Box::new(query_stream.map_err(|_| Error::NetworkError {
            reason: "Query stream returned an error".into(),
        }));

        let (input_sink, follow_up_sink) = (query_sink.clone(), query_sink.clone());

        let parser = ParseMuxer::new();
        let dns_resolver = dns::Resolver::new(dns_resolver, dns_history.clone());

        let (parser_sink, parser_stream) = parser.split();
        let parser_stream = Box::new(parser_stream);
        let (dns_resolver_sink, dns_resolver_stream) = dns_resolver.split();

        // Outgoing pipe: Query Stream -> DNS Resolver -> UDP Socket
        let query_to_dns = Box::new(dns_resolver_sink.send_all(query_stream).map(|_| ()));
        let dns_to_socket = Box::new(socket_sink.send_all(dns_resolver_stream).map(|_| ()));

        // Incoming pipe: UDP Socket -> Parser
        let socket_to_parser = Box::new(parser_sink.send_all(socket_stream).map(|_| ()));

        Self {
            query_to_dns,
            dns_to_socket,
            socket_to_parser,

            parser_stream,
            input_sink,
            follow_up_sink,
        }
    }
}

impl Sink for UdpQuery {
    type SinkItem = pmodels::UserQuery;
    type SinkError = Error;

    fn poll_ready(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(self.input_sink.poll_ready(cx)?)
    }

    fn start_send(&mut self, item: Self::SinkItem) -> Result<(), Self::SinkError> {
        Ok(self.input_sink.start_send(item.into())?)
    }

    fn poll_flush(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(self.input_sink.poll_flush(cx)?)
    }

    fn poll_close(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(self.input_sink.poll_close(cx)?)
    }
}

impl Stream for UdpQuery {
    type Item = ServerEntry;
    type Error = Error;

    fn poll_next(&mut self, cx: &mut task::Context) -> Poll<Option<Self::Item>, Self::Error> {
        self.query_to_dns.poll(cx)?;
        self.dns_to_socket.poll(cx)?;
        self.socket_to_parser.poll(cx)?;

        if let Async::Ready(v) = self.parser_stream.poll_next(cx)? {
            match v {
                Some(data) => match data {
                    FullParseResult::FollowUp(s) => {
                        self.follow_up_sink.try_send(s).unwrap();
                    }
                    FullParseResult::Output(s) => {
                        return Ok(Async::Ready(Some(s)));
                    }
                    FullParseResult::Error(e) => {
                        eprintln!("Parser returned error: {:?}", e);
                    }
                },
                None => {
                    return Ok(Async::Pending);
                }
            }
        }

        Ok(Async::Pending)
    }
}

/// It can be used to spawn multiple UdpQueries.
pub struct UdpQueryBuilder {
    dns_resolver: Arc<tokio_dns::Resolver + Send + Sync + 'static>,
}

impl Default for UdpQueryBuilder {
    fn default() -> Self {
        Self {
            dns_resolver: Arc::new(tokio_dns::CpuPoolResolver::new(8))
                as Arc<tokio_dns::Resolver + Send + Sync + 'static>,
        }
    }
}

impl UdpQueryBuilder {
    pub fn with_dns_resolver(
        mut self,
        resolver: Arc<tokio_dns::Resolver + Send + Sync + 'static>,
    ) -> Self {
        self.dns_resolver = resolver;
        self
    }

    pub fn make_query(&self, socket: UdpSocket) -> UdpQuery {
        UdpQuery::new(Arc::clone(&self.dns_resolver), socket)
    }
}
