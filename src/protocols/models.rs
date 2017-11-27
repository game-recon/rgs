extern crate rgs_models as models;
extern crate serde_json;
extern crate std;

use errors;

use std::str::FromStr;

use std::sync::Arc;

pub type Config = serde_json::Map<String, serde_json::Value>;

#[derive(Clone, Debug)]
pub struct Packet {
    pub addr: std::net::SocketAddr,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringAddr {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    A(std::net::SocketAddr),
    S(StringAddr),
}

#[derive(Clone, Debug)]
pub struct Query {
    pub protocol: TProtocol,
    pub addr: Host,
}

impl PartialEq for Query {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && Arc::ptr_eq(&self.protocol, &other.protocol)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParseResult {
    pub servers: Vec<models::Server>,
    pub follow_up: Vec<Query>,
}

pub trait Protocol: std::fmt::Debug + Send + Sync {
    fn make_request(&self) -> Vec<u8>;
    fn parse_response(&self, p: &Packet) -> errors::Result<ParseResult>;
}

pub type TProtocol = Arc<Protocol>;
pub type ProtocolConfig = std::collections::HashMap<String, TProtocol>;
