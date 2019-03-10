use crate::errors::Error;
use crate::models::*;

use failure::{format_err, Fallible};
use futures::prelude::*;
use openttd;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::collections::HashSet;
use std::net::SocketAddr;

const MASTER_VERSION: u8 = 2;

fn parse_data(buf: &[u8]) -> Fallible<(openttd::ServerListType, HashSet<SocketAddr>)> {
    let p = openttd::Packet::from_incoming_bytes(buf)
        .map_err(|e| format_err!("Nom failure while parsing: {}", e))?
        .1;

    match p {
        openttd::Packet::MasterResponseList(data) => Ok(match data {
            openttd::ServerList::IPv4(set) => (
                openttd::ServerListType::IPv4,
                set.into_iter().map(SocketAddr::V4).collect::<_>(),
            ),
            openttd::ServerList::IPv6(set) => (
                openttd::ServerListType::IPv6,
                set.into_iter().map(SocketAddr::V6).collect::<_>(),
            ),
        }),
        _ => Err(format_err!("invalid packet type: {:?}", p.pkt_type())
            .context(Error::DataParseError)
            .into()),
    }
}

#[derive(Debug)]
pub struct ProtocolImpl {
    pub child: Option<TProtocol>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum State {
    IPv4Polled,
}

impl Protocol for ProtocolImpl {
    fn make_request(&self, state: Option<Value>) -> Vec<u8> {
        if state.is_some() {
            openttd::Packet::ClientGetList(openttd::ClientGetListData {
                master_server_version: MASTER_VERSION,
                request_type: openttd::ServerListType::IPv6,
            })
        } else {
            openttd::Packet::ClientGetList(openttd::ClientGetListData {
                master_server_version: MASTER_VERSION,
                request_type: openttd::ServerListType::IPv4,
            })
        }
        .to_bytes()
        .unwrap()
    }

    fn parse_response(&self, pkt: Packet) -> ProtocolResultStream {
        if let Some(child) = self.child.clone() {
            Box::pin(futures::stream::iter(match parse_data(&pkt.data) {
                Err(e) => vec![Err((Some(pkt), e))],
                Ok((server_type, data)) => match server_type {
                    openttd::ServerListType::IPv4 => {
                        vec![Ok(ParseResult::FollowUp(FollowUpQuery {
                            host: Host::A(pkt.addr),
                            protocol: FollowUpQueryProtocol::This,
                            state: Some(serde_json::to_value(State::IPv4Polled).unwrap()),
                        }))]
                    }
                    _ => vec![],
                }
                .into_iter()
                .chain(data.into_iter().map(move |addr| {
                    Ok(ParseResult::FollowUp(FollowUpQuery {
                        host: Host::A(addr),
                        protocol: FollowUpQueryProtocol::Child(child.clone()),
                        state: None,
                    }))
                }))
                .collect::<Vec<_>>(),
            }))
        } else {
            Box::pin(stream::empty())
        }
    }
}
