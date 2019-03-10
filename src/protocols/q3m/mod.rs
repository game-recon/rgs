use crate::errors::Error;
use crate::models::{
    FollowUpQuery, FollowUpQueryProtocol, Packet, ParseResult, Protocol, ProtocolResultStream,
    TProtocol,
};

use failure::format_err;
use futures;
use futures::prelude::*;
use q3a;
use q3a::MasterQueryExtra::*;
use serde_json::Value;
use std::net::SocketAddr;

#[derive(Clone, Debug, Default)]
pub struct ProtocolImpl {
    pub q3s_protocol: Option<TProtocol>,
    pub request_tag: Option<String>,
    pub version: u32,
}

impl Protocol for ProtocolImpl {
    /// Creates a request packet. Can accept an optional state if there is any.
    fn make_request(&self, _: Option<Value>) -> Vec<u8> {
        let mut out = Vec::new();
        q3a::Packet::GetServers(q3a::GetServersData {
            request_tag: self.request_tag.clone(),
            version: self.version,
            extra: vec![Empty, Full].into_iter().collect(),
        })
        .write_bytes(&mut out)
        .unwrap();
        out
    }
    /// Create a stream of parsed values out of incoming response.
    fn parse_response(&self, p: Packet) -> ProtocolResultStream {
        Box::pin(
            futures::stream::iter(
                match q3a::Packet::from_bytes(p.data.as_slice().into())
                    .map_err(|e| format_err!("{}", e))
                    .and_then(|(_, pkt)| match pkt {
                        q3a::Packet::GetServersResponse(data) => {
                            Ok(match self.q3s_protocol.clone() {
                                Some(q3s_protocol) => data
                                    .data
                                    .into_iter()
                                    .map(|addr| {
                                        ParseResult::FollowUp(FollowUpQuery {
                                            host: SocketAddr::V4(addr).into(),
                                            state: None,
                                            protocol: FollowUpQueryProtocol::Child(
                                                q3s_protocol.clone(),
                                            ),
                                        })
                                    })
                                    .collect(),
                                None => vec![],
                            })
                        }
                        other => Err(format_err!("Wrong packet type: {:?}", other.get_type())
                            .context(Error::DataParseError)
                            .into()),
                    }) {
                    Ok(servers) => servers.into_iter().map(Ok).collect(),
                    Err(e) => vec![Err(e)],
                },
            )
            .map_err({
                let p = p.clone();
                move |e| (Some(p.clone()), e)
            }),
        )
    }
}
