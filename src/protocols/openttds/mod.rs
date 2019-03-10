use crate::errors::Error;
use crate::models::*;

use failure::{format_err, Fallible};
use futures::prelude::*;
//use parking_lot::Mutex;
use serde_json::Value;
use std::net::SocketAddr;
//use tokio::prelude::*;

fn write_v2_data(srv: &mut Server, v: openttd::V2Data) {
    srv.rules
        .insert("max-companies".into(), v.max_companies.into());
    srv.rules
        .insert("current-companies".into(), v.current_companies.into());
    srv.rules
        .insert("max-spectators".into(), v.max_spectators.into());
}

fn write_v3_data(srv: &mut Server, v: openttd::V3Data) {
    srv.rules
        .insert("current-time".into(), v.game_date.timestamp().into());
    srv.rules
        .insert("start-time".into(), v.start_date.timestamp().into());
}

fn write_v4_data(srv: &mut Server, v: openttd::V4Data) {
    srv.rules.insert(
        "active-newgrf".into(),
        Value::Object(
            v.active_newgrf
                .into_iter()
                .map(|(id, hash)| (id.to_string(), hash.to_string().into()))
                .collect(),
        ),
    );
}

fn parse_server(addr: SocketAddr, info: openttd::ServerResponse) -> Fallible<Server> {
    let mut srv = Server::new(addr);
    srv.status = Status::Up;

    srv.name = Some(String::from_utf8_lossy(&info.server_name.into_bytes()).into_owned());
    srv.need_pass = Some(info.use_password);
    srv.map = Some(String::from_utf8_lossy(&info.map_name.into_bytes()).into_owned());
    srv.num_clients = Some(u64::from(info.clients_on));
    srv.max_clients = Some(u64::from(info.clients_max));

    srv.rules.insert(
        "protocol-version".into(),
        u8::from(&info.protocol_ver).into(),
    );

    match info.protocol_ver {
        openttd::ProtocolVer::V1 => {}
        openttd::ProtocolVer::V2(v2) => {
            write_v2_data(&mut srv, v2);
        }
        openttd::ProtocolVer::V3(v2, v3) => {
            write_v2_data(&mut srv, v2);
            write_v3_data(&mut srv, v3);
        }
        openttd::ProtocolVer::V4(v2, v3, v4) => {
            write_v2_data(&mut srv, v2);
            write_v3_data(&mut srv, v3);
            write_v4_data(&mut srv, v4);
        }
    }

    srv.rules.insert(
        "server-version".into(),
        info.server_revision.into_string()?.into(),
    );
    srv.rules
        .insert("language-id".into(), info.server_lang.into());
    srv.rules
        .insert("current-spectators".into(), info.spectators_on.into());
    srv.rules.insert("map-set".into(), info.map_set.into());
    srv.rules.insert("dedicated".into(), info.dedicated.into());

    Ok(srv)
}

fn parse_data(addr: SocketAddr, buf: &[u8]) -> Fallible<Server> {
    let p = openttd::Packet::from_incoming_bytes(buf)
        .map_err(|e| format_err!("{}", e))?
        .1;

    match p {
        openttd::Packet::ServerResponse(info) => parse_server(addr, info),
        _ => Err(format_err!("invalid packet type: {:?}", p.pkt_type())),
    }
}

#[derive(Debug)]
pub struct ProtocolImpl;

impl Protocol for ProtocolImpl {
    fn make_request(&self, _state: Option<Value>) -> Vec<u8> {
        openttd::Packet::ClientFindServer.to_bytes().unwrap()
    }

    fn parse_response(&self, pkt: Packet) -> ProtocolResultStream {
        Box::pin(vec![parse_data(pkt.addr, &pkt.data)
            .map(ParseResult::Output)
            .map_err(|e| (Some(pkt), e.context(Error::DataParseError).into()))])
    }
}

/*
struct SocketMultiplexerControl {
    pub incoming: HashMap<SocketAddr, VecDeque<Vec<u8>>>,
    pub outgoing: HashMap<SocketAddr, VecDeque<Vec<u8>>>,
}

struct SocketMultiplexerTask<S> {
    pub socket: S,
    pub control: Arc<Mutex<OneshotMultiplexerControl>>,
}

impl<
        S: Sink<SinkItem = (SocketAddr, Vec<u8>), SinkError = failure::Error>
            + Stream<Item = (SocketAddr, Vec<u8>), Error = failure::Error>,
    > Future for OneshotMultiplexerTask<S>
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.socket.poll().map(|a| match a {
            Async::Ready(Some((addr, data))) => {
                if let Some(sender) = self.control.lock().mapping.remove(&addr) {
                    sender.send(data);
                    Ok(Async::NotReady)
                }
            }
            Async::Ready(None) => Ok(Async::Ready(())),
            Async::NotReady => Ok(Async::NotReady),
        })
    }
}

struct SocketMultiplexer {
    pub task_close_handle: futures::sync::mpsc::Sender<()>,

}

impl<S> SocketMultiplexer<S> {
    pub fn connect(&self, addr: SocketAddr) {}
}

/// Transforms provided byte stream into byte stream for resolved address
async fn query<D, F, IN, OUT>(
    host: Host,
    resolver: D,
    incoming_factory: F,
    outgoing: OUT,
) -> Fallible<Server>
where
    D: crate::dns::Resolver,
    OUT: Sink<(SocketAddr, Vec<u8>), SinkError = failure::Error> + 'static,
    IN: Stream<Item = Vec<u8>, Error = failure::Error>,
    F: FnOnce(SocketAddr) -> IN + 'static,
{
    let addr = await!(resolver.resolve(host))?;

    let incoming = (incoming_factory)(addr);

    await!(outgoing.send((addr, ProtocolImpl.make_request(None))))?;

    let msg = await!(incoming.into_future())
        .map_err(|(e, _)| e)
        .map(|(msg, _)| msg)?
        .ok_or_else(|| format_err!("Connection hung up"))?;

    parse_data(addr, &msg)
}

pub struct Querier {
    pub sink: Box<dyn Sink<SinkItem = (SocketAddr, Vec<u8>), SinkError = failure::Error> + 'static>,
}

impl Querier {}

pub enum HostState {
    New,
    Querying,
    Sent,
    Finished,
}

pub struct Querier {
    byte_sink: Box<dyn Sink<SinkItem = Vec<u8>, SinkError = failure::Error>>,
    byte_stream: Box<dyn Stream<Item = Vec<u8>, Error = failure::Error>>,
    host_state: HashMap<Host, HostState>,
    ready: VecDeque<Server>,
}

impl Sink for Querier {
    type SinkItem = Host;
    type SinkError = failure::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.host_state.insert(item, HostState::New);
        task::current().notify();
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl Stream for Querier {
    type Item = VecDeque<Server>;
    type Error = failure::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.ready.is_empty() {
            let mut out = Default::default();
            std::mem::swap(&mut out, &mut self.ready);
            task::current().notify();

            return Ok(Async::Ready(Some(out)));
        }

        Ok(Async::Ready(None))
    }
}
*/

#[cfg(test)]
mod tests {
    use super::Protocol;
    use super::*;
    use serde_json::json;
    use std::{collections::HashMap, str::FromStr};

    fn fixtures() -> (SocketAddr, Vec<u8>, Server) {
        let addr = SocketAddr::from_str("127.0.0.1:9000").unwrap();
        let data = vec![
            0x86, 0x00, 0x01, 0x04, 0x03, 0x4D, 0x47, 0x03, 0x05, 0x2E, 0x96, 0xB9, 0xAB, 0x2B,
            0xEA, 0x68, 0x6B, 0xFF, 0x94, 0x96, 0x1A, 0xD4, 0x33, 0xA7, 0x01, 0x32, 0x32, 0x33,
            0x22, 0x31, 0x61, 0x80, 0xDA, 0x1B, 0xA6, 0x44, 0x4A, 0x06, 0xCD, 0x17, 0xF8, 0xFA,
            0x79, 0xD6, 0x0A, 0x44, 0x4E, 0x07, 0x00, 0x48, 0xB3, 0xF9, 0xE4, 0xFD, 0x0D, 0xF2,
            0xA7, 0x2B, 0x5F, 0x44, 0xD3, 0xC8, 0xA2, 0xF4, 0xA0, 0x63, 0xEC, 0x0A, 0x00, 0x63,
            0xEC, 0x0A, 0x00, 0x0F, 0x00, 0x0A, 0x4F, 0x6E, 0x6C, 0x79, 0x46, 0x72, 0x69, 0x65,
            0x6E, 0x64, 0x73, 0x20, 0x4F, 0x70, 0x65, 0x6E, 0x54, 0x54, 0x44, 0x20, 0x53, 0x65,
            0x72, 0x76, 0x65, 0x72, 0x20, 0x23, 0x31, 0x00, 0x31, 0x2E, 0x35, 0x2E, 0x33, 0x00,
            0x16, 0x00, 0x19, 0x00, 0x00, 0x52, 0x61, 0x6E, 0x64, 0x6F, 0x6D, 0x20, 0x4D, 0x61,
            0x70, 0x00, 0x00, 0x04, 0x00, 0x04, 0x01, 0x01,
        ];
        let mut srv = Server::new(addr.clone());
        srv.status = Status::Up;
        srv.name = Some("OnlyFriends OpenTTD Server #1".into());
        srv.map = Some("Random Map".into());
        srv.num_clients = Some(0);
        srv.max_clients = Some(25);
        srv.need_pass = Some(false);
        srv.rules.insert("protocol-version".into(), json!(4));
        srv.rules.insert(
            "active-newgrf".into(),
            json!(vec![
                (478788, "48b3f9e4fd0df2a72b5f44d3c8a2f4a0"),
                (84100941, "2e96b9ab2bea686bff94961ad433a701"),
                (573780530, "316180da1ba6444a06cd17f8fa79d60a"),
            ]
            .into_iter()
            .collect::<HashMap<_, _>>()),
        );
        srv.rules.insert("current-time".into(), 715875.into());
        srv.rules.insert("start-time".into(), 715875.into());
        srv.rules.insert("max-companies".into(), 15.into());
        srv.rules.insert("current-companies".into(), 0.into());
        srv.rules.insert("server-version".into(), "1.5.3".into());
        srv.rules.insert("language-id".into(), 22.into());
        srv.rules.insert("current-spectators".into(), 0.into());
        srv.rules.insert("max-spectators".into(), 10.into());
        srv.rules.insert("map-set".into(), 1.into());
        srv.rules.insert("dedicated".into(), true.into());

        (addr, data, srv)
    }

    #[test]
    fn test_p_make_request() {
        let expectation = vec![3, 0, 0];
        let result = ProtocolImpl.make_request(None);

        assert_eq!(expectation, result);
    }

    #[test]
    fn test_p_parse_response() {
        let p = ProtocolImpl;
        let (addr, data, server) = fixtures();

        let expectation = vec![ParseResult::Output(server)];

        let result = p
            .parse_response(Packet { addr, data })
            .wait()
            .map(|res| res.unwrap())
            .collect::<Vec<ParseResult>>();

        assert_eq!(expectation, result);
    }
}
