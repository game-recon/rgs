use errors;
use errors::Error;
use futures;
use futures::prelude::*;
use futures::stream::FuturesUnordered;
use protocols::models as pmodels;
use serde_json::Value;
use std;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio_dns;

pub fn resolve_host(
    resolver: Arc<tokio_dns::Resolver + Send + Sync + 'static>,
    host: pmodels::Host,
) -> Box<Future<Item = SocketAddr, Error = errors::Error>> {
    match host {
        pmodels::Host::A(addr) => Box::new(futures::future::ok(addr)),
        pmodels::Host::S(stringaddr) => Box::new(
            resolver
                .resolve(&stringaddr.host)
                .map_err(|e| Error::NetworkError {
                    reason: std::error::Error::description(&e).into(),
                })
                .and_then(move |addrs| {
                    addrs
                        .into_iter()
                        .next()
                        .map(|ipaddr| SocketAddr::new(ipaddr, stringaddr.port))
                        .ok_or_else(|| Error::NetworkError {
                            reason: format!("Failed to resolve host {}", &stringaddr.host),
                        })
                }),
        ),
    }
}

pub type History = Arc<Mutex<HashMap<SocketAddr, String>>>;

pub struct ResolvedQuery {
    pub addr: SocketAddr,
    pub protocol: pmodels::TProtocol,
    pub state: Option<Value>,
}

pub struct Resolver {
    inner: Arc<tokio_dns::Resolver + Send + Sync + 'static>,
    history: History,
    pending_requests: FuturesUnordered<Box<Future<Item = Option<ResolvedQuery>, Error = Error>>>,
}

impl Resolver {
    pub fn new(
        resolver: Arc<tokio_dns::Resolver + Send + Sync + 'static>,
        history: History,
    ) -> Self {
        let mut pending_requests = FuturesUnordered::new();
        pending_requests.push(Box::new(futures::future::empty())
            as Box<Future<Item = Option<ResolvedQuery>, Error = Error>>);
        Self {
            inner: resolver,
            history,
            pending_requests,
        }
    }
}

impl Sink for Resolver {
    type SinkItem = pmodels::Query;
    type SinkError = Error;

    fn poll_ready(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }

    fn start_send(&mut self, query: Self::SinkItem) -> Result<(), Self::SinkError> {
        self.pending_requests.push(Box::new(
            resolve_host(self.inner.clone(), query.host.clone())
                .inspect({
                    let host = query.host.clone();
                    let history = Arc::clone(&self.history);
                    move |&addr| {
                        if let pmodels::Host::S(ref s) = host {
                            history.lock().unwrap().insert(addr.clone(), s.host.clone());
                        }
                    }
                })
                .map(|addr| {
                    Some(ResolvedQuery {
                        addr,
                        protocol: query.protocol,
                        state: query.state,
                    })
                })
                .or_else(|e| Ok(None)),
        ));
        Ok(())
    }

    fn poll_flush(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }

    fn poll_close(&mut self, cx: &mut task::Context) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl Stream for Resolver {
    type Item = ResolvedQuery;
    type Error = Error;

    fn poll_next(&mut self, cx: &mut task::Context) -> Poll<Option<Self::Item>, Self::Error> {
        if let Async::Ready(Some(result)) = self.pending_requests.poll()? {
            if let Some(resolved) = result {
                return Ok(Async::Ready(Some(resolved)));
            }
        }

        Ok(Async::NotReady)
    }
}
