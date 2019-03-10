use crate::errors::Error;
use crate::models::*;

use {
    core::{
        pin::Pin,
        task::{Poll, Waker},
    },
    failure::{self, format_err, Fallible},
    futures::{prelude::*, stream::FuturesUnordered, ready},
    log::debug,
    serde_json::Value,
    std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, Mutex},
    },
    tokio_dns,
};

pub trait Resolver: Send + Sync + 'static {
    fn resolve(
        &self,
        host: Host,
    ) -> Pin<Box<dyn Future<Output = Fallible<SocketAddr, failure::Error>> + Send>>;
}

impl<T> Resolver for T
where
    T: tokio_dns::Resolver + Send + Sync + 'static,
{
    fn resolve(
        &self,
        host: Host,
    ) -> Pin<Box<dyn Future<Output = Fallible<SocketAddr, failure::Error>> + Send>> {
        async move {
            match host {
                Host::A(addr) => Ok(addr),
                Host::S(stringaddr) => {
                    let addrs =
                        await!(tokio_dns::Resolver::resolve(self, &stringaddr.host).compat())?;

                    addrs
                        .into_iter()
                        .next()
                        .map(|ipaddr| SocketAddr::new(ipaddr, stringaddr.port))
                        .ok_or_else(|| {
                            format_err!("Failed to resolve host {}", &stringaddr.host)
                                .context(Error::NetworkError)
                                .into()
                        })
                }
            }
        }
            .boxed()
    }
}

pub type History = Arc<Mutex<HashMap<SocketAddr, String>>>;

pub struct ResolvedQuery {
    pub addr: SocketAddr,
    pub protocol: TProtocol,
    pub state: Option<Value>,
}

pub struct ResolverPipe {
    inner: Arc<Resolver>,
    history: History,
    pending_requests:
        FuturesUnordered<Pin<Box<dyn Future<Output = Fallible<Option<ResolvedQuery>>> + Send>>>,
}

impl ResolverPipe {
    pub fn new(resolver: Arc<Resolver>, history: History) -> Self {
        let mut pending_requests = FuturesUnordered::new();
        pending_requests.push(Box::new(futures::future::empty())
            as Pin<
                Box<dyn Future<Item = Option<ResolvedQuery>, Error = failure::Error> + Send>,
            >);
        Self {
            inner: resolver,
            history,
            pending_requests,
        }
    }
}

impl Sink<Query> for ResolverPipe {
    type Error = failure::Error;

    fn poll_ready(self: Pin<&mut Self>, waker: &Waker) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Query) -> Result<(), Self::Error> {
        self.pending_requests.push(
            async move {
                self.inner
                    .resolve(query.host.clone())
                    .inspect({
                        let host = query.host.clone();
                        let history = Arc::clone(&self.history);
                        move |&addr| {
                            if let Host::S(ref s) = host {
                                history.lock().unwrap().insert(addr, s.host.clone());
                            }
                        }
                    })
                    .map_ok(|addr| {
                        Some(ResolvedQuery {
                            addr,
                            protocol: query.protocol,
                            state: query.state,
                        })
                    })
                    .or_else(|_e| Ok(None))
            }
                .boxed(),
        );
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, waker: &Waker) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, waker: &Waker) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for ResolverPipe {
    type Item = Fallible<ResolvedQuery>;

    fn poll_next(self: Pin<&mut Self>, waker: &Waker) -> Poll<Option<Self::Item>> {
        let result = ready!(self.pending_requests.poll());

        if let Some(resolved) = result {
            if resolved.addr.ip().is_unspecified() {
                debug!("Ignoring unspecified address");
            } else {
                debug!("Resolved: {:?}", resolved.addr);
                return Poll::Ready(Some(resolved));
            }
        }

        Poll::Pending
    }
}
