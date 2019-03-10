use core::pin::Pin;
use futures::prelude::*;
use rand::random;
use std::net::IpAddr;
use std::time::Duration;

pub trait Pinger: Send + Sync {
    fn ping(
        &self,
        addr: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Fallible<Option<Duration>> + Send>>>;
}

pub struct DummyPinger;

impl Pinger for DummyPinger {
    fn ping(
        &self,
        _addr: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Fallible<Option<Duration>> + Send>>> {
        async { Ok(None) }.boxed()
    }
}

impl Pinger for tokio_ping::Pinger {
    fn ping(
        &self,
        addr: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Fallible<Option<Duration>> + Send>>> {
        async {
            let rtt = tokio_ping::Pinger::ping(&self, addr, random(), 0, Duration::from_secs(4))?;

            rtt.map(|v| Duration::from_millis(v as u64))
        }
            .boxed()
    }
}
