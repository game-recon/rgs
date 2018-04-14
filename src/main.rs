extern crate futures;
extern crate librgs;
extern crate rand;
extern crate resolve;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_timer;

use futures::prelude::*;
use librgs::errors::Error;
use librgs::protocols::models::*;
use librgs::util::LoggingService;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio_core::net::UdpSocket;

fn main() {
    // let server = ("master.openttd.org", 3978);
    // let p = protocols::openttdm::P::default();
    let logger = librgs::util::RealLogger;
    let pconfig = librgs::protocols::make_default_protocols();

    let requests = vec![UserQuery {
        protocol: pconfig.get("openttdm".into()).unwrap().clone(),
        host: Host::S(
            StringAddr {
                host: "master.openttd.org".into(),
                port: 3978,
            }.into(),
        ),
    }];

    let query_builder = librgs::UdpQueryBuilder::default();

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let socket = UdpSocket::bind(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 5678),
        &core.handle(),
    ).unwrap();
    let (request_sink, server_stream) = query_builder.make_query(socket).split();

    let request_stream = futures::stream::iter_ok::<Vec<UserQuery>, Error>(requests);
    let request_fut = request_sink.send_all(request_stream).and_then(|_| {
        println!("Sent all");
        Ok(())
    });

    let timeout = std::time::Duration::from_secs(10);

    println!("Starting core");

    core.run(tokio_timer::Deadline::new(
        futures::future::join_all(vec![
            Box::new(request_fut) as Box<Future<Item = (), Error = Error>>,
            Box::new(
                server_stream
                    .inspect(move |entry| {
                        logger.info(&serde_json::to_string(&entry.clone().into_inner().1).unwrap());
                    })
                    .for_each(|_| Ok(())),
            ),
        ]),
        std::time::Instant::now() + timeout,
    )).unwrap();
}
