//! NetherNet server example using LAN discovery.
//!
//! Broadcasts server information on LAN, accepts incoming connections, and echoes
//! back whatever it receives on the reliable channel.

use nethernet::protocol::packet::discovery::ServerData;
use nethernet_tokio::connection::ConnectionEvent;
use nethernet_tokio::lan::LanSignaler;
use nethernet_tokio::listener::Listener;
use nethernet_tokio::router::SignalRouter;
use std::net::SocketAddr;
use tracing::Level;
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

/// A real, routable local interface address - each accepted connection's own address
/// becomes its one ICE host candidate verbatim (see `nethernet::session::Session::new`),
/// so, unlike the LAN discovery socket (which can bind the wildcard address and learns
/// peers' addresses dynamically from received packets), it must be an address the
/// local machine can actually be reached at.
///
/// Connecting a UDP socket sends nothing on the wire - it just asks the OS to pick the
/// outbound route/interface for that destination, which is all this needs.
fn local_ip() -> std::io::Result<std::net::IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect("8.8.8.8:80")?;
    probe.local_addr().map(|addr| addr.ip())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);
    let filter_layer = filter::LevelFilter::from_level(Level::INFO);
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filter_layer)
        .init();

    let network_id = rand::random::<u64>();
    // The server doesn't need to seek other peers itself (`broadcast: false`) - it just
    // answers discovery requests aimed at it.
    let bind_addr: SocketAddr = "0.0.0.0:7551".parse()?;
    let signaling = LanSignaler::bind(bind_addr, network_id, false).await?;
    signaling.set_server_data(Some(ServerData::new(
        "My NetherNet Server".to_string(),
        "Example World".to_string(),
    )));

    tracing::info!("NetherNet server starting");
    tracing::info!("   Network ID: {}", network_id);
    tracing::info!("   Listening on: {}", bind_addr);

    let router = SignalRouter::new(signaling);
    let mut listener = Listener::new(router, SocketAddr::new(local_ip()?, 0));
    tracing::info!("Server ready and responding to LAN discovery");

    loop {
        match listener.accept().await {
            Some(Ok(mut connection)) => {
                tracing::info!("New client connected");
                tokio::spawn(async move {
                    let mut packet_count = 0;
                    while let Some(event) = connection.recv().await {
                        match event {
                            ConnectionEvent::Ready => tracing::info!("Connection ready"),
                            ConnectionEvent::Message(channel, data) => {
                                packet_count += 1;
                                connection.send(channel, data.into());
                            }
                        }
                    }
                    tracing::info!("Client disconnected ({packet_count} packets echoed)");
                });
            }
            Some(Err(e)) => tracing::error!("Failed to accept connection: {e}"),
            None => {
                tracing::error!("Signaling stopped; server shutting down");
                break;
            }
        }
    }

    Ok(())
}
