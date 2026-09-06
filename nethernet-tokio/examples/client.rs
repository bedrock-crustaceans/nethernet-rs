//! NetherNet client example using LAN discovery.
//!
//! Discovers servers on the LAN via broadcast, connects to the first one found, and
//! sends a few test packets on the reliable channel.

use nethernet_tokio::connection::{ConnectionEvent, connect_via_lan};
use nethernet_tokio::lan::LanSignaler;
use nethernet_tokio::router::SignalRouter;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::Level;
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

/// A real, routable local interface address - unlike LAN discovery (which learns
/// peers' addresses dynamically from received packets and can bind its own socket to
/// the wildcard address), the data connection's own address becomes its one ICE host
/// candidate verbatim (see `nethernet::session::Session::new`), so it must be an
/// address the local machine can actually be reached at.
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
    let filter_layer = filter::LevelFilter::from_level(Level::DEBUG);
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filter_layer)
        .init();

    let network_id = rand::random::<u64>();
    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
    // `broadcast: true` - this client actively seeks servers on the LAN.
    let signaling = LanSignaler::bind(bind_addr, network_id, true).await?;

    tracing::info!("NetherNet client starting");
    tracing::info!("   Network ID: {}", network_id);
    tracing::info!("   Scanning for servers on LAN...");

    let discovery_timeout_secs = std::env::var("DISCOVERY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3);
    tokio::time::sleep(Duration::from_secs(discovery_timeout_secs)).await;

    let servers = signaling.discovered().await;
    let Some((&server_network_id, server_data)) = servers.iter().next() else {
        tracing::error!("No servers found on LAN!");
        tracing::info!("Make sure a server is running on port 7551");
        return Ok(());
    };
    tracing::info!("Found server with network ID: {server_network_id}");
    tracing::debug!("   Server data: {server_data:?}");

    let router = SignalRouter::new(signaling);
    tracing::info!("Connecting to network ID: {server_network_id}");
    let data_local_addr = SocketAddr::new(local_ip()?, 0);
    let mut connection =
        connect_via_lan(&router, data_local_addr, rand::random(), server_network_id).await?;

    while let Some(event) = connection.recv().await {
        if matches!(event, ConnectionEvent::Ready) {
            break;
        }
    }
    tracing::info!("Connected");

    for i in 1..=10 {
        let message = format!("Hello from client, packet #{i}");
        tracing::debug!("Sending: {message}");
        connection.send(
            nethernet::session::Channel::Reliable,
            message.into_bytes().into(),
        );

        let echo = loop {
            match connection.recv().await {
                Some(ConnectionEvent::Message(_, data)) => break data,
                Some(ConnectionEvent::Ready) => continue,
                None => {
                    tracing::warn!("Connection closed by server");
                    return Ok(());
                }
            }
        };
        tracing::debug!("Received: {}", String::from_utf8_lossy(&echo));

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    tracing::info!("Done");
    Ok(())
}
