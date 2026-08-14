//! NetherNet client example using LAN discovery.
//!
//! This example demonstrates how to create a NetherNet client that:
//! - Discovers servers on LAN via broadcast
//! - Connects via WebRTC
//! - Sends and receives packets

use nethernet_tokio::NethernetStream;
use nethernet_tokio::signaling::lan::LanSignaling;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Level;
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    let filter_layer = filter::LevelFilter::from_level(Level::DEBUG);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filter_layer)
        .init();

    // Create client signaling with unique network ID
    // Use port 0 to let OS assign a free port (different from server's 7551)
    let mut network_id_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut network_id_bytes);
    let network_id = u64::from_le_bytes(network_id_bytes);
    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;

    let signaling = Arc::new(LanSignaling::new(network_id, bind_addr).await?);

    tracing::info!("NetherNet client starting");
    tracing::info!("   Network ID: {}", network_id);
    tracing::info!("   Scanning for servers on LAN...");

    // Read discovery timeout from environment variable or use default
    let discovery_timeout_secs = std::env::var("DISCOVERY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3);

    tracing::info!("   Discovery timeout: {}s", discovery_timeout_secs);

    // Wait for server discovery via broadcast
    tokio::time::sleep(Duration::from_secs(discovery_timeout_secs)).await;

    // Get discovered servers
    let servers = signaling.discover().await;

    if servers.is_empty() {
        tracing::error!("No servers found on LAN!");
        tracing::info!("Make sure a server is running on port 7551");
        return Ok(());
    }

    // Select the first discovered server
    let (server_network_id, server_data) = servers.iter().next().unwrap();
    tracing::info!("🎯 Found server with network ID: {}", server_network_id);
    tracing::debug!("   Server data: {:?}", server_data);

    // Get the actual server address from the signaling layer
    let server_addr = signaling
        .get_address(*server_network_id)
        .await
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Address not found for network ID {}", server_network_id),
            )
        })?;

    tracing::info!(
        "🔗 Connecting to server at {} (network ID: {})",
        server_addr,
        server_network_id
    );

    // Connect to the server using discovered network ID
    let mut stream = NethernetStream::connect(
        signaling.clone(),
        server_network_id.to_string(),
        server_addr,
    )
    .await?;

    tracing::info!("✅ Connected to server");

    // Send some test packets
    for i in 1..=10 {
        let message = format!("Hello from client, packet #{}", i);

        tracing::debug!("📤 Sending: {}", message);
        stream.write_all(message.as_bytes()).await?;
        stream.flush().await?;

        // Receive echo response
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            tracing::warn!("Connection closed by server");
            break;
        }

        let text = String::from_utf8_lossy(&buf[..n]);
        tracing::debug!("📥 Received: {}", text);

        // Wait a bit between packets
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Test large packet (will be segmented)
    tracing::info!("📦 Sending large packet (20KB)...");
    let large_data = vec![0xAB; 20_000];
    stream.write_all(&large_data).await?;
    stream.flush().await?;

    // Read back large packet
    let mut response = vec![0u8; 20_000];
    stream.read_exact(&mut response).await?;
    tracing::info!("✅ Large packet echoed back ({} bytes)", response.len());

    // Close connection gracefully
    tracing::info!("👋 Closing connection...");
    stream.close().await?;
    tracing::info!("✅ Connection closed");

    Ok(())
}
