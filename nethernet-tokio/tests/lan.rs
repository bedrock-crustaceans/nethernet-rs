//! End-to-end negotiation over LAN discovery.

use nethernet_tokio::signaling::lan::{LanConfig, LanSignaling};
use nethernet_tokio::{NethernetListener, NethernetStream, ServerData};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use nethernet_tokio::Signaling;
use nethernet_tokio::protocol::Signal;
use std::pin::Pin;

const PORT: u16 = 7571;

fn config() -> LanConfig {
    config_for(PORT)
}

fn config_for(port: u16) -> LanConfig {
    LanConfig {
        discovery_port: port,
        broadcast_interval: Duration::from_millis(200),
        ..Default::default()
    }
}

/// Signaling that negotiates without trickle ICE, as HTTP endpoints do.
struct NonTrickle(LanSignaling);

impl Signaling for NonTrickle {
    async fn signal(&self, signal: Signal) -> nethernet_tokio::Result<()> {
        self.0.signal(signal).await
    }

    fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        self.0.signals()
    }

    fn network_id(&self) -> String {
        self.0.network_id()
    }

    fn disable_trickle_ice(&self) -> bool {
        true
    }

    fn set_pong_data(&self, data: &[u8]) {
        self.0.set_pong_data(data)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lan_roundtrip() {
    let server_signaling = LanSignaling::with_config(
        1234,
        format!("0.0.0.0:{PORT}").parse::<SocketAddr>().unwrap(),
        config(),
    )
    .await
    .unwrap();
    server_signaling.set_server_data(ServerData::new("test".into(), "world".into()));

    let mut listener = NethernetListener::bind(server_signaling).await.unwrap();
    tokio::spawn(async move {
        let session = listener.accept().await.unwrap();
        let unreliable = session.clone();
        tokio::spawn(async move {
            while let Ok(Some(data)) = unreliable.recv_unreliable().await {
                unreliable.send_unreliable(data).await.unwrap();
            }
        });
        while let Ok(Some(data)) = session.recv().await {
            session.send(data).await.unwrap();
        }
    });

    let client_signaling = Arc::new(
        LanSignaling::with_config(5678, "0.0.0.0:0".parse().unwrap(), config())
            .await
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(600)).await;

    let servers = client_signaling.discover().await;
    assert_eq!(servers.len(), 1, "server not discovered");
    assert_eq!(servers[&1234].server_name, "test");

    let stream = NethernetStream::connect(client_signaling, "1234".to_string())
        .await
        .unwrap();

    stream.send("hello".into()).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), stream.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"hello");

    stream.send_unreliable("fast".into()).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), stream.recv_unreliable())
        .await
        .expect("unreliable echo timed out")
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"fast");

    assert_eq!(stream.remote_addr().await.network_id, "1234");
    stream.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn non_trickle_roundtrip() {
    const PORT: u16 = 7572;

    let server_signaling = LanSignaling::with_config(
        4321,
        format!("0.0.0.0:{PORT}").parse::<SocketAddr>().unwrap(),
        config_for(PORT),
    )
    .await
    .unwrap();
    server_signaling.set_server_data(ServerData::new("test".into(), "world".into()));

    let mut listener = NethernetListener::bind(NonTrickle(server_signaling))
        .await
        .unwrap();
    tokio::spawn(async move {
        let session = listener.accept().await.unwrap();
        while let Ok(Some(data)) = session.recv().await {
            session.send(data).await.unwrap();
        }
    });

    let client_signaling =
        LanSignaling::with_config(8765, "0.0.0.0:0".parse().unwrap(), config_for(PORT))
            .await
            .unwrap();
    let client_signaling = Arc::new(NonTrickle(client_signaling));
    tokio::time::sleep(Duration::from_millis(600)).await;

    let stream = NethernetStream::connect(client_signaling, "4321".to_string())
        .await
        .unwrap();

    stream.send("hello".into()).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), stream.recv())
        .await
        .expect("echo timed out")
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"hello");

    stream.close().await.unwrap();
}
