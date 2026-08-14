//! Signaling against the HTTP endpoint of a server.

use futures::StreamExt;
use nethernet_tokio::signaling::http::HttpSignaling;
use nethernet_tokio::{NethernetError, Signal, SignalType, Signaling};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread")]
async fn offer_is_answered_by_the_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 4096];
        let n = stream.read(&mut request).await.unwrap();

        let answer = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            answer.len(),
            answer
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        String::from_utf8_lossy(&request[..n]).to_string()
    });

    let signaling = HttpSignaling::new("1234".to_string()).unwrap();
    assert!(signaling.disable_trickle_ice());

    let mut signals = signaling.signals();
    signaling
        .signal(Signal::offer(
            42,
            "v=0\r\n".to_string(),
            format!("http://{addr}"),
        ))
        .await
        .unwrap();

    let request = server.await.unwrap();
    assert!(
        request.starts_with("POST /v1/join/1234 HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains("content-type: application/sdp"),
        "{request}"
    );
    assert!(
        request.contains("user-agent: libhttpclient/1.0.0.0"),
        "{request}"
    );

    let signal = tokio::time::timeout(Duration::from_secs(5), signals.next())
        .await
        .expect("answer timed out")
        .expect("stream closed");
    assert_eq!(signal.signal_type, SignalType::Answer);
    assert_eq!(signal.connection_id, 42);
    assert!(signal.data.starts_with("v=0"));
}

#[tokio::test(flavor = "multi_thread")]
async fn error_code_in_the_response_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 4096];
        let _ = stream.read(&mut request).await.unwrap();

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n15")
            .await
            .unwrap();
        stream.flush().await.unwrap();
    });

    let signaling = HttpSignaling::new("1234".to_string()).unwrap();
    let err = signaling
        .signal(Signal::offer(
            1,
            "v=0\r\n".to_string(),
            format!("http://{addr}"),
        ))
        .await
        .unwrap_err();

    assert!(matches!(err, NethernetError::Signaled(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn candidates_are_not_signaled_separately() {
    let signaling = HttpSignaling::new("1234".to_string()).unwrap();

    let err = signaling
        .signal(Signal::candidate(
            1,
            "candidate:1 1 udp 1 127.0.0.1 1 typ host".to_string(),
            "http://127.0.0.1:19132".to_string(),
        ))
        .await
        .unwrap_err();

    assert!(err.to_string().contains("not supported"), "{err}");
}
