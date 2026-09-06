//! Hosting a NetherNet HTTP signaling endpoint (the guide's section 4): a real HTTP
//! server whose requests are converted into
//! [`nethernet::signaling::http::HttpSignaler`] inputs, driven in a background task.
//!
//! Unlike LAN signaling (UDP, packet-and-time driven, see [`crate::net`]), HTTP
//! signaling is connection-oriented and each request may be held open across multiple
//! driver ticks (awaiting an answer), so this has its own driving loop rather than
//! reusing [`crate::net::run`].

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use nethernet::sans::Sans;
use nethernet::signaling::http::HttpSignaler as SansHttpSignaler;
use nethernet::signaling::http::input::{HttpSignalerInput, HttpSignalerRequest};
use nethernet::signaling::http::output::HttpSignalerOutput;
use nethernet::signaling::signal::Signal;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

type SignalingResponse = http::Response<Box<str>>;
type PendingResponse = oneshot::Sender<SignalingResponse>;

/// A very long sleep used in place of "no deadline pending", so the driving loop can
/// always `select!` on a single sleep future.
const NO_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);

struct Driver {
    inner: SansHttpSignaler,
    next_addr: u64,
    pending: HashMap<u64, PendingResponse>,
    /// Absolute deadlines from queued [`HttpSignalerOutput::Timeout`]s, not yet fired.
    deadlines: Vec<Instant>,
}

impl Driver {
    fn drain_outputs(&mut self, signal_tx: &mpsc::UnboundedSender<Signal>) {
        while let Some(output) = Sans::poll(&mut self.inner) {
            match output {
                HttpSignalerOutput::Response(resp) => {
                    if let Some(tx) = self.pending.remove(&resp.addr) {
                        let _ = tx.send(resp.response);
                    }
                }
                HttpSignalerOutput::Signal(signal) => {
                    let _ = signal_tx.send(signal);
                }
                HttpSignalerOutput::Timeout(duration) => {
                    self.deadlines.push(Instant::now() + duration);
                }
            }
        }
    }

    fn next_delay(&self, now: Instant) -> Duration {
        self.deadlines
            .iter()
            .min()
            .map(|deadline| deadline.saturating_duration_since(now))
            .unwrap_or(NO_DEADLINE)
    }
}

async fn run(
    mut driver: Driver,
    mut request_rx: mpsc::UnboundedReceiver<(http::Request<Box<str>>, PendingResponse)>,
    mut command_rx: mpsc::UnboundedReceiver<Signal>,
    signal_tx: mpsc::UnboundedSender<Signal>,
) {
    loop {
        driver.drain_outputs(&signal_tx);

        let now = Instant::now();
        let delay = driver.next_delay(now);

        tokio::select! {
            biased;

            request = request_rx.recv() => {
                let Some((request, response_tx)) = request else {
                    // No listener left to accept connections; nothing left to drive.
                    return;
                };
                let addr = driver.next_addr;
                driver.next_addr += 1;
                driver.pending.insert(addr, response_tx);

                let now = Instant::now();
                if let Err(e) = driver.inner.handle(HttpSignalerInput::Request(
                    HttpSignalerRequest { addr, request },
                    now,
                )) {
                    tracing::debug!("request handling error: {e}");
                }
            }
            signal = command_rx.recv() => {
                if let Some(signal) = signal {
                    let now = Instant::now();
                    if let Err(e) = driver.inner.handle(HttpSignalerInput::Signal(signal, now)) {
                        tracing::debug!("signal handling error: {e}");
                    }
                }
            }
            _ = tokio::time::sleep(delay) => {
                let now = Instant::now();
                driver.deadlines.retain(|deadline| *deadline > now);
                if let Err(e) = driver.inner.handle(HttpSignalerInput::Timeout(now)) {
                    tracing::debug!("timeout handling error: {e}");
                }
            }
        }
    }
}

/// A NetherNet HTTP signaling server: accepts connections on a real
/// [`tokio::net::TcpListener`] and drives
/// [`nethernet::signaling::http::HttpSignaler`] over them in a background task.
///
/// Dropping this stops accepting new connections and, once every in-flight request
/// finishes, stops the driving task.
pub struct HttpSignalingServer {
    local_addr: SocketAddr,
    command_tx: mpsc::UnboundedSender<Signal>,
    signal_rx: mpsc::UnboundedReceiver<Signal>,
    driver_task: JoinHandle<()>,
    accept_task: JoinHandle<()>,
}

impl HttpSignalingServer {
    /// Binds a TCP listener at `bind_addr` and starts accepting NetherNet HTTP
    /// signaling requests on it in the background.
    pub async fn bind(bind_addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;

        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();

        let driver = Driver {
            inner: SansHttpSignaler::new(),
            next_addr: 0,
            pending: HashMap::new(),
            deadlines: Vec::new(),
        };
        let driver_task = tokio::spawn(run(driver, request_rx, command_rx, signal_tx));
        let accept_task = tokio::spawn(accept_loop(listener, request_tx));

        Ok(Self {
            local_addr,
            command_tx,
            signal_rx,
            driver_task,
            accept_task,
        })
    }

    /// The address this server's listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Queues `signal` (an answer or a rejection) to complete whichever pending join
    /// it answers. Fire-and-forget: silently dropped if the driver has already
    /// stopped.
    pub fn send(&self, signal: Signal) {
        let _ = self.command_tx.send(signal);
    }

    /// Receives the next signal from a client (an offer). Returns `None` once the
    /// driver has stopped.
    pub async fn recv(&mut self) -> Option<Signal> {
        self.signal_rx.recv().await
    }
}

impl Drop for HttpSignalingServer {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.driver_task.abort();
    }
}

async fn accept_loop(
    listener: TcpListener,
    request_tx: mpsc::UnboundedSender<(http::Request<Box<str>>, PendingResponse)>,
) {
    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::debug!("accept error: {e}");
                continue;
            }
        };

        let request_tx = request_tx.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |request: http::Request<Incoming>| {
                let request_tx = request_tx.clone();
                async move { Ok::<_, Infallible>(handle(request, &request_tx).await) }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!("connection error: {e}");
            }
        });
    }
}

/// Converts one HTTP request into a `HttpSignalerInput::Request`, waits for the
/// corresponding response, and converts it back.
async fn handle(
    request: http::Request<Incoming>,
    request_tx: &mpsc::UnboundedSender<(http::Request<Box<str>>, PendingResponse)>,
) -> http::Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return empty_response(http::StatusCode::BAD_REQUEST),
    };
    let body: Box<str> = match String::from_utf8(body.to_vec()) {
        Ok(s) => s.into_boxed_str(),
        Err(_) => return empty_response(http::StatusCode::BAD_REQUEST),
    };
    let request = http::Request::from_parts(parts, body);

    let (response_tx, response_rx) = oneshot::channel();
    if request_tx.send((request, response_tx)).is_err() {
        return empty_response(http::StatusCode::SERVICE_UNAVAILABLE);
    }

    match response_rx.await {
        Ok(response) => response.map(|body| Full::new(Bytes::from(body.into_boxed_bytes()))),
        Err(_) => empty_response(http::StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn empty_response(status: http::StatusCode) -> http::Response<Full<Bytes>> {
    http::Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| http::Response::new(Full::new(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nethernet::signaling::signal::{Signal, SignalType};
    use std::net::Ipv4Addr;
    use std::time::Duration as StdDuration;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// A real HTTP client POSTs an offer to a real server; the server surfaces it as a
    /// `Signal` over the driver, the test answers it, and the client's request
    /// completes with the answer SDP - the whole guide section 4 round trip, over a
    /// real TCP connection.
    #[tokio::test]
    async fn join_is_answered_end_to_end() {
        crate::http::client::install_rustls_provider();
        let mut server = HttpSignalingServer::bind(loopback(0)).await.unwrap();
        let base_url = url::Url::parse(&format!("http://{}/", server.local_addr())).unwrap();

        let client = reqwest::Client::new();
        assert!(crate::http::client::supports_nethernet(&client, &base_url).await);

        let join = tokio::spawn({
            let client = client.clone();
            let base_url = base_url.clone();
            async move {
                crate::http::client::join(&client, &base_url, 7, "offer-sdp".to_string()).await
            }
        });

        let offer = tokio::time::timeout(StdDuration::from_secs(5), server.recv())
            .await
            .expect("server never received the offer")
            .unwrap();
        assert_eq!(offer.signal_type, SignalType::Offer);
        assert_eq!(offer.network_id, 7);
        assert_eq!(offer.data, "offer-sdp");

        server.send(Signal::answer(
            offer.connection_id,
            "answer-sdp".to_string(),
            7,
        ));

        let answer = tokio::time::timeout(StdDuration::from_secs(5), join)
            .await
            .expect("client join never completed")
            .unwrap()
            .unwrap();
        assert_eq!(answer, "answer-sdp");
    }
}
