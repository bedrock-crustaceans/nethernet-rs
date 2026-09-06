//! A shared async event loop for driving one of `nethernet`'s sans-io state machines
//! (LAN signaling, an established connection) over a real [`tokio::net::UdpSocket`].
//!
//! Every such state machine in `nethernet` is fed datagrams and time and polled for
//! datagrams to send and a next timeout, in the same shape; this is that shape's async
//! driver, factored out once so each wrapper only has to describe how to adapt its own
//! `handle`/`poll` calls to it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// A datagram-and-time-driven state machine, adapted to a uniform shape so
/// [`run`] can drive any of them.
pub(crate) trait UdpDriven {
    /// Whatever this driver produces besides datagrams to send - e.g. a decoded
    /// [`nethernet::signaling::signal::Signal`] for LAN signaling, or a
    /// [`nethernet::session::SessionOutput`] for an established connection.
    type Output: Send + 'static;
    /// Something the owning handle can inject from outside the driving loop - e.g.
    /// "send this `Signal`" for LAN signaling, or "send this application message" for
    /// a connection. `()` if this driver never needs external input beyond datagrams.
    type Command: Send + 'static;
    type Error: std::fmt::Display;

    fn handle_packet(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), Self::Error>;
    fn handle_command(&mut self, command: Self::Command, now: Instant) -> Result<(), Self::Error>;
    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error>;
    /// The next time [`Self::handle_timeout`] should be called, if anything is
    /// pending.
    fn poll_timeout(&mut self, now: Instant) -> Option<Instant>;
    /// Drains one queued output: either a datagram this driver needs sent, or
    /// something for the caller.
    fn poll(&mut self) -> Option<UdpDrivenOutput<Self::Output>>;
}

pub(crate) enum UdpDrivenOutput<O> {
    /// A datagram to send over the same socket this driver is being fed from.
    Send(Vec<u8>, SocketAddr),
    /// An application-level output, forwarded to whoever is consuming this driver.
    Output(O),
}

/// A generous ceiling used in place of "no timeout pending", so the driving loop can
/// always `select!` on a single sleep future rather than an optional one.
const NO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Runs `driven` to completion: feeds it inbound datagrams from `socket` and commands
/// from `command_rx`, drives its timers, sends its outbound datagrams back out over
/// `socket`, and forwards every other output to `output_tx`. Returns once either
/// channel's counterpart is dropped (the owning handle went away) - whichever comes
/// first.
///
/// Logs (via `tracing`) and otherwise ignores errors from `handle_packet`/
/// `handle_command`/`handle_timeout` - a single malformed or spurious datagram, or a
/// benign protocol hiccup, should not tear down the whole driver.
pub(crate) async fn run<T>(
    socket: Arc<UdpSocket>,
    mut driven: T,
    mut command_rx: mpsc::UnboundedReceiver<T::Command>,
    output_tx: mpsc::UnboundedSender<T::Output>,
) where
    T: UdpDriven,
{
    let mut buf = vec![0u8; 65536];

    loop {
        while let Some(output) = driven.poll() {
            match output {
                UdpDrivenOutput::Send(data, to) => {
                    if let Err(e) = socket.send_to(&data, to).await {
                        tracing::debug!("send error: {e}");
                    }
                }
                UdpDrivenOutput::Output(o) => {
                    if output_tx.send(o).is_err() {
                        // No one is listening anymore; nothing left to drive for.
                        return;
                    }
                }
            }
        }

        let now = Instant::now();
        let delay = driven
            .poll_timeout(now)
            .map(|t| t.saturating_duration_since(now))
            .unwrap_or(NO_TIMEOUT);

        tokio::select! {
            biased;

            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, from)) => {
                        let now = Instant::now();
                        if let Err(e) = driven.handle_packet(&buf[..n], from, now) {
                            tracing::debug!("packet handling error: {e}");
                        }
                    }
                    Err(e) => tracing::debug!("recv error: {e}"),
                }
            }
            command = command_rx.recv() => {
                match command {
                    Some(command) => {
                        let now = Instant::now();
                        if let Err(e) = driven.handle_command(command, now) {
                            tracing::debug!("command handling error: {e}");
                        }
                    }
                    // The owning handle was dropped; nothing left to drive for.
                    None => return,
                }
            }
            _ = tokio::time::sleep(delay) => {
                let now = Instant::now();
                if let Err(e) = driven.handle_timeout(now) {
                    tracing::debug!("timeout handling error: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::convert::Infallible;

    /// A trivial `UdpDriven`: on the very first poll, queues one outbound datagram to
    /// a fixed peer; every inbound datagram is forwarded verbatim as `Output`. No
    /// timers.
    struct Echo {
        greeting: Option<(Vec<u8>, SocketAddr)>,
        received: VecDeque<Vec<u8>>,
    }

    impl UdpDriven for Echo {
        type Output = Vec<u8>;
        type Command = ();
        type Error = Infallible;

        fn handle_packet(
            &mut self,
            data: &[u8],
            _from: SocketAddr,
            _now: Instant,
        ) -> Result<(), Infallible> {
            self.received.push_back(data.to_vec());
            Ok(())
        }

        fn handle_command(&mut self, _command: (), _now: Instant) -> Result<(), Infallible> {
            Ok(())
        }

        fn handle_timeout(&mut self, _now: Instant) -> Result<(), Infallible> {
            Ok(())
        }

        fn poll_timeout(&mut self, _now: Instant) -> Option<Instant> {
            None
        }

        fn poll(&mut self) -> Option<UdpDrivenOutput<Vec<u8>>> {
            if let Some((data, to)) = self.greeting.take() {
                return Some(UdpDrivenOutput::Send(data, to));
            }
            self.received.pop_front().map(UdpDrivenOutput::Output)
        }
    }

    #[tokio::test]
    async fn drives_a_send_and_forwards_a_receive() {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b_addr = b.local_addr().unwrap();

        let (a_tx, mut a_rx) = mpsc::unbounded_channel();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel();
        let (_a_cmd_tx, a_cmd_rx) = mpsc::unbounded_channel();
        let (_b_cmd_tx, b_cmd_rx) = mpsc::unbounded_channel();

        let a_driven = Echo {
            greeting: Some((b"hello from a".to_vec(), b_addr)),
            received: VecDeque::new(),
        };
        let b_driven = Echo {
            greeting: None,
            received: VecDeque::new(),
        };

        tokio::spawn(run(a.clone(), a_driven, a_cmd_rx, a_tx));
        tokio::spawn(run(b.clone(), b_driven, b_cmd_rx, b_tx));

        // b receives a's greeting and forwards it as an Output.
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), b_rx.recv())
            .await
            .expect("timed out waiting for b to receive a's greeting")
            .unwrap();
        assert_eq!(received, b"hello from a");

        // a never queued anything besides its one greeting.
        assert!(a_rx.try_recv().is_err());
    }
}
