use crate::signaling::signal::Signal;
use http::Response;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum HttpSignalerOutput {
    /// A response the driver must send for a previously received request.
    Response(HttpSignalerResponse),
    /// A signal received from a client (an offer or a trickled candidate), ready to be
    /// handed to the session layer.
    Signal(Signal),
    /// Requests that the driver call `handle(Timeout(now))` again after `Duration` has
    /// elapsed, so a pending request can be timed out even with no further input.
    Timeout(Duration),
}

#[derive(Clone, Debug)]
pub struct HttpSignalerResponse {
    pub addr: u64,
    pub response: Response<Box<str>>,
}
