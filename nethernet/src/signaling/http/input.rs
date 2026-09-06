use crate::signaling::signal::Signal;
use http::Request;
use std::time::Instant;

#[derive(Clone, Debug)]
pub enum HttpSignalerInput {
    /// An HTTP request arrived on the signaling listener.
    Request(HttpSignalerRequest, Instant),
    /// A signal produced locally (an answer or a rejection) that should complete
    /// whichever pending join it answers.
    Signal(Signal, Instant),
    /// A previously requested wakeup (see [`super::output::HttpSignalerOutput::Timeout`])
    /// has elapsed.
    Timeout(Instant),
}

#[derive(Clone, Debug)]
pub struct HttpSignalerRequest {
    /// Opaque handle assigned by the driver, used to route the eventual response back
    /// to the in-flight request that produced it.
    pub addr: u64,
    pub request: Request<Box<str>>,
}
