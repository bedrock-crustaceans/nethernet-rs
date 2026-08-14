use http::Request;
use std::time::Instant;

#[derive(Clone, Debug)]
pub enum HttpSignalerInput {
    Request(HttpSignalerRequest, Instant),
    Timeout(Instant),
}

#[derive(Clone, Debug)]
pub struct HttpSignalerRequest {
    pub addr: u64,
    pub request: Request<Box<str>>,
}
