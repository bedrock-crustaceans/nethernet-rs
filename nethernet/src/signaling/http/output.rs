use http::Response;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum HttpSignalerOutput {
    Response(HttpSignalerResponse),
    Timeout(Duration),
}

#[derive(Clone, Debug)]
pub struct HttpSignalerResponse {
    pub addr: u64,
    pub response: Response<Box<str>>,
}
