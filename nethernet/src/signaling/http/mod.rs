pub mod error;
pub mod input;
pub mod output;

use crate::sans::Sans;
use crate::signaling::http::error::HttpSignalerError;
use crate::signaling::http::input::{HttpSignalerInput, HttpSignalerRequest};
use crate::signaling::http::output::{HttpSignalerOutput, HttpSignalerResponse};
use http::header::CONTENT_LENGTH;
use http::{Method, Response, StatusCode};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

struct Pending {
    network_id: Box<str>,
    offer: Box<str>,
    timeout: Instant,
}

pub struct HttpSignaler {
    pending: HashMap<Box<str>, Pending>,
    output: VecDeque<HttpSignalerOutput>,
}

impl Sans for HttpSignaler {
    type Input = HttpSignalerInput;
    type Output = HttpSignalerOutput;
    type Error = HttpSignalerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            HttpSignalerInput::Request(req, now) => self.handle_request(req, now),
            HttpSignalerInput::Timeout(timeout) => self.handle_timeout(timeout),
        }
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl HttpSignaler {
    fn handle_request(
        &mut self,
        request: HttpSignalerRequest,
        now: Instant,
    ) -> Result<(), HttpSignalerError> {
        let segments = request
            .request
            .uri()
            .path()
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>();

        match segments.as_slice() {
            ["v1", "join"] => self.handle_join(&request)?,
            ["v1", "join", network_id] => self.handle_join_network(&request, network_id, now)?,
            _ => self
                .output
                .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                    addr: request.addr,
                    response: HttpSignaler::empty(StatusCode::NOT_FOUND)?,
                })),
        };
        Ok(())
    }

    fn handle_timeout(&mut self, timeout: Instant) -> Result<(), HttpSignalerError> {
        Ok(())
    }

    fn handle_join(&mut self, request: &HttpSignalerRequest) -> Result<(), HttpSignalerError> {
        let method = request.request.method();

        self.output
            .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                addr: request.addr,
                response: HttpSignaler::empty(if matches!(method, &Method::GET) {
                    StatusCode::OK
                } else {
                    StatusCode::METHOD_NOT_ALLOWED
                })?,
            }));

        Ok(())
    }

    fn handle_join_network(
        &mut self,
        request: &HttpSignalerRequest,
        network: &str,
        now: Instant,
    ) -> Result<(), HttpSignalerError> {
        let method = request.request.method();

        if !matches!(method, &Method::POST) {
            self.output
                .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                    addr: request.addr,
                    response: HttpSignaler::empty(StatusCode::METHOD_NOT_ALLOWED)?,
                }));

            return Ok(());
        }

        // TODO: maybe verify claims?

        let pending = Pending {
            timeout: now + Duration::from_secs(30),
            network_id: network.into(),
            offer: request.request.body().clone(),
        };

        self.pending.insert(network.into(), pending);

        // TODO: rest of this

        Ok(())
    }

    fn empty(status: StatusCode) -> http::Result<Response<Box<str>>> {
        Response::builder()
            .status(status)
            .header(CONTENT_LENGTH, 0)
            .body("".into())
    }
}
