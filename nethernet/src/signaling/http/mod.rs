pub mod error;
pub mod input;
pub mod output;

use crate::sans::Sans;
use crate::signaling::http::error::HttpSignalerError;
use crate::signaling::http::input::{HttpSignalerInput, HttpSignalerRequest};
use crate::signaling::http::output::{HttpSignalerOutput, HttpSignalerResponse};
use crate::signaling::signal::{Signal, SignalType};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Response, StatusCode};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Content type used for SDP offer/answer bodies, per the NetherNet HTTP signaling spec.
const SDP_CONTENT_TYPE: &str = "application/sdp";

/// How long a join POST is held open awaiting an answer before it is failed with a timeout.
/// The spec does not mandate a value; the client sends exactly one request and does not
/// retry, so this only bounds how long a stalled host can keep the connection hanging.
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);

struct PendingJoin {
    addr: u64,
    connection_id: u64,
    timeout: Instant,
}

/// Sans-IO implementation of the NetherNet HTTP signaling protocol, per the
/// [partner onboarding guide](https://github.com/Mojang/bedrock-protocol-docs/blob/main/additional_docs/NetherNetOnboardingGuide.md).
///
/// A client `GET`s `/v1/join` as a capability check, then `POST`s a *complete* SDP
/// offer (NetherNet's HTTP signaling always uses full ICE — every candidate is already
/// gathered and embedded in the SDP, never trickled) to `/v1/join/{networkId}`, where
/// `networkId` is the *client's own* `NetworkID`. The request is held open until the
/// driving application answers via [`HttpSignalerInput::Signal`] — [`SignalType::Answer`]
/// completes it with `200 OK` and the answer SDP, [`SignalType::Error`] rejects it with
/// `403 Forbidden` (e.g. after rejecting the offer's identity assertion) — or until
/// [`JOIN_TIMEOUT`] elapses, whichever comes first.
///
/// Because full ICE means every candidate is already in the offer/answer, there is no
/// separate candidate-trickling exchange over this transport: [`SignalType::Candidate`]
/// signals are not meaningful here and are ignored.
///
/// This type performs no I/O itself: feed it requests and timeouts via [`Sans::handle`]
/// and drain responses/signals via [`Sans::poll`].
pub struct HttpSignaler {
    next_connection_id: u64,
    /// Pending joins, keyed by the client's NetworkID. A legitimate client has at most
    /// one connection attempt in flight at a time.
    pending: HashMap<u64, PendingJoin>,
    output: VecDeque<HttpSignalerOutput>,
}

impl Default for HttpSignaler {
    fn default() -> Self {
        Self::new()
    }
}

impl Sans for HttpSignaler {
    type Input = HttpSignalerInput;
    type Output = HttpSignalerOutput;
    type Error = HttpSignalerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            HttpSignalerInput::Request(req, now) => self.handle_request(req, now),
            HttpSignalerInput::Signal(signal, now) => self.handle_signal(signal, now),
            HttpSignalerInput::Timeout(now) => self.handle_timeout(now),
        }
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl HttpSignaler {
    pub fn new() -> Self {
        Self {
            next_connection_id: 1,
            pending: HashMap::new(),
            output: VecDeque::new(),
        }
    }

    fn handle_request(
        &mut self,
        request: HttpSignalerRequest,
        now: Instant,
    ) -> Result<(), HttpSignalerError> {
        let path = request.request.uri().path().to_string();
        let segments = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>();

        match segments.as_slice() {
            ["v1", "join"] => self.handle_join(&request)?,
            ["v1", "join", network_id] => self.handle_join_network(&request, network_id, now)?,
            _ => self.respond(request.addr, StatusCode::NOT_FOUND)?,
        };
        Ok(())
    }

    /// Handles an answer or rejection produced locally (by whichever host is driving
    /// this signaler) that needs to complete a pending join.
    fn handle_signal(&mut self, signal: Signal, _now: Instant) -> Result<(), HttpSignalerError> {
        match signal.signal_type {
            SignalType::Answer => self.handle_answer(signal),
            SignalType::Error => self.handle_error(signal),
            // Full ICE means candidates never trickle over this transport, and the
            // host never originates an offer here; nothing to relay.
            SignalType::Offer | SignalType::Candidate => Ok(()),
        }
    }

    /// Completes a pending join with the host's answer SDP, if that join is still waiting.
    fn handle_answer(&mut self, signal: Signal) -> Result<(), HttpSignalerError> {
        let Some(pending) = self.take_pending(&signal) else {
            return Ok(());
        };
        self.respond_with_sdp(pending.addr, StatusCode::OK, signal.data.into())
    }

    /// Rejects a pending join (e.g. the host refused the offer's identity assertion).
    fn handle_error(&mut self, signal: Signal) -> Result<(), HttpSignalerError> {
        let Some(pending) = self.take_pending(&signal) else {
            return Ok(());
        };
        self.respond(pending.addr, StatusCode::FORBIDDEN)
    }

    /// Removes and returns the pending join for `signal`'s network ID, but only if it
    /// is still waiting on exactly the connection this signal answers.
    fn take_pending(&mut self, signal: &Signal) -> Option<PendingJoin> {
        let matches = self
            .pending
            .get(&signal.network_id)
            .is_some_and(|pending| pending.connection_id == signal.connection_id);
        if matches {
            self.pending.remove(&signal.network_id)
        } else {
            None
        }
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), HttpSignalerError> {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.timeout <= now)
            .map(|(network_id, _)| *network_id)
            .collect();

        for network_id in expired {
            if let Some(pending) = self.pending.remove(&network_id) {
                self.respond(pending.addr, StatusCode::REQUEST_TIMEOUT)?;
            }
        }

        Ok(())
    }

    fn handle_join(&mut self, request: &HttpSignalerRequest) -> Result<(), HttpSignalerError> {
        let method = request.request.method();

        self.respond(
            request.addr,
            if matches!(method, &Method::GET) {
                StatusCode::OK
            } else {
                StatusCode::METHOD_NOT_ALLOWED
            },
        )
    }

    fn handle_join_network(
        &mut self,
        request: &HttpSignalerRequest,
        network_id: &str,
        now: Instant,
    ) -> Result<(), HttpSignalerError> {
        if !matches!(request.request.method(), &Method::POST) {
            return self.respond(request.addr, StatusCode::METHOD_NOT_ALLOWED);
        }

        let Ok(network_id) = network_id.parse::<u64>() else {
            return self.respond(request.addr, StatusCode::BAD_REQUEST);
        };

        // A legitimate client sends exactly one signaling request per connection
        // attempt and never retries; a second one while the first is still pending
        // means the first has been superseded, so fail it outright.
        if let Some(superseded) = self.pending.remove(&network_id) {
            self.respond(superseded.addr, StatusCode::CONFLICT)?;
        }

        let connection_id = self.next_connection_id;
        self.next_connection_id += 1;

        let offer = request.request.body().clone();
        self.pending.insert(
            network_id,
            PendingJoin {
                addr: request.addr,
                connection_id,
                timeout: now + JOIN_TIMEOUT,
            },
        );

        self.output
            .push_back(HttpSignalerOutput::Signal(Signal::offer(
                connection_id,
                offer.into(),
                network_id,
            )));
        self.output
            .push_back(HttpSignalerOutput::Timeout(JOIN_TIMEOUT));

        Ok(())
    }

    fn respond(&mut self, addr: u64, status: StatusCode) -> Result<(), HttpSignalerError> {
        self.output
            .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                addr,
                response: Self::empty(status)?,
            }));
        Ok(())
    }

    fn respond_with_sdp(
        &mut self,
        addr: u64,
        status: StatusCode,
        body: Box<str>,
    ) -> Result<(), HttpSignalerError> {
        self.output
            .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                addr,
                response: Self::sdp_body(status, body)?,
            }));
        Ok(())
    }

    fn empty(status: StatusCode) -> http::Result<Response<Box<str>>> {
        Response::builder()
            .status(status)
            .header(CONTENT_LENGTH, 0)
            .body("".into())
    }

    fn sdp_body(status: StatusCode, body: Box<str>) -> http::Result<Response<Box<str>>> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, SDP_CONTENT_TYPE)
            .header(CONTENT_LENGTH, body.len())
            .body(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn req(addr: u64, method: Method, uri: &str, body: &str) -> HttpSignalerRequest {
        HttpSignalerRequest {
            addr,
            request: Request::builder()
                .method(method)
                .uri(uri)
                .body(body.into())
                .unwrap(),
        }
    }

    #[test]
    fn join_health_check() {
        let mut s = HttpSignaler::new();
        let now = Instant::now();

        s.handle(HttpSignalerInput::Request(
            req(1, Method::GET, "/v1/join", ""),
            now,
        ))
        .unwrap();
        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 1);
        assert_eq!(resp.response.status(), StatusCode::OK);
        assert!(s.poll().is_none());
    }

    #[test]
    fn join_network_then_answer() {
        let mut s = HttpSignaler::new();
        let now = Instant::now();

        s.handle(HttpSignalerInput::Request(
            req(1, Method::POST, "/v1/join/7", "offer-sdp"),
            now,
        ))
        .unwrap();

        // The join is held open: an offer signal is emitted, plus a timeout request,
        // but nothing is emitted directly back to the requester yet.
        let HttpSignalerOutput::Signal(offer) = s.poll().unwrap() else {
            panic!("expected offer signal");
        };
        assert_eq!(offer.signal_type, SignalType::Offer);
        assert_eq!(offer.network_id, 7);
        assert_eq!(offer.data, "offer-sdp");
        let connection_id = offer.connection_id;

        assert!(matches!(s.poll(), Some(HttpSignalerOutput::Timeout(_))));
        assert!(s.poll().is_none());

        // The host answers; the original POST completes with the answer SDP.
        s.handle(HttpSignalerInput::Signal(
            Signal::answer(connection_id, "answer-sdp".to_string(), 7),
            now,
        ))
        .unwrap();

        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 1);
        assert_eq!(resp.response.status(), StatusCode::OK);
        assert_eq!(
            resp.response.headers().get(CONTENT_TYPE).unwrap(),
            SDP_CONTENT_TYPE
        );
        assert_eq!(resp.response.body().as_ref(), "answer-sdp");
        assert!(s.poll().is_none());
    }

    #[test]
    fn join_network_then_error() {
        let mut s = HttpSignaler::new();
        let now = Instant::now();

        s.handle(HttpSignalerInput::Request(
            req(1, Method::POST, "/v1/join/7", "offer-sdp"),
            now,
        ))
        .unwrap();
        let HttpSignalerOutput::Signal(offer) = s.poll().unwrap() else {
            panic!("expected offer signal");
        };
        let connection_id = offer.connection_id;
        s.poll(); // timeout request

        s.handle(HttpSignalerInput::Signal(
            Signal::error(
                connection_id,
                crate::signaling::signal::SignalErrorCode::DestinationNotLoggedIn,
                7,
            ),
            now,
        ))
        .unwrap();

        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 1);
        assert_eq!(resp.response.status(), StatusCode::FORBIDDEN);
        assert!(s.poll().is_none());
    }

    #[test]
    fn join_timeout() {
        let mut s = HttpSignaler::new();
        let now = Instant::now();

        s.handle(HttpSignalerInput::Request(
            req(1, Method::POST, "/v1/join/7", "offer-sdp"),
            now,
        ))
        .unwrap();
        s.poll(); // offer signal
        s.poll(); // timeout request

        s.handle(HttpSignalerInput::Timeout(now + JOIN_TIMEOUT))
            .unwrap();

        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 1);
        assert_eq!(resp.response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(s.poll().is_none());
    }

    #[test]
    fn superseded_join_is_failed_with_conflict() {
        let mut s = HttpSignaler::new();
        let now = Instant::now();

        s.handle(HttpSignalerInput::Request(
            req(1, Method::POST, "/v1/join/7", "offer-sdp-1"),
            now,
        ))
        .unwrap();
        s.poll(); // offer signal
        s.poll(); // timeout request

        s.handle(HttpSignalerInput::Request(
            req(2, Method::POST, "/v1/join/7", "offer-sdp-2"),
            now,
        ))
        .unwrap();

        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 1);
        assert_eq!(resp.response.status(), StatusCode::CONFLICT);

        let HttpSignalerOutput::Signal(offer) = s.poll().unwrap() else {
            panic!("expected offer signal");
        };
        assert_eq!(offer.data, "offer-sdp-2");
        assert!(matches!(s.poll(), Some(HttpSignalerOutput::Timeout(_))));
        assert!(s.poll().is_none());
    }

    #[test]
    fn unknown_route_is_404() {
        let mut s = HttpSignaler::new();
        s.handle(HttpSignalerInput::Request(
            req(1, Method::GET, "/nope", ""),
            Instant::now(),
        ))
        .unwrap();
        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.response.status(), StatusCode::NOT_FOUND);
    }
}
