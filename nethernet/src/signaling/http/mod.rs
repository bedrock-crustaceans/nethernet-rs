pub mod error;
pub mod input;
pub mod output;

use crate::sans::Sans;
use crate::signaling::http::error::HttpSignalerError;
use crate::signaling::http::input::{HttpSignalerInput, HttpSignalerRequest};
use crate::signaling::http::output::{HttpSignalerOutput, HttpSignalerResponse};
use crate::signaling::signal::{Signal, SignalType};
use http::header::CONTENT_LENGTH;
use http::{Method, Response, StatusCode};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// How long a join POST is held open awaiting an answer before it is failed with a timeout.
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a candidates long-poll GET is held open awaiting a new candidate before it
/// is completed with an empty (no new candidates) response.
const CANDIDATES_POLL_TIMEOUT: Duration = Duration::from_secs(25);

struct PendingJoin {
    addr: u64,
    network_id: u64,
    timeout: Instant,
}

struct PendingCandidatesGet {
    addr: u64,
    since: usize,
    timeout: Instant,
}

struct ConnectionState {
    network_id: u64,
    /// Candidates trickled by the host, in the order they were produced.
    host_candidates: Vec<Box<str>>,
    /// An outstanding long-poll GET awaiting candidates past `since`.
    pending_get: Option<PendingCandidatesGet>,
}

/// Sans-IO HTTP signaler.
///
/// Models a rendezvous service: a client `POST`s an SDP offer to `/v1/join/{network_id}`
/// naming the host it wants to connect to; the request is held open until the host
/// (driving this same signaler) answers via [`HttpSignalerInput::Signal`], at which point
/// the response completes with the answer SDP. Trickled ICE candidates flow through
/// `/v1/candidates/{network_id}/{connection_id}` in both directions: the client `POST`s
/// its own candidates, and long-polls with `GET ...?since=N` for candidates trickled by
/// the host.
///
/// This type performs no I/O itself: feed it requests and timeouts via [`Sans::handle`]
/// and drain responses/signals via [`Sans::poll`].
pub struct HttpSignaler {
    next_connection_id: u64,
    pending_joins: HashMap<u64, PendingJoin>,
    connections: HashMap<u64, ConnectionState>,
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
            pending_joins: HashMap::new(),
            connections: HashMap::new(),
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
            ["v1", "candidates", network_id, connection_id] => {
                self.handle_candidates(&request, network_id, connection_id, now)?
            }
            _ => self.respond(request.addr, StatusCode::NOT_FOUND)?,
        };
        Ok(())
    }

    /// Handles answers and trickled candidates produced locally (by whichever host is
    /// driving this signaler) that need to be relayed back to the waiting client.
    fn handle_signal(&mut self, signal: Signal, _now: Instant) -> Result<(), HttpSignalerError> {
        match signal.signal_type {
            SignalType::Answer => self.handle_answer(signal),
            SignalType::Candidate => self.handle_outbound_candidate(signal),
            // Offers and errors are not meaningful for the host to originate over this
            // transport; nothing to relay.
            SignalType::Offer | SignalType::Error => Ok(()),
        }
    }

    /// Completes a pending join with the host's answer SDP, if that join is still waiting.
    fn handle_answer(&mut self, signal: Signal) -> Result<(), HttpSignalerError> {
        let Some(pending) = self.pending_joins.get(&signal.connection_id) else {
            // No longer pending (already timed out, or an unknown connection ID).
            return Ok(());
        };
        if pending.network_id != signal.network_id {
            // Answer names a different host than the one this connection joined; ignore.
            return Ok(());
        }
        let pending = self
            .pending_joins
            .remove(&signal.connection_id)
            .expect("presence checked above");

        self.respond_with_body(pending.addr, StatusCode::OK, signal.data.into())
    }

    /// Records a candidate trickled by the host, completing an outstanding long-poll
    /// GET for it if one is waiting.
    fn handle_outbound_candidate(&mut self, signal: Signal) -> Result<(), HttpSignalerError> {
        let Some(state) = self.connections.get_mut(&signal.connection_id) else {
            return Ok(());
        };
        if state.network_id != signal.network_id {
            // Candidate names a different host than the one this connection joined; ignore.
            return Ok(());
        }

        state.host_candidates.push(signal.data.into());

        if let Some(pending) = state.pending_get.take() {
            let body = state.host_candidates[pending.since..].join("\n");
            self.output
                .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                    addr: pending.addr,
                    response: Self::body(StatusCode::OK, body.into())?,
                }));
        }

        Ok(())
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), HttpSignalerError> {
        let expired_joins: Vec<u64> = self
            .pending_joins
            .iter()
            .filter(|(_, pending)| pending.timeout <= now)
            .map(|(id, _)| *id)
            .collect();

        for connection_id in expired_joins {
            if let Some(pending) = self.pending_joins.remove(&connection_id) {
                self.respond(pending.addr, StatusCode::REQUEST_TIMEOUT)?;
            }
            // No answer arrived in time; the connection never got established.
            self.connections.remove(&connection_id);
        }

        let mut expired_responses = Vec::new();
        for state in self.connections.values_mut() {
            if state.pending_get.as_ref().is_some_and(|p| p.timeout <= now)
                && let Some(pending) = state.pending_get.take()
            {
                expired_responses.push(pending.addr);
            }
        }
        for addr in expired_responses {
            self.respond(addr, StatusCode::NO_CONTENT)?;
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

        let connection_id = self.next_connection_id;
        self.next_connection_id += 1;

        let offer = request.request.body().clone();

        self.pending_joins.insert(
            connection_id,
            PendingJoin {
                addr: request.addr,
                network_id,
                timeout: now + JOIN_TIMEOUT,
            },
        );
        self.connections.insert(
            connection_id,
            ConnectionState {
                network_id,
                host_candidates: Vec::new(),
                pending_get: None,
            },
        );

        self.output.push_back(HttpSignalerOutput::Signal(
            Signal::offer(connection_id, offer.into(), network_id),
        ));
        self.output
            .push_back(HttpSignalerOutput::Timeout(JOIN_TIMEOUT));

        Ok(())
    }

    fn handle_candidates(
        &mut self,
        request: &HttpSignalerRequest,
        network_id: &str,
        connection_id: &str,
        now: Instant,
    ) -> Result<(), HttpSignalerError> {
        let (Ok(network_id), Ok(connection_id)) =
            (network_id.parse::<u64>(), connection_id.parse::<u64>())
        else {
            return self.respond(request.addr, StatusCode::BAD_REQUEST);
        };

        let matches_connection = self
            .connections
            .get(&connection_id)
            .is_some_and(|state| state.network_id == network_id);
        if !matches_connection {
            return self.respond(request.addr, StatusCode::NOT_FOUND);
        }

        match *request.request.method() {
            Method::POST => {
                let candidate = request.request.body().clone();
                self.output.push_back(HttpSignalerOutput::Signal(
                    Signal::candidate(connection_id, candidate.into(), network_id),
                ));
                self.respond(request.addr, StatusCode::ACCEPTED)
            }
            Method::GET => {
                let since = Self::parse_since(request.request.uri().query());
                let state = self
                    .connections
                    .get_mut(&connection_id)
                    .expect("presence checked above");

                if since < state.host_candidates.len() {
                    let body = state.host_candidates[since..].join("\n");
                    self.respond_with_body(request.addr, StatusCode::OK, body.into())
                } else {
                    state.pending_get = Some(PendingCandidatesGet {
                        addr: request.addr,
                        since,
                        timeout: now + CANDIDATES_POLL_TIMEOUT,
                    });
                    self.output
                        .push_back(HttpSignalerOutput::Timeout(CANDIDATES_POLL_TIMEOUT));
                    Ok(())
                }
            }
            _ => self.respond(request.addr, StatusCode::METHOD_NOT_ALLOWED),
        }
    }

    fn parse_since(query: Option<&str>) -> usize {
        query
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("since=")))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn respond(&mut self, addr: u64, status: StatusCode) -> Result<(), HttpSignalerError> {
        self.output
            .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                addr,
                response: Self::empty(status)?,
            }));
        Ok(())
    }

    fn respond_with_body(
        &mut self,
        addr: u64,
        status: StatusCode,
        body: Box<str>,
    ) -> Result<(), HttpSignalerError> {
        self.output
            .push_back(HttpSignalerOutput::Response(HttpSignalerResponse {
                addr,
                response: Self::body(status, body)?,
            }));
        Ok(())
    }

    fn empty(status: StatusCode) -> http::Result<Response<Box<str>>> {
        Response::builder()
            .status(status)
            .header(CONTENT_LENGTH, 0)
            .body("".into())
    }

    fn body(status: StatusCode, body: Box<str>) -> http::Result<Response<Box<str>>> {
        Response::builder()
            .status(status)
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
        assert_eq!(resp.response.body().as_ref(), "answer-sdp");
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
    fn candidates_relay_both_directions() {
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

        // Client posts its own trickled candidate.
        s.handle(HttpSignalerInput::Request(
            req(
                2,
                Method::POST,
                &format!("/v1/candidates/7/{connection_id}"),
                "client-candidate",
            ),
            now,
        ))
        .unwrap();
        let HttpSignalerOutput::Signal(candidate) = s.poll().unwrap() else {
            panic!("expected candidate signal");
        };
        assert_eq!(candidate.signal_type, SignalType::Candidate);
        assert_eq!(candidate.connection_id, connection_id);
        assert_eq!(candidate.data, "client-candidate");
        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 2);
        assert_eq!(resp.response.status(), StatusCode::ACCEPTED);
        assert!(s.poll().is_none());

        // Client long-polls for host candidates; none yet, so it's held open.
        s.handle(HttpSignalerInput::Request(
            req(
                3,
                Method::GET,
                &format!("/v1/candidates/7/{connection_id}"),
                "",
            ),
            now,
        ))
        .unwrap();
        assert!(matches!(s.poll(), Some(HttpSignalerOutput::Timeout(_))));
        assert!(s.poll().is_none());

        // Host trickles a candidate back; the held GET completes immediately.
        s.handle(HttpSignalerInput::Signal(
            Signal::candidate(connection_id, "host-candidate".to_string(), 7),
            now,
        ))
        .unwrap();
        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 3);
        assert_eq!(resp.response.status(), StatusCode::OK);
        assert_eq!(resp.response.body().as_ref(), "host-candidate");
        assert!(s.poll().is_none());

        // A subsequent poll for the same cursor gets nothing new until timeout.
        s.handle(HttpSignalerInput::Request(
            req(
                4,
                Method::GET,
                &format!("/v1/candidates/7/{connection_id}?since=1"),
                "",
            ),
            now,
        ))
        .unwrap();
        assert!(matches!(s.poll(), Some(HttpSignalerOutput::Timeout(_))));
        assert!(s.poll().is_none());

        s.handle(HttpSignalerInput::Timeout(
            now + CANDIDATES_POLL_TIMEOUT,
        ))
        .unwrap();
        let HttpSignalerOutput::Response(resp) = s.poll().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(resp.addr, 4);
        assert_eq!(resp.response.status(), StatusCode::NO_CONTENT);
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
