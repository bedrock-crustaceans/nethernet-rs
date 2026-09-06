use crate::protocol::error::ProtocolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LanSignalerError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("No known address for network ID: {0}")]
    UnknownNetworkId(u64),
}
