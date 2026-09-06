use thiserror::Error;

/// Errors produced while encoding or decoding NetherNet wire-format data.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("message too large: exceeds maximum size of {0} bytes")]
    MessageTooLarge(usize),

    #[error("message parse error: {0}")]
    MessageParse(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
