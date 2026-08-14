use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpSignalerError {
    #[error("Http Error: {0}")]
    HttpError(#[from] http::Error),
}
