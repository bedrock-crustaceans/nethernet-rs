pub mod input;
pub mod output;
pub mod error;

use crate::sans::Sans;
use crate::signaling::http::error::HttpSignalerError;
use crate::signaling::http::input::HttpSignalerInput;
use crate::signaling::http::output::HttpSignalerOutput;

pub struct HttpSignaler {
    
}

impl Sans for HttpSignaler {
    type Input = HttpSignalerInput;
    type Output = HttpSignalerOutput;
    type Error = HttpSignalerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        None
    }
}