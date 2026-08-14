pub mod error;
pub mod input;
pub mod output;

use crate::sans::Sans;
use crate::signaling::lan::error::LanSignalerError;
use crate::signaling::lan::input::LanSignalerInput;
use crate::signaling::lan::output::LanSignalerOutput;

pub struct LanSignaler {}

impl Sans for LanSignaler {
    type Input = LanSignalerInput;
    type Output = LanSignalerOutput;
    type Error = LanSignalerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        None
    }
}
