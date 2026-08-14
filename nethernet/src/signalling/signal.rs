pub enum Signal {
    Offer { sdp: String },
    Answer { sdp: String },
    Candidate { candidate: String },
    Error { code: u32 },
}