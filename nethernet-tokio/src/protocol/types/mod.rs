//! Low-level on-the-wire primitives and helpers for the NetherNet protocol.
//!
//! This module defines basic integer formats, byte array helpers, and other
//! encodings used by discovery and protocol packets.

mod ints;
mod primitives;

pub use ints::{U16LE, U32LE, U64LE};
pub use primitives::{
    read_bytes, read_bytes_u8, read_bytes_u32, read_i32_le, read_u8, write_bytes, write_bytes_u8,
    write_bytes_u32, write_i32_le, write_u8,
};
