use std::io::{self, Read, Write};

/// Little-endian 16-bit unsigned integer helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U16LE(pub u16);

impl U16LE {
    /// Reads a little-endian 16-bit unsigned integer from the given reader.
    ///
    /// On success returns a `U16LE` wrapping the decoded `u16`. Propagates any I/O error encountered while reading.
    pub fn read<R: Read + ?Sized>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf)?;
        Ok(U16LE(u16::from_le_bytes(buf)))
    }

    /// Writes the wrapped integer to the provided writer in little-endian byte order.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

/// Little-endian 32-bit unsigned integer helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32LE(pub u32);

impl U32LE {
    /// Reads a 32-bit little-endian unsigned integer from a reader.
    pub fn read<R: Read + ?Sized>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf)?;
        Ok(U32LE(u32::from_le_bytes(buf)))
    }

    /// Writes the wrapped integer to the provided writer in little-endian byte order.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

/// Little-endian 64-bit unsigned integer helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U64LE(pub u64);

impl U64LE {
    /// Reads a little-endian 64-bit unsigned integer from a reader.
    pub fn read<R: Read + ?Sized>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        Ok(U64LE(u64::from_le_bytes(buf)))
    }

    /// Writes the wrapped integer to the provided writer in little-endian byte order.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.0.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn u16le_roundtrip() {
        let value = U16LE(0xABCD);
        let mut buf = Vec::new();
        value.write(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = U16LE::read(&mut cursor).unwrap();
        assert_eq!(decoded.0, value.0);
    }

    #[test]
    fn u32le_roundtrip() {
        let value = U32LE(0x12345678);
        let mut buf = Vec::new();
        value.write(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = U32LE::read(&mut cursor).unwrap();
        assert_eq!(decoded.0, value.0);
    }

    #[test]
    fn u64le_roundtrip() {
        let value = U64LE(0x123456789ABCDEF0);
        let mut buf = Vec::new();
        value.write(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = U64LE::read(&mut cursor).unwrap();
        assert_eq!(decoded.0, value.0);
    }

    #[test]
    fn u16le_edge_cases() {
        for &val in &[0, u16::MAX] {
            let value = U16LE(val);
            let mut buf = Vec::new();
            value.write(&mut buf).unwrap();
            let mut cursor = Cursor::new(buf);
            let decoded = U16LE::read(&mut cursor).unwrap();
            assert_eq!(decoded.0, val);
        }
    }

    #[test]
    fn u32le_edge_cases() {
        for &val in &[0, u32::MAX] {
            let value = U32LE(val);
            let mut buf = Vec::new();
            value.write(&mut buf).unwrap();
            let mut cursor = Cursor::new(buf);
            let decoded = U32LE::read(&mut cursor).unwrap();
            assert_eq!(decoded.0, val);
        }
    }

    #[test]
    fn u64le_edge_cases() {
        for &val in &[0, u64::MAX] {
            let value = U64LE(val);
            let mut buf = Vec::new();
            value.write(&mut buf).unwrap();
            let mut cursor = Cursor::new(buf);
            let decoded = U64LE::read(&mut cursor).unwrap();
            assert_eq!(decoded.0, val);
        }
    }
}
