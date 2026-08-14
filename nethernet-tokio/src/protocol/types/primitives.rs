use crate::protocol::constants::MAX_BYTES;
use std::io::{self, Read, Write};

/// Reads a single byte from the given reader.
pub fn read_u8(r: &mut dyn Read) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// Writes a single byte to the provided writer.
pub fn write_u8(w: &mut dyn Write, value: u8) -> io::Result<()> {
    w.write_all(&[value])
}

/// Read a 32-bit little-endian signed integer from a reader.
pub fn read_i32_le(r: &mut dyn Read) -> io::Result<i32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(i32::from_le_bytes(buf))
}

/// Writes a 32-bit signed integer to the writer in little-endian byte order.
pub fn write_i32_le(w: &mut dyn Write, value: i32) -> io::Result<()> {
    w.write_all(&value.to_le_bytes())
}

/// Reads a length-prefixed byte array using a custom length reader.
pub fn read_bytes<L: Into<u64>>(
    r: &mut dyn Read,
    read_length: impl Fn(&mut dyn Read) -> io::Result<L>,
) -> io::Result<Vec<u8>> {
    let length: u64 = read_length(r)?.into();

    // Validate length before allocation to prevent OOM attacks
    if length > MAX_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "byte array length {} exceeds maximum allowed {}",
                length, MAX_BYTES
            ),
        ));
    }

    let buf_size: usize = length.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "length too large for buffer allocation",
        )
    })?;
    let mut buf = vec![0u8; buf_size];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Reads a length-prefixed byte array where the length prefix is a `u8`.
pub fn read_bytes_u8(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    read_bytes(r, |r| read_u8(r))
}

/// Reads a length-prefixed byte array where the length is encoded as a 32-bit little-endian integer.
pub fn read_bytes_u32(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    use super::U32LE;
    let length = U32LE::read(r)?.0;

    // Length already consumed by U32LE::read above, so the closure passed to read_bytes
    // intentionally ignores its reader parameter and returns the pre-read length.
    read_bytes(r, |_| Ok(length))
}

/// Writes `data` prefixed by its length using the provided `write_length` closure.
pub fn write_bytes<L: TryFrom<usize>>(
    w: &mut dyn Write,
    data: &[u8],
    write_length: impl Fn(&mut dyn Write, L) -> io::Result<()>,
) -> io::Result<()>
where
    <L as TryFrom<usize>>::Error: std::fmt::Debug,
{
    if data.len() > MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "data length {} exceeds maximum allowed {}",
                data.len(),
                MAX_BYTES
            ),
        ));
    }
    let length = L::try_from(data.len()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("length conversion failed: {:?}", e),
        )
    })?;
    write_length(w, length)?;
    w.write_all(data)?;
    Ok(())
}

/// Writes a length-prefixed byte array using a single-byte (u8) length prefix.
pub fn write_bytes_u8(w: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    write_bytes(w, data, |w, len: u8| write_u8(w, len))
}

/// Writes a little-endian u32 length prefix followed by the provided byte slice.
pub fn write_bytes_u32(w: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    use super::U32LE;
    write_bytes(w, data, |w, len: u32| U32LE(len).write(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn u8_roundtrip() {
        let value = 0x42u8;
        let mut buf = Vec::new();
        write_u8(&mut buf, value).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = read_u8(&mut cursor).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn bytes_u8_roundtrip() {
        let data = vec![1, 2, 3, 4, 5];
        let mut buf = Vec::new();
        write_bytes_u8(&mut buf, &data).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = read_bytes_u8(&mut cursor).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn bytes_u32_roundtrip() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut buf = Vec::new();
        write_bytes_u32(&mut buf, &data).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = read_bytes_u32(&mut cursor).unwrap();
        assert_eq!(decoded, data);
    }
}
