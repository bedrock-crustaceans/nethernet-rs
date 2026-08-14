//! Encryption and decryption utilities for LAN discovery packets.
//!
//! Discovery packets are encrypted using AES-ECB with PKCS7 padding,
//! and authenticated with HMAC-SHA256 checksums.

use crate::error::{NethernetError, Result};
use aes::Aes256;
use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// The encryption key used for packets transmitted during LAN discovery.
/// This is the SHA-256 hash of 0xdeadbeef (also referenced as Application ID).
/// Computed once and cached for all subsequent calls.
static ENCRYPTION_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut hasher = Sha256::new();
    hasher.update(0xdeadbeef_u64.to_le_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
});

/// Pre-initialized AES-256 cipher for encryption and decryption.
///
/// The key is passed as `&[u8; 32]` rather than `&[u8]`: `cipher` 0.5 sizes `Key`
/// as a `hybrid-array` `Array<u8, U32>`, which converts from a fixed-size array
/// reference but not from an unsized slice.
static CIPHER: LazyLock<Aes256> = LazyLock::new(|| Aes256::new((&*ENCRYPTION_KEY).into()));

/// Pre-initialized HMAC-SHA256 state to avoid re-computing the key schedule.
static HMAC_STATE: LazyLock<Hmac<Sha256>> = LazyLock::new(|| {
    <Hmac<Sha256> as KeyInit>::new_from_slice(ENCRYPTION_KEY.as_slice())
        .expect("HMAC can take key of any size")
});

/// Encrypts the given buffer in-place using AES-256 in ECB mode with PKCS#7 padding.
///
/// The buffer is resized to include PKCS#7 padding (multiple of 16 bytes) before encryption.
pub(crate) fn encrypt(buf: &mut Vec<u8>) -> Result<()> {
    // Apply PKCS7 padding
    let block_size = 16;
    let data_len = buf.len();
    let padding_len = block_size - (data_len % block_size);
    buf.resize(data_len + padding_len, padding_len as u8);

    // Encrypt blocks in-place
    // Safety: GenericArray/Block is repr(transparent) over [u8; 16]
    let blocks = unsafe {
        std::slice::from_raw_parts_mut(
            buf.as_mut_ptr() as *mut Block<Aes256>,
            buf.len() / block_size,
        )
    };
    CIPHER.encrypt_blocks(blocks);

    Ok(())
}

/// Decrypts the given buffer in-place using AES-256 in ECB mode and removes PKCS#7 padding.
///
/// Returns an error if the input length is zero or not a multiple of 16, or if PKCS#7 padding is invalid.
pub(crate) fn decrypt(buf: &mut Vec<u8>) -> Result<()> {
    if buf.is_empty() || buf.len() % 16 != 0 {
        return Err(NethernetError::Other(
            "Invalid encrypted data length".to_string(),
        ));
    }

    // Decrypt blocks in-place
    // Safety: GenericArray/Block is repr(transparent) over [u8; 16]
    let blocks = unsafe {
        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut Block<Aes256>, buf.len() / 16)
    };
    CIPHER.decrypt_blocks(blocks);

    // Remove PKCS7 padding
    if let Some(&padding_len) = buf.last() {
        if padding_len > 0 && padding_len <= 16 {
            let data_len = buf.len();
            if data_len >= padding_len as usize {
                // Verify padding (constant-time)
                let padding_start = data_len - padding_len as usize;
                let mut mismatched: u8 = 0;
                for &byte in &buf[padding_start..] {
                    mismatched |= byte ^ padding_len;
                }
                if mismatched == 0 {
                    buf.truncate(padding_start);
                    return Ok(());
                }
            }
        }
    }

    Err(NethernetError::Other("Invalid padding".to_string()))
}

/// Computes an HMAC-SHA256 checksum of the provided data using the module's static encryption key.
///
/// Returns a 32-byte HMAC-SHA256 value.
pub(crate) fn compute_checksum(data: &[u8]) -> [u8; 32] {
    let mut mac = HMAC_STATE.clone();
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Verifies that `data` matches the given HMAC-SHA256 `expected` checksum using the module's encryption key.
///
/// # Returns
///
/// `true` if `expected` matches the HMAC-SHA256 of `data`, `false` otherwise.
pub(crate) fn verify_checksum(data: &[u8], expected: &[u8; 32]) -> bool {
    let mut mac = HMAC_STATE.clone();
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Hello, NetherNet!";
        let mut buf = data.to_vec();
        encrypt(&mut buf).unwrap();
        decrypt(&mut buf).unwrap();
        assert_eq!(data.as_slice(), buf.as_slice());
    }

    #[test]
    fn test_checksum() {
        let data = b"Test data for checksum";
        let checksum = compute_checksum(data);
        assert!(verify_checksum(data, &checksum));

        let wrong_checksum = [0u8; 32];
        assert!(!verify_checksum(data, &wrong_checksum));
    }
}
