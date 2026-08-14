use crate::error::{NethernetError, Result};
use crate::protocol::constants::MAX_MESSAGE_SIZE;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Message segment
/// First byte contains segment count, remainder contains data
#[derive(Debug, Clone)]
pub struct MessageSegment {
    /// Remaining segment count (0 = last segment)
    pub remaining_segments: u8,
    /// Segment data
    pub data: Bytes,
}

impl MessageSegment {
    /// Creates a [`MessageSegment`] with the given remaining segment count and payload.
    pub fn new(remaining_segments: u8, data: Bytes) -> Self {
        Self {
            remaining_segments,
            data,
        }
    }

    /// Serialize the segment into a byte buffer where the first byte is the remaining segment count and the rest is the payload.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + self.data.len());
        buf.put_u8(self.remaining_segments);
        buf.extend_from_slice(&self.data);
        buf.freeze()
    }

    /// Decode a MessageSegment from bytes.
    ///
    /// This is zero-copy as the input `Bytes` is used for the payload.
    /// Minimum length is 2 bytes (1 for segment count + at least 1 for data) to match go-nethernet.
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < 2 {
            return Err(NethernetError::MessageParse(format!(
                "Message too short, expected at least 2 bytes, got {}",
                data.len()
            )));
        }

        let remaining_segments = data[0];
        data.advance(1);
        Ok(Self {
            remaining_segments,
            data,
        })
    }
}

/// Complete message - data assembled from segments
#[derive(Debug, Clone)]
pub struct Message {
    /// Expected segment count
    expected_segments: u8,
    /// Assembled data
    data: BytesMut,
}

impl Message {
    /// Creates a new, empty Message ready to receive segments.
    ///
    /// The returned Message is initialized to expect no segments and has an empty internal buffer.
    pub fn new() -> Self {
        Self {
            expected_segments: 0,
            data: BytesMut::new(),
        }
    }

    /// Adds a segment to the current message accumulator and returns the complete message when assembly finishes.
    ///
    /// This validates segment sequencing, appends the segment payload to the internal buffer, and resets internal state when a complete message is produced. If a segment is out of the expected order the accumulator is cleared and a `MessageParse` error is returned.
    pub fn add_segment(&mut self, segment: MessageSegment) -> Result<Option<Bytes>> {
        // Set expected_segments if this is the first segment
        if self.expected_segments == 0 && segment.remaining_segments > 0 {
            self.expected_segments = segment.remaining_segments + 1;
            // Pre-allocate buffer to avoid reallocations
            let estimated = self.expected_segments as usize * MAX_MESSAGE_SIZE;
            self.data.reserve(estimated);
        }

        // Check segment order
        if self.expected_segments > 0 {
            let expected_remaining = self.expected_segments - 1;
            if expected_remaining != segment.remaining_segments {
                // Reset state before returning error to keep Message instance safe for reuse
                self.data.clear();
                self.expected_segments = 0;
                return Err(NethernetError::MessageParse(format!(
                    "Invalid segment sequence: expected {}, got {}",
                    expected_remaining, segment.remaining_segments
                )));
            }
            self.expected_segments -= 1;
        }

        // Add data
        self.data.put(segment.data);

        // Return message if this is the last segment
        if segment.remaining_segments == 0 {
            let data = self.data.split().freeze();
            self.expected_segments = 0;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Splits a byte buffer into protocol-sized message segments.
    ///
    /// For inputs shorter than or equal to MAX_MESSAGE_SIZE this returns a single
    /// segment with `remaining_segments` equal to 0. For longer inputs the data
    /// is chunked into segments of at most MAX_MESSAGE_SIZE bytes; the first
    /// returned segment has `remaining_segments = segment_count - 1` and the last
    /// has `remaining_segments = 0`.
    #[inline(always)]
    pub fn split_into_segments(data: Bytes) -> Result<Vec<MessageSegment>> {
        let len = data.len();

        if len <= MAX_MESSAGE_SIZE {
            // Optimize for the common single-segment case to avoid div_ceil overhead
            // and use direct Vec construction to avoid potential macro overhead.
            let segments = vec![MessageSegment::new(0, data)];
            return Ok(segments);
        }

        let segment_count = len.div_ceil(MAX_MESSAGE_SIZE);

        if segment_count > 255 {
            return Err(NethernetError::MessageTooLarge(len));
        }

        // PRE-ALLOC
        let mut segments = Vec::with_capacity(segment_count);

        let mut remaining = data;
        let mut left = segment_count as u8;

        // Fast path
        while remaining.len() > MAX_MESSAGE_SIZE {
            left -= 1;

            let chunk = remaining.split_to(MAX_MESSAGE_SIZE);

            segments.push(MessageSegment::new(left, chunk));
        }

        // Last chunk
        if !remaining.is_empty() {
            left -= 1;
            segments.push(MessageSegment::new(left, remaining));
        }

        debug_assert_eq!(left, 0);

        Ok(segments)
    }
}

impl Default for Message {
    /// Creates a new [`Message`] initialized for assembling messages.
    ///
    /// # Returns
    ///
    /// A [`Message`] with an empty buffer and no expected segments.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_segment() {
        let data = Bytes::from("Hello, World!");
        let segments = Message::split_into_segments(data.clone()).unwrap();

        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].remaining_segments, 0);
        assert_eq!(segments[0].data, data);
    }

    #[test]
    fn test_multiple_segments() {
        let data = Bytes::from(vec![0u8; MAX_MESSAGE_SIZE * 2 + 100]);
        let segments = Message::split_into_segments(data.clone()).unwrap();

        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].remaining_segments, 2);
        assert_eq!(segments[1].remaining_segments, 1);
        assert_eq!(segments[2].remaining_segments, 0);
    }

    #[test]
    fn test_reassembly() {
        let original_data = Bytes::from(vec![1u8; MAX_MESSAGE_SIZE * 2 + 100]);
        let segments = Message::split_into_segments(original_data.clone()).unwrap();

        let mut message = Message::new();
        for (i, segment) in segments.iter().enumerate() {
            let result = message.add_segment(segment.clone()).unwrap();
            if i < segments.len() - 1 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some());
                assert_eq!(result.unwrap(), original_data);
            }
        }
    }

    #[test]
    fn test_out_of_order_segments_error() {
        // Create multiple segments from a large data
        let data = Bytes::from(vec![42u8; MAX_MESSAGE_SIZE * 2 + 100]);
        let segments = Message::split_into_segments(data.clone()).unwrap();

        // Should have at least 3 segments
        assert!(segments.len() >= 3);

        let mut message = Message::new();

        // Add segment 1 (middle segment) first - this should succeed
        // because it's the first segment being added and sets expected_segments
        let result = message.add_segment(segments[1].clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Not complete yet

        // Now try to add segment 0 (earlier segment with higher remaining_segments)
        // This should fail because we expect the next segment in sequence
        let result = message.add_segment(segments[0].clone());
        assert!(result.is_err());

        // Verify it's the right error type
        if let Err(NethernetError::MessageParse(msg)) = result {
            assert!(msg.contains("Invalid segment sequence"));
        } else {
            panic!("Expected MessageParse error for out-of-order segment");
        }
    }

    #[test]
    fn test_memory_efficient_allocation() {
        // Create 10 segments of 100 bytes each
        let segment_data = Bytes::from(vec![0u8; 100]);
        let mut message = Message::new();

        // Add the first segment with remaining_segments = 9
        let segment = MessageSegment::new(9, segment_data.clone());
        message.add_segment(segment).unwrap();

        // Capacity should be at least 10 * 100 = 1000
        // and no more than the 10 * MAX_MESSAGE_SIZE reserve requested above.
        let capacity = message.data.capacity();
        assert!(capacity >= 1000, "Capacity {} too small", capacity);
        assert!(
            capacity <= 10 * MAX_MESSAGE_SIZE,
            "Capacity {} too large (over-allocation)",
            capacity
        );
    }
}
