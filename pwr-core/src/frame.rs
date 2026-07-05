//! Frame encoding and decoding for the pwr wire protocol.
//!
//! Every message on the wire is wrapped in a 10-byte frame header:
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0       4     Magic bytes "PWRF" (0x50 0x57 0x52 0x46)
//! 4       4     Payload length in bytes (big-endian u32)
//! 8       1     Protocol version (currently 0x01)
//! 9       1     Message type (see protocol::MessageType)
//! 10      N     Payload (bincode-encoded message body)
//! ```
//!
//! The maximum payload size is 16 MiB. File content is NOT sent
//! through the frame layer; it is streamed as raw bytes with a
//! separate chunking protocol (4-byte length prefix, 0 = EOF).

use crate::error::{PwrError, Result};
use crate::protocol::MessageType;

/// Magic bytes that prefix every frame.
pub const FRAME_MAGIC: [u8; 4] = [0x50, 0x57, 0x52, 0x46]; // "PWRF"

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Maximum frame payload size: 16 MiB.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Total frame header size in bytes.
pub const HEADER_SIZE: usize = 10;

/// Encode a message into a framed byte vector suitable for writing
/// to a TCP stream.
///
/// The caller provides the message (which must implement serde::Serialize),
/// its MessageType discriminant, and optionally a specific protocol version
/// (defaults to PROTOCOL_VERSION).
///
/// Returns the complete frame bytes: 10-byte header + JSON-encoded body.
pub fn encode_frame<T: serde::Serialize>(
    msg: &T,
    msg_type: MessageType,
) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(msg)
        .map_err(|e| PwrError::Framing(format!("encode error: {}", e)))?;

    if body.len() > MAX_FRAME_SIZE {
        return Err(PwrError::Framing(format!(
            "payload size {} exceeds maximum {}",
            body.len(),
            MAX_FRAME_SIZE
        )));
    }

    let payload_len = body.len() as u32;
    let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());

    // Magic bytes
    frame.extend_from_slice(&FRAME_MAGIC);
    // Payload length (big-endian)
    frame.extend_from_slice(&payload_len.to_be_bytes());
    // Protocol version
    frame.push(PROTOCOL_VERSION);
    // Message type
    frame.push(msg_type as u8);
    // Payload
    frame.extend_from_slice(&body);

    Ok(frame)
}

/// Decoded frame components returned by `decode_frame_header`.
#[derive(Debug)]
pub struct FrameHeader {
    /// Length of the payload in bytes.
    pub payload_len: u32,
    /// Protocol version from the frame.
    pub version: u8,
    /// Message type discriminant.
    pub msg_type: MessageType,
}

/// Decode a frame from raw bytes, returning the message type and
/// the raw payload bytes.
///
/// The caller is responsible for deserializing the payload into
/// the appropriate typed struct based on the message type.
///
/// Returns `None` if more bytes are needed to complete the frame
/// (the caller should buffer and retry).
pub fn decode_frame(data: &[u8]) -> Result<Option<(FrameHeader, Vec<u8>)>> {
    // Need at least the 10-byte header
    if data.len() < HEADER_SIZE {
        return Ok(None);
    }

    // Verify magic bytes
    if data[0..4] != FRAME_MAGIC {
        return Err(PwrError::Framing(format!(
            "invalid magic bytes: expected {:02X?}, got {:02X?}",
            &FRAME_MAGIC[..],
            &data[0..4]
        )));
    }

    // Read payload length
    let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

    if payload_len > MAX_FRAME_SIZE {
        return Err(PwrError::Framing(format!(
            "frame payload size {} exceeds maximum {}",
            payload_len, MAX_FRAME_SIZE
        )));
    }

    // Check if we have the full payload
    let total_frame_size = HEADER_SIZE + payload_len;
    if data.len() < total_frame_size {
        return Ok(None);
    }

    // Read version
    let version = data[8];
    if version != PROTOCOL_VERSION {
        return Err(PwrError::Framing(format!(
            "unsupported protocol version: got {}, expected {}",
            version, PROTOCOL_VERSION
        )));
    }

    // Read message type
    let msg_type_byte = data[9];
    let msg_type = MessageType::from_byte(msg_type_byte).ok_or_else(|| {
        PwrError::Framing(format!("unknown message type: 0x{:02X}", msg_type_byte))
    })?;

    // Extract payload
    let payload = data[HEADER_SIZE..total_frame_size].to_vec();

    Ok(Some((
        FrameHeader {
            payload_len: payload_len as u32,
            version,
            msg_type,
        },
        payload,
    )))
}

/// Streaming frame decoder that maintains an internal buffer.
///
/// Call `push_bytes` with data read from the socket, then call
/// `try_decode` to extract complete frames. Incomplete frames
/// are buffered until enough data arrives.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// Create a new frame decoder with an empty buffer.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Append raw bytes received from the transport.
    pub fn push_bytes(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Attempt to decode one complete frame from the buffer.
    ///
    /// Returns `Ok(Some((header, payload)))` if a complete frame was decoded.
    /// The decoded bytes are removed from the internal buffer.
    /// Returns `Ok(None)` if more data is needed.
    /// Returns `Err` if the frame is malformed.
    pub fn try_decode(&mut self) -> Result<Option<(FrameHeader, Vec<u8>)>> {
        match decode_frame(&self.buffer)? {
            Some((header, payload)) => {
                let consumed = HEADER_SIZE + header.payload_len as usize;
                self.buffer.drain(..consumed);
                Ok(Some((header, payload)))
            }
            None => Ok(None),
        }
    }

    /// Return the number of buffered bytes waiting to be decoded.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

// ---------------------------------------------------------------------------
// File chunk streaming
// ---------------------------------------------------------------------------

/// Write a chunk of file data in the streaming format.
///
/// Format: 4-byte big-endian chunk length (0 = EOF marker),
/// followed by that many bytes of file content.
pub fn encode_file_chunk(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut chunk = Vec::with_capacity(4 + data.len());
    chunk.extend_from_slice(&len.to_be_bytes());
    chunk.extend_from_slice(data);
    chunk
}

/// The EOF marker for file chunk streaming.
/// A chunk with length 0 signals the end of the current file.
pub fn encode_file_eof() -> Vec<u8> {
    vec![0u8, 0, 0, 0]
}

/// Decode one chunk from a byte buffer.
///
/// Returns:
/// - `Ok(Some(data))` for a data chunk
/// - `Ok(None)` if the chunk is the EOF marker (length = 0)
/// - `Err` if the buffer doesn't contain enough data for the claimed length
pub fn decode_file_chunk(data: &[u8]) -> Result<Option<&[u8]>> {
    if data.len() < 4 {
        return Err(PwrError::Framing(
            "incomplete chunk header: need 4 bytes".into(),
        ));
    }

    let chunk_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if chunk_len == 0 {
        return Ok(None); // EOF marker
    }

    if data.len() < 4 + chunk_len {
        return Err(PwrError::Framing(format!(
            "incomplete chunk data: need {} bytes, have {}",
            4 + chunk_len,
            data.len()
        )));
    }

    Ok(Some(&data[4..4 + chunk_len]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Handshake, StatusRequest};

    #[test]
    fn test_encode_decode_round_trip() -> Result<()> {
        let msg = Handshake {
            version: 1,
            client_id: "test-client".into(),
            nonce: [0x42; 32],
            proof: [0x99; 32],
        };

        let frame = encode_frame(&msg, MessageType::Handshake)?;

        // Verify magic bytes
        assert_eq!(&frame[0..4], &FRAME_MAGIC);

        // Decode
        let (header, payload) = decode_frame(&frame)?.unwrap();

        assert_eq!(header.version, PROTOCOL_VERSION);
        assert_eq!(header.msg_type, MessageType::Handshake);

        let decoded: Handshake = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded.client_id, "test-client");

        Ok(())
    }

    #[test]
    fn test_decode_needs_more_data() -> Result<()> {
        // Only 5 bytes — incomplete header
        assert!(decode_frame(&[0x50, 0x57, 0x52, 0x46, 0x00])?.is_none());
        Ok(())
    }

    #[test]
    fn test_decode_rejects_bad_magic() {
        let mut bad = vec![0x00; 10];
        bad[0] = 0xDE;
        bad[1] = 0xAD;
        assert!(decode_frame(&bad).is_err());
    }

    #[test]
    fn test_decode_rejects_oversized_frame() {
        let mut header = Vec::new();
        header.extend_from_slice(&FRAME_MAGIC);
        header.extend_from_slice(&((MAX_FRAME_SIZE as u32 + 1).to_be_bytes()));
        header.push(PROTOCOL_VERSION);
        header.push(MessageType::Error as u8);

        assert!(decode_frame(&header).is_err());
    }

    #[test]
    fn test_frame_decoder_buffering() -> Result<()> {
        let mut decoder = FrameDecoder::new();

        let msg = StatusRequest { project_uuid: None };
        let frame = encode_frame(&msg, MessageType::StatusRequest)?;

        // Feed half the frame
        let mid = frame.len() / 2;
        decoder.push_bytes(&frame[..mid]);
        assert!(decoder.try_decode()?.is_none()); // Not enough data

        // Feed the rest
        decoder.push_bytes(&frame[mid..]);
        let result = decoder.try_decode()?;
        assert!(result.is_some());

        let (header, _payload) = result.unwrap();
        assert_eq!(header.msg_type, MessageType::StatusRequest);
        assert_eq!(decoder.buffered_len(), 0);

        Ok(())
    }

    #[test]
    fn test_file_chunk_round_trip() {
        let data = b"Hello, file streaming!";
        let chunk = encode_file_chunk(data);

        let decoded = decode_file_chunk(&chunk).unwrap();
        assert_eq!(decoded, Some(&data[..]));
    }

    #[test]
    fn test_file_eof() {
        let eof = encode_file_eof();
        assert_eq!(decode_file_chunk(&eof).unwrap(), None);
    }
}
