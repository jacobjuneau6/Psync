//! Frame encoding and decoding for the wire protocol.
//! Stub — full framing implementation in commits 9-10.

use crate::error::Result;

/// Maximum frame payload size: 16 MiB.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Magic bytes that prefix every frame: "PWRF".
pub const FRAME_MAGIC: [u8; 4] = [0x50, 0x57, 0x52, 0x46];

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Encode a serializable message into a framed byte vector.
pub fn encode_frame<T: serde::Serialize>(_msg: &T, _msg_type: u8) -> Result<Vec<u8>> {
    // Stub — will be implemented in commit 9
    Ok(Vec::new())
}

/// Decode a frame header and return the payload bytes and message type.
pub fn decode_frame(_data: &[u8]) -> Result<(u8, Vec<u8>)> {
    // Stub — will be implemented in commit 10
    Ok((0, Vec::new()))
}
