mod mrt;

use bytes::Bytes;

/// MrtEncode trait defines the encode method for encoding BGP messages (records, elems) into MRT format bytes.
pub trait MrtEncode {
    fn encode(&self) -> Bytes;
}
