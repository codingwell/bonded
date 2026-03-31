use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

const HEADER_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHeader {
    pub connection_id: u32,
    pub sequence: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFrame {
    pub header: SessionHeader,
    pub payload: Bytes,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("buffer too small for frame header")]
    BufferTooSmall,
}

impl SessionFrame {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        buf.put_u32(self.header.connection_id);
        buf.put_u64(self.header.sequence);
        buf.put_u32(self.header.flags);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(raw: &[u8]) -> Result<Self, FrameError> {
        if raw.len() < HEADER_LEN {
            return Err(FrameError::BufferTooSmall);
        }
        let mut raw = raw;
        let connection_id = raw.get_u32();
        let sequence = raw.get_u64();
        let flags = raw.get_u32();
        let payload = Bytes::copy_from_slice(raw);
        Ok(Self {
            header: SessionHeader {
                connection_id,
                sequence,
                flags,
            },
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionFrame, SessionHeader};
    use bytes::Bytes;

    #[test]
    fn frame_roundtrip_encode_decode() {
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 42,
                sequence: 7,
                flags: 1,
            },
            payload: Bytes::from_static(b"hello"),
        };

        let encoded = frame.encode();
        let decoded = SessionFrame::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.header.connection_id, 42);
        assert_eq!(decoded.header.sequence, 7);
        assert_eq!(&decoded.payload[..], b"hello");
    }
}
