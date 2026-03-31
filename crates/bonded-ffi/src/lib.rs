use bonded_core::session::SessionFrame;
use std::slice;

const BONDED_FFI_OK: i32 = 0;
const BONDED_FFI_ERR_NULL_POINTER: i32 = 1;
const BONDED_FFI_ERR_DECODE: i32 = 2;

#[repr(C)]
pub struct BondedFrameMetadata {
    pub connection_id: u32,
    pub sequence: u64,
    pub flags: u32,
    pub payload_len: usize,
}

fn decode_frame_metadata(raw: &[u8]) -> Result<BondedFrameMetadata, i32> {
    let frame = SessionFrame::decode(raw).map_err(|_| BONDED_FFI_ERR_DECODE)?;
    Ok(BondedFrameMetadata {
        connection_id: frame.header.connection_id,
        sequence: frame.header.sequence,
        flags: frame.header.flags,
        payload_len: frame.payload.len(),
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn bonded_ffi_api_version() -> u32 {
    1
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `raw_ptr` must point to `raw_len` bytes of readable memory.
/// `out_metadata` must point to writable memory for one `BondedFrameMetadata`.
pub unsafe extern "C" fn bonded_ffi_decode_frame_metadata(
    raw_ptr: *const u8,
    raw_len: usize,
    out_metadata: *mut BondedFrameMetadata,
) -> i32 {
    if raw_ptr.is_null() || out_metadata.is_null() {
        return BONDED_FFI_ERR_NULL_POINTER;
    }

    // Safety: caller guarantees `raw_ptr` is valid for `raw_len` bytes.
    let raw = unsafe { slice::from_raw_parts(raw_ptr, raw_len) };
    match decode_frame_metadata(raw) {
        Ok(metadata) => {
            // Safety: caller guarantees `out_metadata` points to writable memory.
            unsafe {
                *out_metadata = metadata;
            }
            BONDED_FFI_OK
        }
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::{bonded_ffi_api_version, decode_frame_metadata};
    use bonded_core::session::{SessionFrame, SessionHeader};

    #[test]
    fn ffi_api_version_is_stable() {
        assert_eq!(bonded_ffi_api_version(), 1);
    }

    #[test]
    fn decode_frame_metadata_reads_session_headers() {
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 42,
                sequence: 9,
                flags: 7,
            },
            payload: b"hello".to_vec().into(),
        };

        let decoded = decode_frame_metadata(&frame.encode()).expect("decode should succeed");
        assert_eq!(decoded.connection_id, 42);
        assert_eq!(decoded.sequence, 9);
        assert_eq!(decoded.flags, 7);
        assert_eq!(decoded.payload_len, 5);
    }

    #[test]
    fn decode_frame_metadata_rejects_short_buffers() {
        let result = decode_frame_metadata(b"tiny");
        assert!(result.is_err());
    }
}
