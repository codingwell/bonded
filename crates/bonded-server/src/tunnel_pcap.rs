use anyhow::Context;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const PCAP_PATH: &str = "/var/lib/bonded/tunnel.pcap";
const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

pub struct TunnelPcapLogger {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    bytes_written: u64,
    max_bytes: u64,
    stopped_at_limit: bool,
}

impl TunnelPcapLogger {
    pub fn from_env(max_mb_env: &str) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(value) = std::env::var(max_mb_env).ok() else {
            return Ok(None);
        };

        let max_mb: u64 = value
            .trim()
            .parse()
            .with_context(|| format!("{max_mb_env} must be an integer number of megabytes"))?;
        if max_mb == 0 {
            anyhow::bail!("{max_mb_env} must be > 0 when set");
        }

        let max_bytes = max_mb
            .checked_mul(1024 * 1024)
            .context("pcap size limit overflow")?;

        let path = Path::new(PCAP_PATH);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let mut file = File::create(path)
            .with_context(|| format!("failed to create pcap file at {}", PCAP_PATH))?;
        let header = build_global_header();
        file.write_all(&header)
            .with_context(|| format!("failed to write pcap header to {}", PCAP_PATH))?;
        file.flush()
            .with_context(|| format!("failed to flush pcap header to {}", PCAP_PATH))?;

        info!(
            path = %PCAP_PATH,
            max_mb,
            max_bytes,
            env = %max_mb_env,
            "tunnel PCAP logging enabled"
        );

        Ok(Some(Arc::new(Self {
            inner: Mutex::new(Inner {
                file,
                bytes_written: PCAP_GLOBAL_HEADER_LEN as u64,
                max_bytes,
                stopped_at_limit: false,
            }),
        })))
    }

    pub fn log_packet(&self, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }

        let mut inner = match self.inner.lock() {
            Ok(value) => value,
            Err(_) => return,
        };

        let record_len = match (PCAP_RECORD_HEADER_LEN as u64).checked_add(packet.len() as u64) {
            Some(v) => v,
            None => return,
        };

        if inner.bytes_written.saturating_add(record_len) > inner.max_bytes {
            if !inner.stopped_at_limit {
                inner.stopped_at_limit = true;
                warn!(
                    path = %PCAP_PATH,
                    max_bytes = inner.max_bytes,
                    bytes_written = inner.bytes_written,
                    "tunnel PCAP size limit reached; packet logging stopped"
                );
            }
            return;
        }

        let (secs, usecs) = current_pcap_timestamp();
        let rec_header = build_record_header(secs, usecs, packet.len() as u32, packet.len() as u32);

        if inner.file.write_all(&rec_header).is_err() {
            return;
        }
        if inner.file.write_all(packet).is_err() {
            return;
        }
        let _ = inner.file.flush();
        inner.bytes_written = inner.bytes_written.saturating_add(record_len);
    }
}

fn build_global_header() -> [u8; PCAP_GLOBAL_HEADER_LEN] {
    let mut out = [0u8; PCAP_GLOBAL_HEADER_LEN];
    out[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out[4..6].copy_from_slice(&2u16.to_le_bytes());
    out[6..8].copy_from_slice(&4u16.to_le_bytes());
    out[8..12].copy_from_slice(&0i32.to_le_bytes());
    out[12..16].copy_from_slice(&0u32.to_le_bytes());
    out[16..20].copy_from_slice(&65535u32.to_le_bytes());
    // LINKTYPE_RAW: packet data begins with IPv4/IPv6 header.
    out[20..24].copy_from_slice(&101u32.to_le_bytes());
    out
}

fn build_record_header(ts_sec: u32, ts_usec: u32, incl_len: u32, orig_len: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    out[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    out[8..12].copy_from_slice(&incl_len.to_le_bytes());
    out[12..16].copy_from_slice(&orig_len.to_le_bytes());
    out
}

fn current_pcap_timestamp() -> (u32, u32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs() as u32, now.subsec_micros())
}

#[cfg(test)]
mod tests {
    use super::{build_global_header, build_record_header};

    #[test]
    fn pcap_global_header_has_magic_and_linktype_raw() {
        let header = build_global_header();
        assert_eq!(
            u32::from_le_bytes([header[0], header[1], header[2], header[3]]),
            0xa1b2c3d4
        );
        assert_eq!(
            u32::from_le_bytes([header[20], header[21], header[22], header[23]]),
            101
        );
    }

    #[test]
    fn pcap_record_header_encodes_lengths() {
        let header = build_record_header(1, 2, 3, 4);
        assert_eq!(
            u32::from_le_bytes([header[0], header[1], header[2], header[3]]),
            1
        );
        assert_eq!(
            u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
            2
        );
        assert_eq!(
            u32::from_le_bytes([header[8], header[9], header[10], header[11]]),
            3
        );
        assert_eq!(
            u32::from_le_bytes([header[12], header[13], header[14], header[15]]),
            4
        );
    }
}
