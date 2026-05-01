use anyhow::Context;
use bonded_core::session::{SessionFrame, SessionHeader};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct TunBridge {
    state: Arc<Mutex<TunBridgeState>>,
    outbound_tx: mpsc::UnboundedSender<OutboundPacket>,
}

struct OutboundPacket {
    session_id: u64,
    connection_id: u32,
    payload: Bytes,
}

struct SessionRoute {
    tx: mpsc::UnboundedSender<SessionFrame>,
    connection_id: u32,
    next_server_sequence: u64,
}

struct TunBridgeState {
    sessions: HashMap<u64, SessionRoute>,
    ip_to_session: HashMap<Ipv4Addr, u64>,
}

impl TunBridge {
    pub fn new(device: tun::AsyncDevice) -> Self {
        let state = Arc::new(Mutex::new(TunBridgeState {
            sessions: HashMap::new(),
            ip_to_session: HashMap::new(),
        }));
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<OutboundPacket>();

        let state_for_writer = state.clone();
        let state_for_reader = state.clone();
        let (mut tun_reader, mut tun_writer) = tokio::io::split(device);

        tokio::spawn(async move {
            while let Some(pkt) = outbound_rx.recv().await {
                let Some((src_ip, _dst_ip)) = parse_ipv4_src_dst(&pkt.payload) else {
                    warn!(
                        session_id = pkt.session_id,
                        payload_len = pkt.payload.len(),
                        "dropping non-ipv4 packet in TUN outbound path"
                    );
                    continue;
                };

                {
                    let mut guard = state_for_writer.lock().await;
                    if let Some(route) = guard.sessions.get_mut(&pkt.session_id) {
                        route.connection_id = pkt.connection_id;
                        guard.ip_to_session.insert(src_ip, pkt.session_id);
                    }
                }

                if let Err(err) = tun_writer.write_all(&pkt.payload).await {
                    warn!(
                        session_id = pkt.session_id,
                        error = %err,
                        "failed to write packet to TUN"
                    );
                    break;
                }
            }
        });

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let read = match tun_reader.read(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(err) => {
                        warn!(error = %err, "failed to read packet from TUN");
                        break;
                    }
                };

                let packet = &buf[..read];
                let Some((_src_ip, dst_ip)) = parse_ipv4_src_dst(packet) else {
                    continue;
                };

                let mut guard = state_for_reader.lock().await;
                let Some(session_id) = guard.ip_to_session.get(&dst_ip).copied() else {
                    debug!(dst_ip = %dst_ip, "no session route for TUN return packet");
                    continue;
                };

                let Some(route) = guard.sessions.get_mut(&session_id) else {
                    let _ = guard.ip_to_session.remove(&dst_ip);
                    continue;
                };

                let frame = SessionFrame {
                    header: SessionHeader {
                        connection_id: route.connection_id,
                        sequence: route.next_server_sequence,
                        flags: 0,
                    },
                    payload: Bytes::copy_from_slice(packet),
                };
                route.next_server_sequence = route.next_server_sequence.wrapping_add(1);

                if route.tx.send(frame).is_err() {
                    let _ = guard.sessions.remove(&session_id);
                    guard
                        .ip_to_session
                        .retain(|_, mapped| *mapped != session_id);
                }
            }
        });

        Self { state, outbound_tx }
    }

    pub async fn register_session(&self, session_id: u64, tx: mpsc::UnboundedSender<SessionFrame>) {
        let mut guard = self.state.lock().await;
        guard.sessions.insert(
            session_id,
            SessionRoute {
                tx,
                connection_id: 1,
                next_server_sequence: 0,
            },
        );
    }

    pub async fn unregister_session(&self, session_id: u64) {
        let mut guard = self.state.lock().await;
        guard.sessions.remove(&session_id);
        guard
            .ip_to_session
            .retain(|_, mapped| *mapped != session_id);
    }

    pub fn submit_client_frame(&self, session_id: u64, frame: SessionFrame) -> anyhow::Result<()> {
        self.outbound_tx
            .send(OutboundPacket {
                session_id,
                connection_id: frame.header.connection_id,
                payload: frame.payload,
            })
            .context("tun bridge outbound channel closed")
    }
}

fn parse_ipv4_src_dst(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 {
        return None;
    }

    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len > packet.len() {
        return None;
    }

    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst))
}

#[cfg(test)]
mod tests {
    use super::parse_ipv4_src_dst;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_ipv4_src_dst() {
        let pkt = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 64, 17, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1,
        ];
        let (src, dst) = parse_ipv4_src_dst(&pkt).expect("valid ipv4 packet");
        assert_eq!(src, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(dst, Ipv4Addr::new(1, 1, 1, 1));
    }
}
