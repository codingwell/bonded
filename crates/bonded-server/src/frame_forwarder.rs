use bonded_core::session::SessionFrame;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::debug;

// ── UDP ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Ipv4UdpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
    identification: u16,
}

// ── ICMP ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Ipv4IcmpEchoPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identification: u16,
    echo_identifier: u16,
    echo_sequence: u16,
    icmp_segment: Vec<u8>,
}

// ── TCP flow table ────────────────────────────────────────────────────────────

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;
const TCP_FIN: u8 = 0x01;

/// 4-tuple key: (client_virtual_ip, client_port, server_ip, server_port)
type FlowKey = (Ipv4Addr, u16, Ipv4Addr, u16);

struct TcpFlowEntry {
    stream: Arc<Mutex<TcpStream>>,
    /// Next sequence number the server will use when sending data.
    server_seq: u32,
}

/// Per-client-session TCP NAT flow table.  One instance is created per
/// authenticated VPN session before the frame-receive loop starts, and dropped
/// when the session ends.
#[derive(Clone, Default)]
pub struct TcpFlowTable {
    flows: Arc<Mutex<HashMap<FlowKey, TcpFlowEntry>>>,
}

#[derive(Debug)]
struct Ipv4TcpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

// ── Main forwarding entry-point ───────────────────────────────────────────────

pub async fn forward_frame(
    frame: SessionFrame,
    upstream_tcp_target: Option<&str>,
    tcp_flows: &TcpFlowTable,
) -> anyhow::Result<Option<SessionFrame>> {
    // ── UDP ───────────────────────────────────────────────────────────────────
    if let Some(udp_packet) = parse_ipv4_udp_packet(&frame.payload) {
        debug!(
            src_ip = %udp_packet.src_ip,
            dst_ip = %udp_packet.dst_ip,
            src_port = udp_packet.src_port,
            dst_port = udp_packet.dst_port,
            payload_size = udp_packet.payload.len(),
            "UDP packet forwarding outbound"
        );

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let bound_addr = socket.local_addr()?;
        debug!(
            src_ip = %udp_packet.src_ip,
            dst_ip = %udp_packet.dst_ip,
            src_port = udp_packet.src_port,
            dst_port = udp_packet.dst_port,
            bound_addr = %bound_addr,
            "UDP socket bound for forwarding"
        );

        let target = SocketAddrV4::new(udp_packet.dst_ip, udp_packet.dst_port);
        socket.send_to(&udp_packet.payload, target).await?;
        debug!(
            dst_ip = %udp_packet.dst_ip,
            dst_port = udp_packet.dst_port,
            payload_size = udp_packet.payload.len(),
            "UDP packet sent to target"
        );

        let mut response = vec![0_u8; 65535];
        let read_size = match timeout(Duration::from_millis(1200), socket.recv(&mut response)).await
        {
            Ok(result) => result?,
            Err(_) => {
                debug!(
                    src_ip = %udp_packet.src_ip,
                    dst_ip = %udp_packet.dst_ip,
                    src_port = udp_packet.src_port,
                    dst_port = udp_packet.dst_port,
                    "UDP response timeout (1200ms) - no response received"
                );
                return Ok(None);
            }
        };

        response.truncate(read_size);
        debug!(
            src_ip = %udp_packet.src_ip,
            dst_ip = %udp_packet.dst_ip,
            src_port = udp_packet.src_port,
            dst_port = udp_packet.dst_port,
            response_size = read_size,
            "UDP response received from target"
        );

        let response_packet = build_ipv4_udp_packet(
            udp_packet.dst_ip,
            udp_packet.src_ip,
            udp_packet.dst_port,
            udp_packet.src_port,
            udp_packet.identification,
            &response,
        )?;
        debug!(
            src_ip = %udp_packet.dst_ip,
            dst_ip = %udp_packet.src_ip,
            src_port = udp_packet.dst_port,
            dst_port = udp_packet.src_port,
            response_packet_size = response_packet.len(),
            "UDP response packet built for client"
        );
        return Ok(Some(SessionFrame {
            header: frame.header,
            payload: response_packet.into(),
        }));
    }

    // ── ICMP ──────────────────────────────────────────────────────────────────
    if let Some(icmp_packet) = parse_ipv4_icmp_echo_packet(&frame.payload) {
        debug!(
            src_ip = %icmp_packet.src_ip,
            dst_ip = %icmp_packet.dst_ip,
            echo_identifier = icmp_packet.echo_identifier,
            echo_sequence = icmp_packet.echo_sequence,
            payload_size = icmp_packet.icmp_segment.len().saturating_sub(8),
            "ICMP echo packet forwarding outbound"
        );

        let reply = send_icmp_echo_and_wait_reply(
            icmp_packet.dst_ip,
            icmp_packet.echo_identifier,
            icmp_packet.echo_sequence,
            icmp_packet.icmp_segment.clone(),
        )
        .await?;

        let Some(reply_icmp_segment) = reply else {
            debug!(
                src_ip = %icmp_packet.src_ip,
                dst_ip = %icmp_packet.dst_ip,
                echo_identifier = icmp_packet.echo_identifier,
                echo_sequence = icmp_packet.echo_sequence,
                "ICMP echo response timeout (1200ms) - no response received"
            );
            return Ok(None);
        };

        let response_packet = build_ipv4_icmp_packet(
            icmp_packet.dst_ip,
            icmp_packet.src_ip,
            icmp_packet.identification,
            &reply_icmp_segment,
        )?;
        debug!(
            src_ip = %icmp_packet.dst_ip,
            dst_ip = %icmp_packet.src_ip,
            echo_identifier = icmp_packet.echo_identifier,
            echo_sequence = icmp_packet.echo_sequence,
            response_packet_size = response_packet.len(),
            "ICMP echo response packet built for client"
        );
        return Ok(Some(SessionFrame {
            header: frame.header,
            payload: response_packet.into(),
        }));
    }

    // ── TCP (VPN packet-level NAT/proxy) ──────────────────────────────────────
    if let Some(tcp_pkt) = parse_ipv4_tcp_packet(&frame.payload) {
        return handle_tcp_frame(frame, tcp_pkt, tcp_flows).await;
    }

    // ── Raw upstream TCP byte-pipe (legacy fallback) ──────────────────────────
    if let Some(target) = upstream_tcp_target.filter(|value| !value.trim().is_empty()) {
        debug!(
            target = %target,
            payload_size = frame.payload.len(),
            "TCP payload forwarding to upstream"
        );
        let mut upstream = TcpStream::connect(target).await?;
        debug!(target = %target, "upstream TCP connection established");

        upstream.write_all(&frame.payload).await?;
        upstream.flush().await?;
        debug!(
            target = %target,
            payload_size = frame.payload.len(),
            "TCP payload sent to upstream"
        );

        let mut response = vec![0_u8; 8192];
        let read_size = timeout(Duration::from_millis(500), upstream.read(&mut response))
            .await
            .unwrap_or(Ok(0))?;

        if read_size > 0 {
            debug!(
                target = %target,
                response_size = read_size,
                "TCP response received from upstream"
            );
            response.truncate(read_size);
            return Ok(Some(SessionFrame {
                header: frame.header,
                payload: response.into(),
            }));
        } else {
            debug!(target = %target, "TCP response timeout (500ms) - no response received");
        }
    }

    Ok(Some(frame))
}

// ── TCP NAT handler ───────────────────────────────────────────────────────────

async fn handle_tcp_frame(
    frame: SessionFrame,
    pkt: Ipv4TcpPacket,
    flows: &TcpFlowTable,
) -> anyhow::Result<Option<SessionFrame>> {
    // Fixed ISN for simplicity; a production implementation would use a random value.
    const SERVER_ISN: u32 = 0x1234_5678;
    const WINDOW: u16 = 65535;

    let key: FlowKey = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port);

    // ── SYN: open upstream connection, synthesise SYN-ACK ────────────────────
    if pkt.flags & TCP_SYN != 0 && pkt.flags & TCP_ACK == 0 {
        let target = SocketAddrV4::new(pkt.dst_ip, pkt.dst_port);
        let upstream = TcpStream::connect(target).await?;
        debug!(
            src_ip = %pkt.src_ip, src_port = pkt.src_port,
            dst_ip = %pkt.dst_ip, dst_port = pkt.dst_port,
            "TCP SYN: upstream connected"
        );
        flows.flows.lock().await.insert(
            key,
            TcpFlowEntry {
                stream: Arc::new(Mutex::new(upstream)),
                // SYN-ACK consumes one sequence number; first data byte is ISN+1.
                server_seq: SERVER_ISN.wrapping_add(1),
            },
        );
        let syn_ack = build_ipv4_tcp_packet(
            pkt.dst_ip,
            pkt.src_ip,
            pkt.dst_port,
            pkt.src_port,
            SERVER_ISN,
            pkt.seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            WINDOW,
            &[],
        );
        return Ok(Some(SessionFrame {
            header: frame.header,
            payload: syn_ack.into(),
        }));
    }

    // ── FIN: tear down flow, send FIN-ACK ────────────────────────────────────
    if pkt.flags & TCP_FIN != 0 {
        let entry = flows.flows.lock().await.remove(&key);
        let server_seq = entry.map_or(SERVER_ISN.wrapping_add(1), |e| e.server_seq);
        debug!(
            src_ip = %pkt.src_ip, src_port = pkt.src_port,
            "TCP FIN: removing flow"
        );
        let fin_ack = build_ipv4_tcp_packet(
            pkt.dst_ip,
            pkt.src_ip,
            pkt.dst_port,
            pkt.src_port,
            server_seq,
            pkt.seq.wrapping_add(1),
            TCP_FIN | TCP_ACK,
            WINDOW,
            &[],
        );
        return Ok(Some(SessionFrame {
            header: frame.header,
            payload: fin_ack.into(),
        }));
    }

    // ── PSH: forward payload to upstream, read response ───────────────────────
    if pkt.flags & TCP_PSH != 0 && !pkt.payload.is_empty() {
        // Grab a clone of the stream Arc without holding the table lock during I/O.
        let stream_arc = flows.flows.lock().await.get(&key).map(|e| e.stream.clone());

        let Some(stream_arc) = stream_arc else {
            debug!(
                src_ip = %pkt.src_ip, src_port = pkt.src_port,
                "TCP PSH for unknown flow, dropping"
            );
            return Ok(None);
        };

        let (n, response) = {
            let mut stream = stream_arc.lock().await;
            stream.write_all(&pkt.payload).await?;
            stream.flush().await?;

            let mut buf = vec![0u8; 65535];
            let n = match timeout(Duration::from_millis(1200), stream.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => {
                    debug!(
                        src_ip = %pkt.src_ip, src_port = pkt.src_port,
                        "TCP upstream read timeout (1200ms)"
                    );
                    return Ok(None);
                }
            };
            buf.truncate(n);
            (n, buf)
        };

        if n == 0 {
            // Upstream closed connection; no data to return.
            return Ok(None);
        }

        // Advance the server's tracked sequence number.
        let server_seq = {
            let mut table = flows.flows.lock().await;
            if let Some(entry) = table.get_mut(&key) {
                let seq = entry.server_seq;
                entry.server_seq = seq.wrapping_add(n as u32);
                seq
            } else {
                SERVER_ISN.wrapping_add(1)
            }
        };

        let resp_pkt = build_ipv4_tcp_packet(
            pkt.dst_ip,
            pkt.src_ip,
            pkt.dst_port,
            pkt.src_port,
            server_seq,
            pkt.seq.wrapping_add(pkt.payload.len() as u32),
            TCP_PSH | TCP_ACK,
            WINDOW,
            &response,
        );
        debug!(
            src_ip = %pkt.src_ip, src_port = pkt.src_port,
            response_bytes = n,
            "TCP PSH: forwarded and built response"
        );
        return Ok(Some(SessionFrame {
            header: frame.header,
            payload: resp_pkt.into(),
        }));
    }

    // ── Pure ACK (handshake completion or keepalive): no response needed ──────
    debug!(
        src_ip = %pkt.src_ip, src_port = pkt.src_port,
        flags = pkt.flags,
        "TCP ACK (no data): no response"
    );
    Ok(None)
}

// ── ICMP helper ───────────────────────────────────────────────────────────────

async fn send_icmp_echo_and_wait_reply(
    dst_ip: Ipv4Addr,
    echo_identifier: u16,
    echo_sequence: u16,
    request_icmp_segment: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        let timeout = std::time::Duration::from_millis(1200);
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        let target = SocketAddrV4::new(dst_ip, 0);
        socket.connect(&target.into())?;
        socket.send(&request_icmp_segment)?;

        loop {
            let mut raw_response = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
            let read_size = match socket.recv(&mut raw_response) {
                Ok(size) => size,
                Err(err)
                    if err.kind() == std::io::ErrorKind::TimedOut
                        || err.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            };

            if read_size < 8 {
                continue;
            }

            let response: Vec<u8> = raw_response[..read_size]
                .iter()
                .map(|byte| {
                    // Bytes reported by recv() are fully initialized by the OS.
                    unsafe { byte.assume_init() }
                })
                .collect();
            let reply_type = response[0];
            let reply_code = response[1];
            // SOCK_DGRAM ICMP sockets cause the Linux kernel to rewrite the echo
            // identifier with the socket'"'"'s own ephemeral identifier.  Only check
            // the sequence number to match the reply; restore the caller-supplied
            // identifier afterwards so that the VPN client sees a coherent packet.
            let reply_sequence = u16::from_be_bytes([response[6], response[7]]);
            if reply_type == 0 && reply_code == 0 && reply_sequence == echo_sequence {
                let mut fixed = response;
                fixed[4..6].copy_from_slice(&echo_identifier.to_be_bytes());
                // Recompute the ICMP checksum after patching the identifier field.
                fixed[2..4].copy_from_slice(&[0, 0]);
                let new_cksum = checksum_ones_complement(&fixed);
                fixed[2..4].copy_from_slice(&new_cksum.to_be_bytes());
                return Ok(Some(fixed));
            }
        }
    })
    .await?
}

// ── Packet parsers ────────────────────────────────────────────────────────────

fn parse_ipv4_udp_packet(packet: &[u8]) -> Option<Ipv4UdpPacket> {
    if packet.len() < 28 {
        return None;
    }

    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len + 8 {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len + 8 || total_len > packet.len() {
        return None;
    }

    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    let is_fragmented = (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0;
    if is_fragmented {
        return None;
    }

    if packet[9] != 17 {
        return None;
    }

    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let identification = u16::from_be_bytes([packet[4], packet[5]]);

    let udp_start = header_len;
    let udp_len = u16::from_be_bytes([packet[udp_start + 4], packet[udp_start + 5]]) as usize;
    if udp_len < 8 || udp_start + udp_len > total_len {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[udp_start], packet[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([packet[udp_start + 2], packet[udp_start + 3]]);
    let payload = packet[(udp_start + 8)..(udp_start + udp_len)].to_vec();

    Some(Ipv4UdpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
        identification,
    })
}

fn parse_ipv4_icmp_echo_packet(packet: &[u8]) -> Option<Ipv4IcmpEchoPacket> {
    if packet.len() < 28 {
        return None;
    }

    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len + 8 {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len + 8 || total_len > packet.len() {
        return None;
    }

    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    let is_fragmented = (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0;
    if is_fragmented {
        return None;
    }

    if packet[9] != 1 {
        return None;
    }

    let icmp_start = header_len;
    let icmp_type = packet[icmp_start];
    let icmp_code = packet[icmp_start + 1];
    if icmp_type != 8 || icmp_code != 0 {
        return None;
    }

    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let identification = u16::from_be_bytes([packet[4], packet[5]]);
    let echo_identifier = u16::from_be_bytes([packet[icmp_start + 4], packet[icmp_start + 5]]);
    let echo_sequence = u16::from_be_bytes([packet[icmp_start + 6], packet[icmp_start + 7]]);

    Some(Ipv4IcmpEchoPacket {
        src_ip,
        dst_ip,
        identification,
        echo_identifier,
        echo_sequence,
        icmp_segment: packet[icmp_start..total_len].to_vec(),
    })
}

fn parse_ipv4_tcp_packet(packet: &[u8]) -> Option<Ipv4TcpPacket> {
    if packet.len() < 40 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let ip_hdr_len = ihl * 4;
    if packet[9] != 6 {
        return None; // not TCP
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len > packet.len() || total_len < ip_hdr_len + 20 {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ip_hdr_len..total_len];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack_seq = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;
    if tcp_hdr_len < 20 || tcp.len() < tcp_hdr_len {
        return None;
    }
    let flags = tcp[13];
    let payload = tcp[tcp_hdr_len..].to_vec();
    Some(Ipv4TcpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack_seq,
        flags,
        payload,
    })
}

// ── Packet builders ───────────────────────────────────────────────────────────

fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    identification: u16,
    udp_payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let ip_header_len = 20usize;
    let udp_header_len = 8usize;
    let total_len = ip_header_len + udp_header_len + udp_payload.len();
    if total_len > u16::MAX as usize {
        anyhow::bail!("udp response too large for IPv4 packet");
    }

    let udp_len = (udp_header_len + udp_payload.len()) as u16;
    let mut packet = vec![0_u8; total_len];

    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[10..12].copy_from_slice(&[0, 0]);
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    let udp_start = ip_header_len;
    packet[udp_start..udp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp_start + 2..udp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&[0, 0]);
    packet[(udp_start + 8)..].copy_from_slice(udp_payload);

    let ip_checksum = checksum_ones_complement(&packet[..ip_header_len]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_checksum = udp_checksum_ipv4(src_ip, dst_ip, &packet[udp_start..]);
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    Ok(packet)
}

fn build_ipv4_icmp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identification: u16,
    icmp_segment: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let ip_header_len = 20usize;
    if icmp_segment.len() < 8 {
        anyhow::bail!("icmp response too short");
    }

    let total_len = ip_header_len + icmp_segment.len();
    if total_len > u16::MAX as usize {
        anyhow::bail!("icmp response too large for IPv4 packet");
    }

    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[10..12].copy_from_slice(&[0, 0]);
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    packet[ip_header_len..].copy_from_slice(icmp_segment);
    let icmp_start = ip_header_len;
    packet[icmp_start + 2..icmp_start + 4].copy_from_slice(&[0, 0]);
    let icmp_checksum = checksum_ones_complement(&packet[icmp_start..]);
    packet[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    let ip_checksum = checksum_ones_complement(&packet[..ip_header_len]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    Ok(packet)
}

fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_hlen = 20usize;
    let tcp_hlen = 20usize;
    let total = ip_hlen + tcp_hlen + payload.len();
    let mut pkt = vec![0u8; total];

    // IPv4 header
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = checksum_ones_complement(&pkt[..ip_hlen]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack_seq.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5 (20 bytes, no options)
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&window.to_be_bytes());
    // [36..38] = checksum (computed below); [38..40] = urgent pointer = 0
    if !payload.is_empty() {
        pkt[40..].copy_from_slice(payload);
    }
    let tcp_cksum = tcp_checksum_ipv4(src_ip, dst_ip, &pkt[ip_hlen..]);
    pkt[36..38].copy_from_slice(&tcp_cksum.to_be_bytes());
    pkt
}

// ── Checksum helpers ──────────────────────────────────────────────────────────

fn checksum_ones_complement(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }

    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

fn udp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_segment.len() + (udp_segment.len() % 2));
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_segment);
    if udp_segment.len() % 2 == 1 {
        pseudo.push(0);
    }

    let checksum = checksum_ones_complement(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn tcp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let seg_len = tcp_segment.len();
    let mut pseudo = Vec::with_capacity(12 + seg_len + (seg_len % 2));
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(6); // TCP protocol number
    pseudo.extend_from_slice(&(seg_len as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    if seg_len % 2 == 1 {
        pseudo.push(0);
    }
    let cksum = checksum_ones_complement(&pseudo);
    if cksum == 0 {
        0xffff
    } else {
        cksum
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{forward_frame, TcpFlowTable};
    use bonded_core::session::{SessionFrame, SessionHeader};
    use bytes::Bytes;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    #[tokio::test]
    async fn forwarder_echoes_original_frame_without_upstream() {
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 1,
                sequence: 1,
                flags: 0,
            },
            payload: Bytes::from_static(b"hello"),
        };

        let result = forward_frame(frame.clone(), None, &TcpFlowTable::default())
            .await
            .expect("forwarding should succeed")
            .expect("non-udp frame should be returned");
        assert_eq!(result, frame);
    }

    #[tokio::test]
    async fn forwarder_returns_upstream_response_when_available() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("address should resolve");

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept should succeed");
            let mut incoming = [0_u8; 64];
            let _ = stream
                .read(&mut incoming)
                .await
                .expect("upstream read should succeed");
            stream
                .write_all(b"world")
                .await
                .expect("upstream write should succeed");
        });

        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 1,
                sequence: 2,
                flags: 0,
            },
            payload: Bytes::from_static(b"hello"),
        };

        let result = forward_frame(frame, Some(&addr.to_string()), &TcpFlowTable::default())
            .await
            .expect("forwarding should succeed")
            .expect("upstream response should be returned");
        assert_eq!(&result.payload[..], b"world");

        server_task.await.expect("upstream task should join");
    }

    #[tokio::test]
    async fn forwarder_relays_ipv4_udp_payload_and_builds_response_packet() {
        let udp_listener = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp listener should bind");
        let udp_addr = udp_listener
            .local_addr()
            .expect("udp listener address should resolve");

        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 2048];
            let (size, peer) = udp_listener
                .recv_from(&mut buffer)
                .await
                .expect("udp listener should receive payload");
            assert_eq!(&buffer[..size], b"dns-query");
            udp_listener
                .send_to(b"dns-response", peer)
                .await
                .expect("udp listener should send response");
        });

        let request_payload = build_test_ipv4_udp_packet(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::LOCALHOST,
            53001,
            udp_addr.port(),
            b"dns-query",
        );

        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 9,
                sequence: 42,
                flags: 0,
            },
            payload: request_payload.into(),
        };

        let response = forward_frame(frame, None, &TcpFlowTable::default())
            .await
            .expect("forwarding should succeed")
            .expect("udp relay should return response frame");

        let response_payload = response.payload.to_vec();
        let parsed = super::parse_ipv4_udp_packet(&response_payload)
            .expect("response should be valid ipv4 udp packet");
        assert_eq!(parsed.src_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(parsed.dst_ip, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(&parsed.payload[..], b"dns-response");

        udp_task.await.expect("udp task should join");
    }

    fn build_test_ipv4_udp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        super::build_ipv4_udp_packet(src_ip, dst_ip, src_port, dst_port, 1234, payload)
            .expect("test packet should build")
    }

    #[test]
    fn parses_and_builds_ipv4_icmp_echo_packets() {
        let request_icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x02, b'p', b'i', b'n', b'g'];
        let request = super::build_ipv4_icmp_packet(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(1, 1, 1, 1),
            0x9abc,
            &request_icmp,
        )
        .expect("request packet should build");

        let parsed = super::parse_ipv4_icmp_echo_packet(&request)
            .expect("request packet should parse as icmp echo");
        assert_eq!(parsed.src_ip, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(parsed.dst_ip, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.identification, 0x9abc);
        assert_eq!(parsed.echo_identifier, 0x1234);
        assert_eq!(parsed.echo_sequence, 2);

        let reply_icmp = vec![0, 0, 0, 0, 0x12, 0x34, 0x00, 0x02, b'p', b'o', b'n', b'g'];
        let reply = super::build_ipv4_icmp_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(10, 8, 0, 2),
            parsed.identification,
            &reply_icmp,
        )
        .expect("reply packet should build");

        assert_eq!(reply[9], 1, "reply must be IPv4 ICMP protocol");
        let ihl = (reply[0] & 0x0f) as usize;
        let icmp_start = ihl * 4;
        assert_eq!(reply[icmp_start], 0, "icmp type must be echo reply");
        assert_eq!(reply[icmp_start + 4], 0x12);
        assert_eq!(reply[icmp_start + 5], 0x34);
    }
}
