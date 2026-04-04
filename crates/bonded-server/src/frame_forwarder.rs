use bonded_core::session::SessionFrame;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};
use tracing::debug;

#[derive(Debug, Clone)]
struct Ipv4UdpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
    identification: u16,
}

#[derive(Debug, Clone)]
struct Ipv4IcmpEchoPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identification: u16,
    echo_identifier: u16,
    echo_sequence: u16,
    icmp_segment: Vec<u8>,
}

pub async fn forward_frame(
    frame: SessionFrame,
    upstream_tcp_target: Option<&str>,
) -> anyhow::Result<Option<SessionFrame>> {
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
            // identifier with the socket's own ephemeral identifier.  Only check
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

#[cfg(test)]
mod tests {
    use super::forward_frame;
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

        let result = forward_frame(frame.clone(), None)
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

        let result = forward_frame(frame, Some(&addr.to_string()))
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

        let response = forward_frame(frame, None)
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
