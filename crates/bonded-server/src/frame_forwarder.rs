use bonded_core::session::SessionFrame;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
struct Ipv4UdpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
    identification: u16,
}

pub async fn forward_frame(
    frame: SessionFrame,
    upstream_tcp_target: Option<&str>,
) -> anyhow::Result<Option<SessionFrame>> {
    if let Some(udp_packet) = parse_ipv4_udp_packet(&frame.payload) {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = SocketAddrV4::new(udp_packet.dst_ip, udp_packet.dst_port);
        socket.send_to(&udp_packet.payload, target).await?;

        let mut response = vec![0_u8; 65535];
        let read_size = match timeout(Duration::from_millis(1200), socket.recv(&mut response)).await
        {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };

        response.truncate(read_size);
        let response_packet = build_ipv4_udp_packet(
            udp_packet.dst_ip,
            udp_packet.src_ip,
            udp_packet.dst_port,
            udp_packet.src_port,
            udp_packet.identification,
            &response,
        )?;
        return Ok(Some(SessionFrame {
            header: frame.header,
            payload: response_packet.into(),
        }));
    }

    if let Some(target) = upstream_tcp_target.filter(|value| !value.trim().is_empty()) {
        let mut upstream = TcpStream::connect(target).await?;
        upstream.write_all(&frame.payload).await?;
        upstream.flush().await?;

        let mut response = vec![0_u8; 8192];
        let read_size = timeout(Duration::from_millis(500), upstream.read(&mut response))
            .await
            .unwrap_or(Ok(0))?;

        if read_size > 0 {
            response.truncate(read_size);
            return Ok(Some(SessionFrame {
                header: frame.header,
                payload: response.into(),
            }));
        }
    }

    Ok(Some(frame))
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
}
