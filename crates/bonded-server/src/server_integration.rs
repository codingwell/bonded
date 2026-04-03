use crate::auth_handshake::perform_auth_handshake;
use crate::authorized_keys::AuthorizedKeysStore;
use bonded_client::establish_naive_tcp_session;
use bonded_core::auth::{sign_auth_challenge, DeviceKeypair};
use bonded_core::config::ClientConfig;
use bonded_core::session::{SessionFrame, SessionHeader};
use bonded_core::transport::{NaiveTcpTransport, Transport, WebSocketTlsTransport};
use bytes::Bytes;
use serde_json::Value;
use std::fs;
use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::Connector;

fn temp_file_path(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("bonded-{name}-{stamp}.toml"))
}

fn test_tls_configs() -> (TlsAcceptor, Connector) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("test cert should generate");
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .expect("server config should build");

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der))
        .expect("root cert should add");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (
        TlsAcceptor::from(Arc::new(server_config)),
        Connector::Rustls(Arc::new(client_config)),
    )
}

#[tokio::test]
async fn authenticated_client_can_exchange_session_frame() {
    let keypair = DeviceKeypair::generate();
    let path = temp_file_path("server-e2e");
    let invites = temp_file_path("server-e2e-invites");
    fs::write(
        &path,
        format!(
            "[[devices]]\ndevice_id = \"linux-cli\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys file should be written");
    fs::write(
        &invites,
        r#"[[tokens]]
token = "pair-me"
expires_at = "unix:9999999999"
uses_remaining = 1
"#,
    )
    .expect("invite tokens file should be written");

    let store = AuthorizedKeysStore::load(&path).expect("authorized keys should load");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local address should resolve");

    let invites_for_server = invites.clone();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        let (public_key, stream) = perform_auth_handshake(stream, store, &invites_for_server)
            .await
            .expect("handshake should succeed");
        let mut transport = NaiveTcpTransport::from_stream(stream);
        let frame = transport.recv().await.expect("server should receive frame");
        (public_key, frame)
    });

    let stream = TcpStream::connect(addr)
        .await
        .expect("client should connect to server");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let hello = serde_json::json!({
        "public_key_b64": keypair.public_key_b64,
        "invite_token": "",
    });
    write_half
        .write_all(format!("{}\n", hello).as_bytes())
        .await
        .expect("hello should be written");

    let mut challenge_line = String::new();
    reader
        .read_line(&mut challenge_line)
        .await
        .expect("challenge should be readable");
    let challenge: Value =
        serde_json::from_str(challenge_line.trim_end()).expect("challenge json should parse");
    let challenge_b64 = challenge["challenge_b64"]
        .as_str()
        .expect("challenge should include challenge_b64");

    let signature_b64 =
        sign_auth_challenge(&keypair, challenge_b64).expect("challenge should be signable");
    let proof = serde_json::json!({
        "signature_b64": signature_b64,
    });
    write_half
        .write_all(format!("{}\n", proof).as_bytes())
        .await
        .expect("proof should be written");

    let mut result_line = String::new();
    reader
        .read_line(&mut result_line)
        .await
        .expect("result should be readable");
    let result: Value = serde_json::from_str(result_line.trim_end()).expect("result should parse");
    assert_eq!(result["status"], "ok");

    let stream = reader
        .into_inner()
        .reunite(write_half)
        .expect("stream halves should reunite");
    let mut transport = NaiveTcpTransport::from_stream(stream);
    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 77,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"frame-payload"),
        })
        .await
        .expect("client should send framed payload");

    let (public_key, received) = server_task.await.expect("server task should join");
    assert_eq!(public_key, keypair.public_key_b64);
    assert_eq!(received.header.connection_id, 77);
    assert_eq!(received.header.sequence, 0);
    assert_eq!(&received.payload[..], b"frame-payload");

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(invites);
}

#[tokio::test]
async fn authenticated_websocket_client_can_exchange_session_frame() {
    let keypair = DeviceKeypair::generate();
    let path = temp_file_path("server-ws-e2e");
    let invites = temp_file_path("server-ws-e2e-invites");
    fs::write(
        &path,
        format!(
            "[[devices]]\ndevice_id = \"linux-cli\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys file should be written");
    fs::write(
        &invites,
        r#"[[tokens]]
token = "pair-me"
expires_at = "unix:9999999999"
uses_remaining = 1
"#,
    )
    .expect("invite tokens file should be written");

    let store = AuthorizedKeysStore::load(&path).expect("authorized keys should load");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local address should resolve");
    let (tls_acceptor, tls_connector) = test_tls_configs();

    let invites_for_server = invites.clone();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        let mut transport = WebSocketTlsTransport::accept_tls(stream, tls_acceptor)
            .await
            .expect("wss should accept");
        let public_key = crate::auth_handshake::perform_websocket_auth_handshake(
            &mut transport,
            store,
            &invites_for_server,
        )
        .await
        .expect("websocket handshake should succeed");

        let frame = transport
            .recv()
            .await
            .expect("server should receive websocket frame");
        (public_key, frame)
    });

    let mut transport = WebSocketTlsTransport::connect_with_connector(
        &format!("wss://localhost:{}", addr.port()),
        tls_connector,
    )
    .await
    .expect("client websocket should connect");

    let hello = serde_json::json!({
        "public_key_b64": keypair.public_key_b64,
        "invite_token": "",
    });
    transport
        .send_text(&hello.to_string())
        .await
        .expect("hello should be written");

    let challenge_line = transport
        .recv_text()
        .await
        .expect("challenge should be readable");
    let challenge: Value =
        serde_json::from_str(challenge_line.trim_end()).expect("challenge json should parse");
    let challenge_b64 = challenge["challenge_b64"]
        .as_str()
        .expect("challenge should include challenge_b64");

    let signature_b64 =
        sign_auth_challenge(&keypair, challenge_b64).expect("challenge should be signable");
    let proof = serde_json::json!({
        "signature_b64": signature_b64,
    });
    transport
        .send_text(&proof.to_string())
        .await
        .expect("proof should be written");

    let result_line = transport
        .recv_text()
        .await
        .expect("result should be readable");
    let result: Value = serde_json::from_str(result_line.trim_end()).expect("result should parse");
    assert_eq!(result["status"], "ok");

    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 78,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"ws-frame-payload"),
        })
        .await
        .expect("client should send websocket framed payload");

    let (public_key, received) = server_task.await.expect("server task should join");
    assert_eq!(public_key, keypair.public_key_b64);
    assert_eq!(received.header.connection_id, 78);
    assert_eq!(received.header.sequence, 0);
    assert_eq!(&received.payload[..], b"ws-frame-payload");

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(invites);
}

#[tokio::test]
#[ignore = "manual diagnostic: requires internet egress from server host and may be flaky in CI"]
async fn localhost_server_and_rust_client_can_probe_public_dns_udp() {
    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-dns-e2e-keys");
    let invites_path = temp_file_path("server-dns-e2e-invites");
    let private_key_path = temp_file_path("server-dns-e2e-private");
    let public_key_path = temp_file_path("server-dns-e2e-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"rust-e2e\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys file should be written");

    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invite tokens file should be written");

    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key file should be written");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key file should be written");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("invite path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            "",
            &invite_for_server,
            store,
            crate::session_registry::SessionRegistry::default(),
        )
        .await
    });

    let mut connected = false;
    let mut last_error = String::new();
    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);
                let (query, query_id) = build_dns_query_example_com();
                eprintln!(
                    "[DNS Test] Sending query to 8.8.8.8:53, query_id=0x{:04x}, payload_len={}",
                    query_id,
                    query.len()
                );
                let udp_packet = build_ipv4_udp_packet(
                    Ipv4Addr::new(10, 8, 0, 2),
                    Ipv4Addr::new(8, 8, 8, 8),
                    53001,
                    53,
                    4242,
                    &query,
                )
                .expect("dns probe packet should build");

                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 900,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: udp_packet.into(),
                    })
                    .await
                    .expect("dns probe frame should send");

                let recv = timeout(Duration::from_secs(5), transport.recv()).await;
                match recv {
                    Ok(Ok(frame)) => {
                        let parsed = parse_ipv4_udp_packet(&frame.payload)
                            .expect("dns response should be ipv4+udp");
                        assert_eq!(parsed.src_ip, Ipv4Addr::new(8, 8, 8, 8));
                        assert_eq!(parsed.dst_ip, Ipv4Addr::new(10, 8, 0, 2));
                        assert_eq!(parsed.src_port, 53);
                        assert_eq!(parsed.dst_port, 53001);
                        assert!(
                            parsed.payload.len() >= 12,
                            "dns payload too small: {} bytes",
                            parsed.payload.len()
                        );
                        eprintln!(
                            "[DNS Test] Received UDP response, payload_len={}",
                            parsed.payload.len()
                        );

                        // Validate DNS response header
                        let dns_response = &parsed.payload;
                        if dns_response.len() >= 12 {
                            let resp_id = u16::from_be_bytes([dns_response[0], dns_response[1]]);
                            let flags = u16::from_be_bytes([dns_response[2], dns_response[3]]);
                            let qd_count = u16::from_be_bytes([dns_response[4], dns_response[5]]);
                            let an_count = u16::from_be_bytes([dns_response[6], dns_response[7]]);
                            let ns_count = u16::from_be_bytes([dns_response[8], dns_response[9]]);
                            let ar_count = u16::from_be_bytes([dns_response[10], dns_response[11]]);

                            eprintln!(
                                "[DNS Test] Response ID: 0x{:04x} (expected 0x{:04x})",
                                resp_id, query_id
                            );
                            eprintln!("[DNS Test] Flags: 0x{:04x} (QR={}, OPCODE={}, AA={}, TC={}, RD={}, RA={}, RCODE={})",
                                flags,
                                (flags >> 15) & 1,
                                (flags >> 11) & 0xf,
                                (flags >> 10) & 1,
                                (flags >> 9) & 1,
                                (flags >> 8) & 1,
                                (flags >> 7) & 1,
                                flags & 0xf
                            );
                            eprintln!(
                                "[DNS Test] Counts: QD={}, AN={}, NS={}, AR={}",
                                qd_count, an_count, ns_count, ar_count
                            );

                            // Validate response basics
                            assert_eq!(resp_id, query_id, "DNS response ID mismatch");
                            assert_eq!((flags >> 15) & 1, 1, "DNS response flag (QR) not set");
                            let rcode = flags & 0xf;
                            assert_eq!(rcode, 0, "DNS response code indicates error: {}", rcode);

                            if an_count > 0 {
                                eprintln!("[DNS Test] ✓ Response contains {} answer record(s), DNS query succeeded", an_count);
                            } else {
                                eprintln!("[DNS Test] ⚠ Response has no answer records (possible NODATA/NXDOMAIN)");
                            }
                        } else {
                            eprintln!("[DNS Test] ⚠ DNS payload too short to parse header");
                        }
                    }
                    Ok(Err(err)) => {
                        panic!("dns probe frame receive failed: {err}");
                    }
                    Err(_) => {
                        panic!(
                            "timed out waiting for DNS response frame from server. \
                             Check server internet UDP egress and frame_forwarder UDP timeout."
                        );
                    }
                }

                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    if !connected {
        panic!("rust client failed to connect/authenticate to local server: {last_error}");
    }

    server_task.abort();

    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

async fn try_establish_client_stream(
    bind: &str,
    private_key_path: &std::path::Path,
    public_key_path: &std::path::Path,
) -> Result<tokio::net::TcpStream, String> {
    let mut cfg = ClientConfig::default();
    cfg.client.server_public_address = bind.to_owned();
    cfg.client.server_websocket_address = bind.to_owned();
    cfg.client.private_key_path = private_key_path.display().to_string();
    cfg.client.public_key_path = public_key_path.display().to_string();
    cfg.client.invite_token = String::new();
    cfg.client.preferred_protocols = vec!["naive_tcp".to_owned()];

    establish_naive_tcp_session(&cfg)
        .await
        .map_err(|err| err.to_string())
}

fn pick_ephemeral_bind() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("ephemeral bind should work");
    let addr = listener
        .local_addr()
        .expect("ephemeral local address should resolve");
    format!("127.0.0.1:{}", addr.port())
}

fn build_dns_query_example_com() -> (Vec<u8>, u16) {
    let query_id: u16 = 0x1234;
    let payload = vec![
        0x12, 0x34, 0x01, 0x00, // id + standard query with recursion desired
        0x00, 0x01, 0x00, 0x00, // qdcount=1, ancount=0
        0x00, 0x00, 0x00, 0x00, // nscount=0, arcount=0
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // qname
        0x00, 0x01, // qtype=A
        0x00, 0x01, // qclass=IN
    ];
    (payload, query_id)
}

#[derive(Debug, Clone)]
struct Ipv4UdpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
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

    if packet[9] != 17 {
        return None;
    }

    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

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
        anyhow::bail!("udp packet too large for ipv4");
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
