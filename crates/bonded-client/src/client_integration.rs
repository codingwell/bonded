use crate::{establish_naive_tcp_session, establish_naive_tcp_sessions};
use bonded_core::auth::{create_auth_challenge, verify_auth_challenge, DeviceKeypair};
use bonded_core::config::{ClientConfig, ClientSection};
use bonded_core::session::{SessionFrame, SessionHeader};
use bonded_core::transport::{NaiveTcpTransport, Transport};
use bytes::Bytes;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

fn temp_file_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("bonded-client-integration-{name}-{stamp}.txt"))
}

fn test_client_config(addr: String, keypair: &DeviceKeypair) -> ClientConfig {
    let private_key_path = temp_file_path("private");
    let public_key_path = temp_file_path("public");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    ClientConfig {
        client: ClientSection {
            server_public_address: addr,
            private_key_path: private_key_path.to_string_lossy().to_string(),
            public_key_path: public_key_path.to_string_lossy().to_string(),
            ..ClientConfig::default().client
        },
    }
}

async fn server_handshake(stream: TcpStream, expected_public_key: &str) -> TcpStream {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut hello_line = String::new();
    reader
        .read_line(&mut hello_line)
        .await
        .expect("hello should be readable");
    let hello: serde_json::Value =
        serde_json::from_str(hello_line.trim_end()).expect("hello should parse");
    assert_eq!(
        hello["public_key_b64"].as_str().unwrap_or_default(),
        expected_public_key
    );

    let challenge_b64 = create_auth_challenge();
    let challenge = json!({ "challenge_b64": challenge_b64 });
    write_half
        .write_all(format!("{}\n", challenge).as_bytes())
        .await
        .expect("challenge should be written");

    let mut proof_line = String::new();
    reader
        .read_line(&mut proof_line)
        .await
        .expect("proof should be readable");
    let proof: serde_json::Value =
        serde_json::from_str(proof_line.trim_end()).expect("proof should parse");
    let signature_b64 = proof["signature_b64"]
        .as_str()
        .expect("signature should exist");
    verify_auth_challenge(expected_public_key, &challenge_b64, signature_b64)
        .expect("signature should verify");

    write_half
        .write_all(b"{\"status\":\"ok\"}\n")
        .await
        .expect("status should be written");

    reader
        .into_inner()
        .reunite(write_half)
        .expect("stream should reunite")
}

#[tokio::test]
async fn single_path_authenticated_frame_exchange() {
    let keypair = DeviceKeypair::generate();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("addr should resolve");

    let expected_public_key = keypair.public_key_b64.clone();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        let stream = server_handshake(stream, &expected_public_key).await;
        let mut transport = NaiveTcpTransport::from_stream(stream);
        let frame = transport.recv().await.expect("frame should arrive");
        transport.send(frame).await.expect("echo should send");
    });

    let cfg = test_client_config(addr.to_string(), &keypair);
    let stream = establish_naive_tcp_session(&cfg)
        .await
        .expect("session should authenticate");
    let mut transport = NaiveTcpTransport::from_stream(stream);
    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 5,
                sequence: 1,
                flags: 0,
            },
            payload: Bytes::from_static(b"hello"),
        })
        .await
        .expect("send should succeed");

    let echoed = transport.recv().await.expect("echo should arrive");
    assert_eq!(&echoed.payload[..], b"hello");

    server_task.await.expect("server task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn multipath_failover_continues_exchange() {
    let keypair = DeviceKeypair::generate();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("addr should resolve");

    let expected_public_key = keypair.public_key_b64.clone();
    let server_task = tokio::spawn(async move {
        let (first_stream, _) = listener.accept().await.expect("first accept should succeed");
        let first_stream = server_handshake(first_stream, &expected_public_key).await;
        drop(first_stream);

        let (second_stream, _) = listener.accept().await.expect("second accept should succeed");
        let second_stream = server_handshake(second_stream, &expected_public_key).await;
        let mut transport = NaiveTcpTransport::from_stream(second_stream);
        let frame = transport.recv().await.expect("fallback frame should arrive");
        transport.send(frame).await.expect("fallback echo should send");
    });

    let cfg = test_client_config(addr.to_string(), &keypair);
    let streams = establish_naive_tcp_sessions(&cfg, 2)
        .await
        .expect("both paths should authenticate");
    let mut paths: Vec<NaiveTcpTransport> = streams
        .into_iter()
        .map(NaiveTcpTransport::from_stream)
        .collect();

    let frame = SessionFrame {
        header: SessionHeader {
            connection_id: 9,
            sequence: 2,
            flags: 0,
        },
        payload: Bytes::from_static(b"survive"),
    };

    // Path 0 may already be closed at send time; either send or recv must fail.
    let first_send = paths[0].send(frame.clone()).await;
    if first_send.is_ok() {
        let timed_out = timeout(Duration::from_millis(300), paths[0].recv()).await;
        assert!(timed_out.is_err() || timed_out.unwrap().is_err());
    } else {
        assert!(first_send.is_err());
    }

    paths[1].send(frame).await.expect("fallback send should work");
    let echoed = paths[1].recv().await.expect("fallback echo should arrive");
    assert_eq!(&echoed.payload[..], b"survive");

    server_task.await.expect("server task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}
