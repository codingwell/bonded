use crate::auth_handshake::perform_auth_handshake;
use crate::authorized_keys::AuthorizedKeysStore;
use bonded_core::auth::{sign_auth_challenge, DeviceKeypair};
use bonded_core::session::{SessionFrame, SessionHeader};
use bonded_core::transport::{NaiveTcpTransport, Transport};
use bytes::Bytes;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

fn temp_file_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("bonded-{name}-{stamp}.toml"))
}

#[tokio::test]
async fn authenticated_client_can_exchange_session_frame() {
    let keypair = DeviceKeypair::generate();
    let path = temp_file_path("server-e2e");
    fs::write(
        &path,
        format!(
            "[[devices]]\ndevice_id = \"linux-cli\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys file should be written");

    let store = AuthorizedKeysStore::load(&path).expect("authorized keys should load");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local address should resolve");

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        let (public_key, stream) = perform_auth_handshake(stream, store)
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
}
