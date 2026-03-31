use bonded_core::session::SessionFrame;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn forward_frame(
    frame: SessionFrame,
    upstream_tcp_target: Option<&str>,
) -> anyhow::Result<SessionFrame> {
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
            return Ok(SessionFrame {
                header: frame.header,
                payload: response.into(),
            });
        }
    }

    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::forward_frame;
    use bonded_core::session::{SessionFrame, SessionHeader};
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
            .expect("forwarding should succeed");
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
            .expect("forwarding should succeed");
        assert_eq!(&result.payload[..], b"world");

        server_task.await.expect("upstream task should join");
    }
}
