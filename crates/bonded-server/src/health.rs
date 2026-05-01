use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub async fn run_health_server(bind: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, "health listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                error!(error = %err, "failed to accept health connection");
                continue;
            }
        };

        tokio::spawn(async move {
            if let Err(err) = handle_health_connection(stream).await {
                error!(peer = %peer, error = %err, "health request handling failed");
            }
        });
    }
}

async fn handle_health_connection(mut stream: TcpStream) -> anyhow::Result<()> {
    let mut buffer = [0_u8; 1024];
    let _read = stream.read(&mut buffer).await?;

    let response = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\nconnection: close\r\n\r\nOK";
    stream.write_all(response).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_health_server;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    #[tokio::test]
    async fn health_endpoint_returns_ok_response() {
        let probe = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe listener should bind");
        let addr = probe.local_addr().expect("probe addr should resolve");
        drop(probe);

        let bind = addr.to_string();
        let health_task = tokio::spawn(async move { run_health_server(&bind).await });

        let mut stream = None;
        for _ in 0..10 {
            match TcpStream::connect(addr).await {
                Ok(candidate) => {
                    stream = Some(candidate);
                    break;
                }
                Err(_) => sleep(Duration::from_millis(20)).await,
            }
        }
        let mut stream = stream.expect("health server should accept connection");
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request should be written");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("response should be readable");
        let text = String::from_utf8(response).expect("response should be utf8");
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.ends_with("OK"));

        health_task.abort();
    }
}
