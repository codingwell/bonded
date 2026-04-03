use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream as ServerTlsStream, TlsAcceptor};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{
    accept_async, connect_async, connect_async_tls_with_config, Connector, MaybeTlsStream,
    WebSocketStream,
};

use crate::session::SessionFrame;

const MIN_SESSION_FRAME_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    NaiveTcp,
    WebSocketTls,
    Quic,
}

#[async_trait]
pub trait Transport: Send {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()>;
    async fn recv(&mut self) -> anyhow::Result<SessionFrame>;
    fn kind(&self) -> TransportKind;
}

pub struct NaiveTcpTransport {
    stream: TcpStream,
    /// Accumulates bytes across `select!` cancellations so that `recv()` is cancel-safe.
    read_buf: BytesMut,
}

enum WebSocketStreamInner {
    Client(WebSocketStream<MaybeTlsStream<TcpStream>>),
    Server(WebSocketStream<TcpStream>),
    ServerTls(WebSocketStream<ServerTlsStream<TcpStream>>),
}

pub struct WebSocketTlsTransport {
    stream: WebSocketStreamInner,
}

impl NaiveTcpTransport {
    pub async fn connect(address: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(address).await?;
        Ok(Self { stream, read_buf: BytesMut::new() })
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self { stream, read_buf: BytesMut::new() }
    }
}

impl WebSocketTlsTransport {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let (stream, _response) = connect_async(url).await?;
        Ok(Self {
            stream: WebSocketStreamInner::Client(stream),
        })
    }

    pub async fn connect_with_connector(url: &str, connector: Connector) -> anyhow::Result<Self> {
        let (stream, _response) =
            connect_async_tls_with_config(url, None, false, Some(connector)).await?;
        Ok(Self {
            stream: WebSocketStreamInner::Client(stream),
        })
    }

    pub fn from_client_stream(stream: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            stream: WebSocketStreamInner::Client(stream),
        }
    }

    pub async fn accept(stream: TcpStream) -> anyhow::Result<Self> {
        let stream = accept_async(stream).await?;
        Ok(Self {
            stream: WebSocketStreamInner::Server(stream),
        })
    }

    pub async fn accept_tls(stream: TcpStream, acceptor: TlsAcceptor) -> anyhow::Result<Self> {
        let tls_stream = acceptor.accept(stream).await?;
        let ws_stream = accept_async(tls_stream).await?;
        Ok(Self {
            stream: WebSocketStreamInner::ServerTls(ws_stream),
        })
    }

    pub async fn send_text(&mut self, text: &str) -> anyhow::Result<()> {
        match &mut self.stream {
            WebSocketStreamInner::Client(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
            WebSocketStreamInner::Server(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
            WebSocketStreamInner::ServerTls(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
        }
        Ok(())
    }

    pub async fn recv_text(&mut self) -> anyhow::Result<String> {
        loop {
            let next = match &mut self.stream {
                WebSocketStreamInner::Client(stream) => stream.next().await,
                WebSocketStreamInner::Server(stream) => stream.next().await,
                WebSocketStreamInner::ServerTls(stream) => stream.next().await,
            };

            match next {
                Some(Ok(Message::Text(text))) => return Ok(text),
                Some(Ok(Message::Binary(_))) => {
                    anyhow::bail!("unexpected websocket binary message while awaiting text")
                }
                Some(Ok(Message::Close(_))) => {
                    anyhow::bail!("websocket closed while awaiting text")
                }
                Some(Ok(_)) => continue,
                Some(Err(err)) => return Err(err.into()),
                None => anyhow::bail!("websocket closed while awaiting text"),
            }
        }
    }
}

#[async_trait]
impl Transport for NaiveTcpTransport {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
        let encoded = frame.encode();
        let len = u32::try_from(encoded.len())?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
        // Fill the internal buffer until we have the 4-byte length prefix.
        // Bytes already in `self.read_buf` survive a `tokio::select!` cancellation,
        // making this method cancel-safe.
        while self.read_buf.len() < 4 {
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("connection closed while reading frame length prefix");
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }

        let len = u32::from_be_bytes([
            self.read_buf[0],
            self.read_buf[1],
            self.read_buf[2],
            self.read_buf[3],
        ]) as usize;

        if len < MIN_SESSION_FRAME_LEN {
            anyhow::bail!(
                "invalid session frame length prefix: {len} bytes (minimum {MIN_SESSION_FRAME_LEN})"
            );
        }

        // Fill the buffer until we have the full frame (length prefix + payload).
        while self.read_buf.len() < 4 + len {
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("connection closed while reading frame payload");
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }

        // Consume exactly one frame from the front of the buffer.
        let _ = self.read_buf.split_to(4); // discard 4-byte length prefix
        let frame_bytes = self.read_buf.split_to(len);
        Ok(SessionFrame::decode(&frame_bytes)?)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::NaiveTcp
    }
}

#[async_trait]
impl Transport for WebSocketTlsTransport {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
        let payload = frame.encode().to_vec();
        match &mut self.stream {
            WebSocketStreamInner::Client(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
            WebSocketStreamInner::Server(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
            WebSocketStreamInner::ServerTls(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
        loop {
            let next = match &mut self.stream {
                WebSocketStreamInner::Client(stream) => stream.next().await,
                WebSocketStreamInner::Server(stream) => stream.next().await,
                WebSocketStreamInner::ServerTls(stream) => stream.next().await,
            };

            match next {
                Some(Ok(Message::Binary(raw))) => return Ok(SessionFrame::decode(&raw)?),
                Some(Ok(Message::Close(_))) => anyhow::bail!("websocket closed"),
                Some(Ok(_)) => continue,
                Some(Err(err)) => return Err(err.into()),
                None => anyhow::bail!("websocket closed"),
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::WebSocketTls
    }
}

#[cfg(test)]
mod tests {
    use super::{NaiveTcpTransport, Transport, TransportKind, WebSocketTlsTransport};
    use crate::session::{SessionFrame, SessionHeader};
    use bytes::Bytes;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn naive_tcp_transport_exchanges_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("local addr should resolve");

        let server_task = tokio::spawn(async move {
            let (server_stream, _) = listener.accept().await.expect("accept should succeed");
            let mut server_transport = NaiveTcpTransport::from_stream(server_stream);
            let frame = server_transport
                .recv()
                .await
                .expect("server should recv frame");
            assert_eq!(frame.header.connection_id, 88);
            assert_eq!(&frame.payload[..], b"ping");

            let response = SessionFrame {
                header: SessionHeader {
                    connection_id: 88,
                    sequence: 1,
                    flags: 0,
                },
                payload: Bytes::from_static(b"pong"),
            };
            server_transport
                .send(response)
                .await
                .expect("server should send response");
        });

        let mut client_transport = NaiveTcpTransport::connect(&address.to_string())
            .await
            .expect("client should connect");
        assert_eq!(client_transport.kind(), TransportKind::NaiveTcp);

        let request = SessionFrame {
            header: SessionHeader {
                connection_id: 88,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"ping"),
        };
        client_transport
            .send(request)
            .await
            .expect("client should send request");

        let response = client_transport
            .recv()
            .await
            .expect("client should receive response");
        assert_eq!(response.header.sequence, 1);
        assert_eq!(&response.payload[..], b"pong");

        server_task.await.expect("server task should join");
    }

    #[tokio::test]
    async fn websocket_transport_exchanges_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("local addr should resolve");

        let server_task = tokio::spawn(async move {
            let (server_stream, _) = listener.accept().await.expect("accept should succeed");
            let mut server_transport = WebSocketTlsTransport::accept(server_stream)
                .await
                .expect("server websocket should accept");
            let frame = server_transport
                .recv()
                .await
                .expect("server should recv websocket frame");
            assert_eq!(frame.header.connection_id, 66);
            assert_eq!(&frame.payload[..], b"hello-ws");

            let response = SessionFrame {
                header: SessionHeader {
                    connection_id: 66,
                    sequence: 1,
                    flags: 0,
                },
                payload: Bytes::from_static(b"world-ws"),
            };
            server_transport
                .send(response)
                .await
                .expect("server should send websocket response");
        });

        let mut client_transport = WebSocketTlsTransport::connect(&format!("ws://{address}"))
            .await
            .expect("client websocket should connect");
        assert_eq!(client_transport.kind(), TransportKind::WebSocketTls);

        let request = SessionFrame {
            header: SessionHeader {
                connection_id: 66,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"hello-ws"),
        };
        client_transport
            .send(request)
            .await
            .expect("client should send websocket request");

        let response = client_transport
            .recv()
            .await
            .expect("client should recv websocket response");
        assert_eq!(response.header.sequence, 1);
        assert_eq!(&response.payload[..], b"world-ws");

        server_task.await.expect("server task should join");
    }
}
