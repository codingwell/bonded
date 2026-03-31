use async_trait::async_trait;

use crate::session::SessionFrame;

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
