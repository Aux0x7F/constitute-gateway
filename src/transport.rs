use anyhow::Result;
use tokio::net::UdpSocket;

pub async fn start_udp(bind: &str) -> Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    tracing::info!(bind = %bind, "udp listener ready (stub)");

    let mut buf = [0u8; 1500];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        tracing::info!(from = %from, len, "udp packet (stub)");
    }
}

pub async fn start_quic_stub() -> Result<()> {
    tracing::info!("quic listener disabled (stub)");
    Ok(())
}
