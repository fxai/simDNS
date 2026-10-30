use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::handler::{Handler, Transport};

/// Serve DNS over UDP. Each datagram is handled on its own task so a jittered
/// response never blocks the receive loop.
pub async fn serve_udp(socket: Arc<UdpSocket>, handler: Arc<Handler>) {
    // 64 KiB is the maximum UDP payload; one reusable receive buffer.
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "simdns::udp", error = %e, "udp recv failed");
                continue;
            }
        };
        let raw = buf[..n].to_vec();
        let handler = handler.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let outcome = handler.handle(&raw, Some(src.ip()), Transport::Udp);
            outcome.log.emit();
            if !outcome.jitter.is_zero() {
                tokio::time::sleep(outcome.jitter).await;
            }
            if let Err(e) = socket.send_to(&outcome.response, src).await {
                tracing::warn!(target: "simdns::udp", error = %e, peer = %src, "udp send failed");
            }
        });
    }
}
