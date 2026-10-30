use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::handler::{Handler, Transport};

/// Serve DNS over TCP (RFC 1035 §4.2.2: 2-byte big-endian length prefix per
/// message). A semaphore caps concurrent connections so a flood can't exhaust
/// file descriptors or memory.
pub async fn serve_tcp(
    listener: TcpListener,
    handler: Arc<Handler>,
    max_connections: usize,
    max_message_bytes: usize,
) {
    let permits = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "simdns::tcp", error = %e, "tcp accept failed");
                continue;
            }
        };

        // Shed load rather than queue unboundedly when at capacity.
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(target: "simdns::tcp", peer = %peer, "tcp connection limit reached; dropping");
                continue;
            }
        };

        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the connection's lifetime
            let mut stream = stream;
            // A single connection may carry multiple sequential queries.
            loop {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    break; // clean EOF or reset
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len == 0 || len > max_message_bytes {
                    tracing::warn!(target: "simdns::tcp", peer = %peer, len, "tcp message length out of bounds; closing");
                    break;
                }
                let mut msg = vec![0u8; len];
                if stream.read_exact(&mut msg).await.is_err() {
                    break;
                }

                let outcome = handler.handle(&msg, Some(peer.ip()), Transport::Tcp);
                outcome.log.emit();
                if !outcome.jitter.is_zero() {
                    tokio::time::sleep(outcome.jitter).await;
                }

                let resp = &outcome.response;
                if resp.len() > u16::MAX as usize {
                    tracing::warn!(target: "simdns::tcp", peer = %peer, "response exceeds TCP frame limit; closing");
                    break;
                }
                let frame_len = (resp.len() as u16).to_be_bytes();
                if stream.write_all(&frame_len).await.is_err() || stream.write_all(resp).await.is_err() {
                    break;
                }
                let _ = stream.flush().await;
            }
        });
    }
}
