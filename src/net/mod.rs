//! Async UDP and TCP listeners. Both delegate all protocol logic to
//! [`crate::handler::Handler`] and only concern themselves with framing,
//! concurrency bounds, and jitter-delayed sending.

mod tcp;
mod udp;

pub use tcp::serve_tcp;
pub use udp::serve_udp;
