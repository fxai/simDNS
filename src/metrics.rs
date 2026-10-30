//! Runtime metrics, exposed over an optional HTTP endpoint so a SOC analyst can
//! align tool-side counters against SIEM alert timestamps.
//!
//! Counters are plain atomics; the HTTP layer only reads them. The endpoint
//! serves both a human/JSON view (`/metrics.json`) and a Prometheus text view
//! (`/metrics`) so it can drop straight into existing lab scrape configs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};

#[derive(Debug, Default)]
pub struct Metrics {
    pub queries_total: AtomicU64,
    pub queries_in_zone: AtomicU64,
    pub queries_refused: AtomicU64,
    pub responses_nxdomain: AtomicU64,
    pub responses_servfail: AtomicU64,
    pub responses_formerr: AtomicU64,
    pub answers_txt: AtomicU64,
    pub answers_a: AtomicU64,
    pub answers_aaaa: AtomicU64,
    pub answers_cname: AtomicU64,
    pub answers_null: AtomicU64,
    pub inbound_payload_bytes: AtomicU64,
    pub outbound_answer_bytes: AtomicU64,
    pub sessions_created: AtomicU64,
    pub sessions_rejected: AtomicU64,
    pub malformed_packets: AtomicU64,
    pub udp_queries: AtomicU64,
    pub tcp_queries: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[inline]
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        vec![
            ("queries_total", g(&self.queries_total)),
            ("queries_in_zone", g(&self.queries_in_zone)),
            ("queries_refused", g(&self.queries_refused)),
            ("responses_nxdomain", g(&self.responses_nxdomain)),
            ("responses_servfail", g(&self.responses_servfail)),
            ("responses_formerr", g(&self.responses_formerr)),
            ("answers_txt", g(&self.answers_txt)),
            ("answers_a", g(&self.answers_a)),
            ("answers_aaaa", g(&self.answers_aaaa)),
            ("answers_cname", g(&self.answers_cname)),
            ("answers_null", g(&self.answers_null)),
            ("inbound_payload_bytes", g(&self.inbound_payload_bytes)),
            ("outbound_answer_bytes", g(&self.outbound_answer_bytes)),
            ("sessions_created", g(&self.sessions_created)),
            ("sessions_rejected", g(&self.sessions_rejected)),
            ("malformed_packets", g(&self.malformed_packets)),
            ("udp_queries", g(&self.udp_queries)),
            ("tcp_queries", g(&self.tcp_queries)),
        ]
    }
}

#[derive(Clone)]
struct MetricsState {
    metrics: Arc<Metrics>,
    sessions_live: Arc<dyn Fn() -> usize + Send + Sync>,
}

pub fn router(metrics: Arc<Metrics>, sessions_live: Arc<dyn Fn() -> usize + Send + Sync>) -> Router {
    let state = MetricsState { metrics, sessions_live };
    Router::new()
        .route("/metrics", get(prometheus))
        .route("/metrics.json", get(json))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

async fn json(State(state): State<MetricsState>) -> impl IntoResponse {
    let mut body = String::from("{");
    let mut first = true;
    for (k, v) in state.metrics.snapshot() {
        if !first {
            body.push(',');
        }
        first = false;
        body.push_str(&format!("\"{k}\":{v}"));
    }
    body.push_str(&format!(",\"sessions_live\":{}", (state.sessions_live.as_ref())()));
    body.push('}');
    ([("content-type", "application/json")], body)
}

async fn prometheus(State(state): State<MetricsState>) -> impl IntoResponse {
    let mut body = String::new();
    for (k, v) in state.metrics.snapshot() {
        body.push_str(&format!("# TYPE simdns_{k} counter\nsimdns_{k} {v}\n"));
    }
    body.push_str("# TYPE simdns_sessions_live gauge\n");
    body.push_str(&format!("simdns_sessions_live {}\n", (state.sessions_live.as_ref())()));
    ([("content-type", "text/plain; version=0.0.4")], body)
}
