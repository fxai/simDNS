//! In-memory session tracking with TTL-based eviction and a hard capacity cap.
//!
//! The emulated protocol carries a session id in the query (see the wire-format
//! doc). Tracking it lets the telemetry correlate a sequence of chunked queries
//! as one logical "transfer", which is exactly what a detection rule keys on.
//!
//! Memory is bounded two ways: idle sessions expire after `ttl`, and the total
//! count is capped at `max_sessions` (new sessions past the cap are rejected,
//! surfaced as a counter rather than unbounded growth).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SessionState {
    /// Session start time; retained for age-based telemetry.
    #[allow(dead_code)]
    pub created: Instant,
    pub last_seen: Instant,
    /// Number of queries observed for this session.
    pub query_count: u64,
    /// Total decoded payload bytes attributed to this session.
    pub payload_bytes: u64,
    /// Highest sequence number seen (for reassembly/gap telemetry).
    pub max_seq: u32,
}

impl SessionState {
    fn new(now: Instant) -> Self {
        Self { created: now, last_seen: now, query_count: 0, payload_bytes: 0, max_seq: 0 }
    }
}

/// What happened when we touched a session, so the caller can log it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Touch {
    Created,
    Updated,
    /// Capacity reached; the session was not tracked.
    Rejected,
}

pub struct SessionStore {
    inner: Mutex<HashMap<String, SessionState>>,
    ttl: Duration,
    max_sessions: usize,
}

impl SessionStore {
    pub fn new(ttl: Duration, max_sessions: usize) -> Self {
        Self { inner: Mutex::new(HashMap::new()), ttl, max_sessions }
    }

    /// Record activity for `id`. Returns the touch outcome and a snapshot of the
    /// resulting state (except when rejected).
    pub fn touch(
        &self,
        id: &str,
        seq: u32,
        payload_bytes: u64,
    ) -> (Touch, Option<SessionState>) {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("session mutex poisoned");

        if let Some(state) = map.get_mut(id) {
            state.last_seen = now;
            state.query_count += 1;
            state.payload_bytes += payload_bytes;
            state.max_seq = state.max_seq.max(seq);
            return (Touch::Updated, Some(state.clone()));
        }

        // New session. Enforce the cap, evicting expired entries first so a lab
        // left running doesn't wedge on stale sessions.
        if map.len() >= self.max_sessions {
            Self::evict_expired(&mut map, self.ttl, now);
            if map.len() >= self.max_sessions {
                return (Touch::Rejected, None);
            }
        }

        let mut state = SessionState::new(now);
        state.query_count = 1;
        state.payload_bytes = payload_bytes;
        state.max_seq = seq;
        map.insert(id.to_string(), state.clone());
        (Touch::Created, Some(state))
    }

    /// Remove all sessions idle longer than the TTL. Returns the count removed.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("session mutex poisoned");
        let before = map.len();
        Self::evict_expired(&mut map, self.ttl, now);
        before - map.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("session mutex poisoned").len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn evict_expired(map: &mut HashMap<String, SessionState>, ttl: Duration, now: Instant) {
        map.retain(|_, s| now.duration_since(s.last_seen) < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_update_accumulates() {
        let store = SessionStore::new(Duration::from_secs(60), 10);
        let (t1, s1) = store.touch("abc", 0, 10);
        assert_eq!(t1, Touch::Created);
        assert_eq!(s1.unwrap().payload_bytes, 10);

        let (t2, s2) = store.touch("abc", 3, 5);
        assert_eq!(t2, Touch::Updated);
        let s2 = s2.unwrap();
        assert_eq!(s2.query_count, 2);
        assert_eq!(s2.payload_bytes, 15);
        assert_eq!(s2.max_seq, 3);
    }

    #[test]
    fn cap_rejects_when_full_of_live_sessions() {
        let store = SessionStore::new(Duration::from_secs(60), 1);
        assert_eq!(store.touch("a", 0, 0).0, Touch::Created);
        assert_eq!(store.touch("b", 0, 0).0, Touch::Rejected);
    }

    #[test]
    fn sweep_removes_expired() {
        let store = SessionStore::new(Duration::from_millis(1), 10);
        store.touch("a", 0, 0);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(store.sweep(), 1);
        assert!(store.is_empty());
    }
}
