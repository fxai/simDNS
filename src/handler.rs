//! Core query handling: parse → authorise → shape → build response.
//!
//! This is deliberately transport-agnostic and synchronous. The async UDP/TCP
//! layers call [`Handler::handle`] with the raw request bytes and get back an
//! [`Outcome`] carrying the serialized response, the jitter to wait before
//! sending it, and a structured log record. Keeping it pure makes the
//! signature-shaping logic unit-testable without sockets.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, NULL, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rand::Rng;
use std::str::FromStr;
use std::time::Duration;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::profile::{AnswerKind, Disposition, Profile};
use crate::session::{SessionStore, Touch};
use crate::zone::Zone;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// Everything the net layer needs after handling a request.
pub struct Outcome {
    pub response: Vec<u8>,
    pub jitter: Duration,
    pub log: QueryLog,
}

/// Structured, correlation-friendly record of one query/response.
#[derive(Debug, Default)]
pub struct QueryLog {
    pub src_ip: Option<IpAddr>,
    pub transport: &'static str,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub answer_type: Option<&'static str>,
    pub session_id: Option<String>,
    pub seq: Option<u32>,
    pub payload_len: usize,
    pub response_len: usize,
    pub malformed: bool,
    pub truncated: bool,
    /// Only populated when `telemetry.log_decoded_payload` is enabled.
    pub decoded_payload: Option<String>,
}

impl QueryLog {
    /// Emit via `tracing`. The active subscriber decides JSON vs pretty.
    ///
    /// Absent values use sentinels so every log line has a stable schema:
    /// `src_ip`/`session_id`/`decoded_payload` become empty strings and `seq`
    /// becomes `-1` when not present.
    pub fn emit(&self) {
        let src_ip = self.src_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let session_id = self.session_id.as_deref().unwrap_or("");
        let answer_type = self.answer_type.unwrap_or("");
        let decoded_payload = self.decoded_payload.as_deref().unwrap_or("");
        let seq = self.seq.map(|s| s as i64).unwrap_or(-1);
        tracing::info!(
            target: "simdns::query",
            src_ip = %src_ip,
            transport = self.transport,
            qname = %self.qname,
            qtype = %self.qtype,
            rcode = %self.rcode,
            answer_type = answer_type,
            session_id = session_id,
            seq = seq,
            payload_len = self.payload_len,
            response_len = self.response_len,
            malformed = self.malformed,
            truncated = self.truncated,
            decoded_payload = %decoded_payload,
            "dns_query"
        );
    }
}

/// Parsed view of the inbound (query-based) channel labels.
struct Inbound {
    session_id: Option<String>,
    seq: Option<u32>,
    decoded: Option<Vec<u8>>,
}

pub struct Handler {
    cfg: Arc<Config>,
    zone: Arc<Zone>,
    profile: Profile,
    sessions: Arc<SessionStore>,
    metrics: Arc<Metrics>,
    cname_target: Name,
    apex_ns: Name,
}

impl Handler {
    pub fn new(
        cfg: Arc<Config>,
        zone: Arc<Zone>,
        sessions: Arc<SessionStore>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        let profile = Profile::new(&cfg.profile);
        let cname_target = Name::from_str(&cfg.channel.cname_target)
            .map_err(|e| format!("invalid channel.cname_target: {e}"))?;
        // A synthetic in-zone nameserver label for apex NS answers. Built by
        // string concatenation to stay agnostic to the hickory name-builder API.
        let apex_ns = Name::from_str(&format!("ns1.{}", zone.apex()))
            .map_err(|e| format!("building apex NS name: {e}"))?;
        Ok(Self { cfg, zone, profile, sessions, metrics, cname_target, apex_ns })
    }

    /// Handle one raw request datagram / TCP message.
    pub fn handle(&self, raw: &[u8], src_ip: Option<IpAddr>, transport: Transport) -> Outcome {
        Metrics::inc(&self.metrics.queries_total);
        match transport {
            Transport::Udp => Metrics::inc(&self.metrics.udp_queries),
            Transport::Tcp => Metrics::inc(&self.metrics.tcp_queries),
        }

        let request = match Message::from_vec(raw) {
            Ok(m) => m,
            Err(_) => return self.formerr(raw, src_ip, transport),
        };

        // Reject anything that isn't a well-formed single-question QUERY.
        if request.op_code() != OpCode::Query
            || request.message_type() != MessageType::Query
            || request.queries().len() != 1
        {
            return self.formerr(raw, src_ip, transport);
        }

        // UDP answers are bounded by the client's advertised buffer (EDNS0) or
        // the classic 512-byte limit; TCP has no such bound. Oversized UDP
        // answers are truncated with TC=1 so the client retries over TCP.
        let size_limit = match transport {
            Transport::Tcp => None,
            Transport::Udp => {
                Some(request.extensions().as_ref().map(|e| e.max_payload() as usize).unwrap_or(512).max(512))
            }
        };

        let query = request.queries()[0].clone();
        let qname = query.name().clone();
        let qtype = query.query_type();

        let mut log = QueryLog {
            src_ip,
            transport: transport.as_str(),
            qname: qname.to_string(),
            qtype: qtype.to_string(),
            ..Default::default()
        };

        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(false);
        response.add_query(query.clone());

        if !self.zone.contains(&qname) {
            // Out-of-bailiwick: behave like a real delegated authority.
            response.set_response_code(ResponseCode::Refused);
            response.set_authoritative(false);
            Metrics::inc(&self.metrics.queries_refused);
            log.rcode = "REFUSED".into();
            return self.finish(response, log, size_limit);
        }

        Metrics::inc(&self.metrics.queries_in_zone);
        response.set_authoritative(true);

        // Apex control-plane records keep NS delegation realistic.
        if qname.to_lowercase() == *self.zone.apex() {
            match qtype {
                RecordType::SOA => {
                    response.add_answer(self.soa_record());
                    response.set_response_code(ResponseCode::NoError);
                    log.rcode = "NOERROR".into();
                    log.answer_type = Some("SOA");
                    return self.finish(response, log, size_limit);
                }
                RecordType::NS => {
                    response.add_answer(self.ns_record());
                    response.set_response_code(ResponseCode::NoError);
                    log.rcode = "NOERROR".into();
                    log.answer_type = Some("NS");
                    return self.finish(response, log, size_limit);
                }
                _ => {}
            }
        }

        // Decode the inbound channel carried in the sub-zone labels.
        let inbound = self.parse_inbound(&qname);
        log.session_id = inbound.session_id.clone();
        log.seq = inbound.seq;
        if let Some(decoded) = &inbound.decoded {
            log.payload_len = decoded.len();
            Metrics::add(&self.metrics.inbound_payload_bytes, decoded.len() as u64);
            if self.cfg.telemetry.log_decoded_payload {
                log.decoded_payload = Some(render_decoded(decoded));
            }
        }

        // Track the session (correlates chunked queries into one transfer).
        if let Some(sid) = &inbound.session_id {
            let bytes = inbound.decoded.as_ref().map(|d| d.len() as u64).unwrap_or(0);
            let (touch, _state) = self.sessions.touch(sid, inbound.seq.unwrap_or(0), bytes);
            match touch {
                Touch::Created => Metrics::inc(&self.metrics.sessions_created),
                Touch::Rejected => Metrics::inc(&self.metrics.sessions_rejected),
                Touch::Updated => {}
            }
        }

        // Decide disposition: failure rolls, else a record kind from the mix.
        match self.profile.decide() {
            Disposition::NxDomain => {
                response.set_response_code(ResponseCode::NXDomain);
                response.add_name_server(self.soa_record()); // SOA in authority, like a real negative answer
                Metrics::inc(&self.metrics.responses_nxdomain);
                log.rcode = "NXDOMAIN".into();
            }
            Disposition::ServFail => {
                response.set_response_code(ResponseCode::ServFail);
                Metrics::inc(&self.metrics.responses_servfail);
                log.rcode = "SERVFAIL".into();
            }
            Disposition::Answer(kind) => {
                let kind = self.resolve_kind(kind, qtype);
                let (record, payload_bytes) = self.build_answer(&qname, kind);
                response.add_answer(record);
                response.set_response_code(ResponseCode::NoError);
                Metrics::add(&self.metrics.outbound_answer_bytes, payload_bytes as u64);
                self.count_answer(kind);
                log.rcode = "NOERROR".into();
                log.answer_type = Some(answer_kind_str(kind));
            }
        }

        self.finish(response, log, size_limit)
    }

    /// If `honor_qtype` and the QTYPE is a supported data type, answer with that
    /// type; otherwise use the mix-selected kind.
    fn resolve_kind(&self, mix_kind: AnswerKind, qtype: RecordType) -> AnswerKind {
        if !self.cfg.profile.honor_qtype {
            return mix_kind;
        }
        match qtype {
            RecordType::TXT => AnswerKind::Txt,
            RecordType::A => AnswerKind::A,
            RecordType::AAAA => AnswerKind::Aaaa,
            RecordType::CNAME => AnswerKind::Cname,
            RecordType::NULL => AnswerKind::Null,
            _ => mix_kind,
        }
    }

    fn parse_inbound(&self, qname: &Name) -> Inbound {
        let Some(data) = self.zone.data_labels(qname) else {
            return Inbound { session_id: None, seq: None, decoded: None };
        };
        let labels = data.labels; // leftmost-first: [payload.., seq, session]
        let n = labels.len();
        if n == 0 {
            return Inbound { session_id: None, seq: None, decoded: None };
        }
        let session_id = Some(labels[n - 1].clone());

        // Second-from-apex label is the sequence number, if it parses.
        let (seq, payload_end) = if n >= 2 {
            match labels[n - 2].parse::<u32>() {
                Ok(s) => (Some(s), n - 2),
                Err(_) => (None, n - 1),
            }
        } else {
            (None, n - 1)
        };

        let decoded = if payload_end > 0 {
            let joined: String = labels[..payload_end].concat();
            self.cfg.channel.encoding.decode(&joined)
        } else {
            None
        };

        Inbound { session_id, seq, decoded }
    }

    fn build_answer(&self, qname: &Name, kind: AnswerKind) -> (Record, usize) {
        let ttl = self.cfg.channel.answer_ttl_secs;
        let ch = &self.cfg.channel;
        match kind {
            AnswerKind::Txt => {
                let payload = random_ascii(ch.txt_payload_bytes);
                let chunks: Vec<String> =
                    payload.as_bytes().chunks(255).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
                let len = payload.len();
                let rdata = RData::TXT(TXT::new(chunks));
                (Record::from_rdata(qname.clone(), ttl, rdata), len)
            }
            AnswerKind::A => {
                let addr = pick(&ch.a_pool).copied().unwrap_or(std::net::Ipv4Addr::new(192, 0, 2, 1));
                (Record::from_rdata(qname.clone(), ttl, RData::A(A(addr))), 4)
            }
            AnswerKind::Aaaa => {
                let addr = pick(&ch.aaaa_pool)
                    .copied()
                    .unwrap_or(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
                (Record::from_rdata(qname.clone(), ttl, RData::AAAA(AAAA(addr))), 16)
            }
            AnswerKind::Cname => {
                let rdata = RData::CNAME(CNAME(self.cname_target.clone()));
                (Record::from_rdata(qname.clone(), ttl, rdata), self.cname_target.len())
            }
            AnswerKind::Null => {
                let bytes: Vec<u8> = (0..ch.null_payload_bytes)
                    .map(|_| rand::thread_rng().gen::<u8>())
                    .collect();
                let len = bytes.len();
                (Record::from_rdata(qname.clone(), ttl, RData::NULL(NULL::with(bytes))), len)
            }
        }
    }

    fn count_answer(&self, kind: AnswerKind) {
        let c = match kind {
            AnswerKind::Txt => &self.metrics.answers_txt,
            AnswerKind::A => &self.metrics.answers_a,
            AnswerKind::Aaaa => &self.metrics.answers_aaaa,
            AnswerKind::Cname => &self.metrics.answers_cname,
            AnswerKind::Null => &self.metrics.answers_null,
        };
        Metrics::inc(c);
    }

    fn soa_record(&self) -> Record {
        let apex = self.zone.apex().clone();
        let rname = Name::from_str(&format!("hostmaster.{apex}")).unwrap_or_else(|_| apex.clone());
        let soa = SOA::new(self.apex_ns.clone(), rname, 1, 3600, 600, 604_800, 60);
        Record::from_rdata(apex, self.cfg.channel.answer_ttl_secs, RData::SOA(soa))
    }

    fn ns_record(&self) -> Record {
        let apex = self.zone.apex().clone();
        Record::from_rdata(apex, self.cfg.channel.answer_ttl_secs, RData::NS(NS(self.apex_ns.clone())))
    }

    /// Serialize the response and attach jitter + log. `size_limit` is `Some`
    /// for UDP (enforce TC-bit truncation) and `None` for TCP. On a
    /// serialization error (should not happen for well-formed messages), fall
    /// back to SERVFAIL.
    fn finish(&self, mut response: Message, mut log: QueryLog, size_limit: Option<usize>) -> Outcome {
        let mut bytes = response.to_vec().unwrap_or_else(|_| {
            let mut fail = Message::new();
            fail.set_id(response.id());
            fail.set_message_type(MessageType::Response);
            fail.set_response_code(ResponseCode::ServFail);
            fail.to_vec().unwrap_or_default()
        });

        if let Some(max) = size_limit {
            if bytes.len() > max {
                // Re-emit as a truncated referral: TC=1, drop record sections.
                response.set_truncated(true);
                response.take_answers();
                response.take_name_servers();
                response.take_additionals();
                bytes = response.to_vec().unwrap_or_default();
            }
        }

        log.truncated = response.truncated();
        log.response_len = bytes.len();
        Outcome { response: bytes, jitter: self.profile.jitter(), log }
    }

    fn formerr(&self, raw: &[u8], src_ip: Option<IpAddr>, transport: Transport) -> Outcome {
        Metrics::inc(&self.metrics.malformed_packets);
        Metrics::inc(&self.metrics.responses_formerr);

        // Salvage the transaction id so the (broken) client can correlate.
        let id = if raw.len() >= 2 {
            u16::from_be_bytes([raw[0], raw[1]])
        } else {
            0
        };
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::FormErr);
        let bytes = msg.to_vec().unwrap_or_default();

        let log = QueryLog {
            src_ip,
            transport: transport.as_str(),
            qname: String::new(),
            qtype: String::new(),
            rcode: "FORMERR".into(),
            malformed: true,
            response_len: bytes.len(),
            ..Default::default()
        };
        // FORMERR is not jittered: a real server rejects malformed input fast.
        Outcome { response: bytes, jitter: Duration::ZERO, log }
    }
}

fn answer_kind_str(kind: AnswerKind) -> &'static str {
    match kind {
        AnswerKind::Txt => "TXT",
        AnswerKind::A => "A",
        AnswerKind::Aaaa => "AAAA",
        AnswerKind::Cname => "CNAME",
        AnswerKind::Null => "NULL",
    }
}

/// Decoded inbound payloads may be arbitrary bytes; render lossily and cap the
/// length so a single huge query can't blow up a log line.
fn render_decoded(bytes: &[u8]) -> String {
    const CAP: usize = 512;
    let slice = &bytes[..bytes.len().min(CAP)];
    let mut s = String::from_utf8_lossy(slice).into_owned();
    if bytes.len() > CAP {
        s.push_str("...[truncated]");
    }
    s
}

fn random_ascii(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..len).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect()
}

fn pick<T>(pool: &[T]) -> Option<&T> {
    if pool.is_empty() {
        None
    } else {
        Some(&pool[rand::thread_rng().gen_range(0..pool.len())])
    }
}
