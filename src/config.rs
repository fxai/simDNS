//! Configuration model: TOML file + CLI overlay.
//!
//! All tuning knobs that shape emitted telemetry live here so a scenario can be
//! captured as a single, reproducible `config.toml`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use serde::Deserialize;

use crate::encoding::Encoding;

/// Top-level configuration. Every field has a `Default` so a minimal TOML file
/// (or none at all) still yields a runnable server.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub zone: ZoneConfig,
    pub channel: ChannelConfig,
    pub profile: ProfileConfig,
    pub session: SessionConfig,
    pub telemetry: TelemetryConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind both the UDP and TCP listeners to.
    pub bind: IpAddr,
    pub port: u16,
    /// Enable the UDP/53 listener.
    pub udp: bool,
    /// Enable the TCP/53 listener (needed for large TXT answers / fragmentation tests).
    pub tcp: bool,
    /// Max bytes read for a single TCP message (bounds memory per connection).
    pub tcp_max_message_bytes: usize,
    /// Max concurrent TCP connections accepted (DoS bound).
    pub tcp_max_connections: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ZoneConfig {
    /// The single delegated zone this server is authoritative for, e.g.
    /// `test-telemetry.example.com`. Queries outside it return REFUSED.
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelConfig {
    /// Expected encoding of data carried in subdomain labels.
    pub encoding: Encoding,
    /// A records handed back for outbound emulation (round-robined).
    pub a_pool: Vec<Ipv4Addr>,
    /// AAAA records handed back for outbound emulation.
    pub aaaa_pool: Vec<Ipv6Addr>,
    /// Target the CNAME answers point at (inside or outside the zone).
    pub cname_target: String,
    /// Fixed TXT payload size in bytes for synthetic outbound responses.
    pub txt_payload_bytes: usize,
    /// Size in bytes of synthetic NULL-record payloads.
    pub null_payload_bytes: usize,
    /// TTL applied to all synthetic answer records. Low TTLs are themselves a
    /// detection signal, so this is tunable.
    pub answer_ttl_secs: u32,
}

/// Statistical shaping of the emitted signature. See the `profile` module.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileConfig {
    /// Minimum added response latency in milliseconds (beacon cadence jitter).
    pub jitter_min_ms: u64,
    /// Maximum added response latency in milliseconds.
    pub jitter_max_ms: u64,
    /// Weighted record-type mix for outbound answers, e.g. `TXT = 90, A = 10`.
    pub record_mix: RecordMix,
    /// When true, a supported QTYPE (TXT/A/AAAA/CNAME/NULL) is answered with
    /// that same type and `record_mix` is used only as a fallback for other
    /// QTYPEs. When false, the server always picks the answer type from
    /// `record_mix` regardless of QTYPE — useful for emitting a precise,
    /// server-controlled record-type distribution (and the type/QTYPE mismatch
    /// is itself a controllable protocol anomaly).
    pub honor_qtype: bool,
    /// Fraction [0.0, 1.0] of in-zone queries answered with NXDOMAIN
    /// (simulates DNS scanning / non-existent-domain patterns).
    pub nxdomain_rate: f64,
    /// Fraction [0.0, 1.0] of in-zone queries answered with SERVFAIL.
    pub servfail_rate: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecordMix {
    pub txt: u32,
    pub a: u32,
    pub aaaa: u32,
    pub cname: u32,
    pub null: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    /// Time-to-live for an idle session before eviction.
    pub ttl_secs: u64,
    /// Hard cap on tracked sessions (bounded memory / DoS guard).
    pub max_sessions: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// `json` (default) or `pretty`.
    pub format: LogFormat,
    /// Log the decoded label payload. Off by default to avoid writing test
    /// data that may be sensitive into logs.
    pub log_decoded_payload: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            zone: ZoneConfig::default(),
            channel: ChannelConfig::default(),
            profile: ProfileConfig::default(),
            session: SessionConfig::default(),
            telemetry: TelemetryConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 53,
            udp: true,
            tcp: true,
            tcp_max_message_bytes: 65_535,
            tcp_max_connections: 256,
        }
    }
}

impl Default for ZoneConfig {
    fn default() -> Self {
        Self {
            name: "test-telemetry.example.com".to_string(),
        }
    }
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            encoding: Encoding::Base32,
            a_pool: vec![Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 11)],
            aaaa_pool: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)],
            cname_target: "sink.test-telemetry.example.com".to_string(),
            txt_payload_bytes: 180,
            null_payload_bytes: 180,
            answer_ttl_secs: 60,
        }
    }
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            jitter_min_ms: 0,
            jitter_max_ms: 0,
            record_mix: RecordMix::default(),
            honor_qtype: true,
            nxdomain_rate: 0.0,
            servfail_rate: 0.0,
        }
    }
}

impl Default for RecordMix {
    fn default() -> Self {
        // 90% TXT / 10% A, matching the spec's canonical example.
        Self { txt: 90, a: 10, aaaa: 0, cname: 0, null: 0 }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self { ttl_secs: 300, max_sessions: 10_000 }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { format: LogFormat::Json, log_decoded_payload: false }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: SocketAddr::from(([127, 0, 0, 1], 9100)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config file {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("parsing config file {path}: {source}")]
    Parse { path: String, source: toml::de::Error },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    /// Load config from a TOML file. Missing file is an error; use
    /// `Config::default()` explicitly if no file is desired.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let cfg: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reject nonsensical combinations early rather than at request time.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.zone.name.trim().is_empty() {
            return Err(ConfigError::Invalid("zone.name must not be empty".into()));
        }
        if !self.server.udp && !self.server.tcp {
            return Err(ConfigError::Invalid(
                "at least one of server.udp / server.tcp must be enabled".into(),
            ));
        }
        for (field, v) in [
            ("profile.nxdomain_rate", self.profile.nxdomain_rate),
            ("profile.servfail_rate", self.profile.servfail_rate),
        ] {
            if !(0.0..=1.0).contains(&v) {
                return Err(ConfigError::Invalid(format!("{field} must be in [0.0, 1.0]")));
            }
        }
        if self.profile.nxdomain_rate + self.profile.servfail_rate > 1.0 {
            return Err(ConfigError::Invalid(
                "profile.nxdomain_rate + profile.servfail_rate must not exceed 1.0".into(),
            ));
        }
        if self.profile.jitter_min_ms > self.profile.jitter_max_ms {
            return Err(ConfigError::Invalid(
                "profile.jitter_min_ms must be <= profile.jitter_max_ms".into(),
            ));
        }
        if self.profile.record_mix.total() == 0 {
            return Err(ConfigError::Invalid(
                "profile.record_mix must have at least one non-zero weight".into(),
            ));
        }
        if self.session.max_sessions == 0 {
            return Err(ConfigError::Invalid("session.max_sessions must be > 0".into()));
        }
        Ok(())
    }

    /// The socket address the DNS listeners bind to.
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.server.bind, self.server.port)
    }
}

impl RecordMix {
    pub fn total(&self) -> u32 {
        self.txt + self.a + self.aaaa + self.cname + self.null
    }
}
