//! simdns — DNS Telemetry Emulation Server.
//!
//! A purple-team detection-engineering harness that emits controlled,
//! reproducible DNS artifacts (volumetric, entropy, uncommon-record-type,
//! NXDOMAIN-scan patterns) so SOC teams can calibrate SIEM/EDR detections.
//!
//! It is a test harness, not an implant: it contains no evasion, obfuscation,
//! or anti-analysis logic and is intended to produce *detectable* traffic.

mod config;
mod encoding;
mod handler;
mod metrics;
mod net;
mod profile;
mod session;
mod telemetry;
mod zone;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::{TcpListener, UdpSocket};

use crate::config::{Config, LogFormat};
use crate::encoding::Encoding;
use crate::handler::Handler;
use crate::metrics::Metrics;
use crate::session::SessionStore;
use crate::zone::Zone;

/// DNS Telemetry Emulation Server for detection engineering.
#[derive(Debug, Parser)]
#[command(name = "simdns", version, about)]
struct Cli {
    /// Path to a TOML config file. Defaults are used if omitted.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override the listener bind address.
    #[arg(long, value_name = "IP")]
    bind: Option<IpAddr>,

    /// Override the listener port.
    #[arg(long)]
    port: Option<u16>,

    /// Override the authoritative delegated zone.
    #[arg(long, value_name = "FQDN")]
    zone: Option<String>,

    /// Override the inbound label encoding (base32|hex|base64url).
    #[arg(long)]
    encoding: Option<String>,

    /// Enable the metrics endpoint and bind it to this address.
    #[arg(long, value_name = "IP:PORT")]
    metrics_addr: Option<SocketAddr>,

    /// Override the log format (json|pretty).
    #[arg(long)]
    log_format: Option<String>,

    /// Log decoded inbound payloads (off by default; may expose test data).
    #[arg(long)]
    log_decoded_payload: bool,
}

fn build_config(cli: &Cli) -> Result<Config> {
    let mut cfg = match &cli.config {
        Some(path) => Config::from_file(path).context("loading config file")?,
        None => Config::default(),
    };

    if let Some(bind) = cli.bind {
        cfg.server.bind = bind;
    }
    if let Some(port) = cli.port {
        cfg.server.port = port;
    }
    if let Some(zone) = &cli.zone {
        cfg.zone.name = zone.clone();
    }
    if let Some(enc) = &cli.encoding {
        cfg.channel.encoding = Encoding::from_str(enc).map_err(anyhow::Error::msg)?;
    }
    if let Some(addr) = cli.metrics_addr {
        cfg.metrics.enabled = true;
        cfg.metrics.bind = addr;
    }
    if let Some(lf) = &cli.log_format {
        cfg.telemetry.format = match lf.to_ascii_lowercase().as_str() {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            other => anyhow::bail!("unknown log format {other:?} (expected json|pretty)"),
        };
    }
    if cli.log_decoded_payload {
        cfg.telemetry.log_decoded_payload = true;
    }

    cfg.validate().context("validating configuration")?;
    Ok(cfg)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Config errors must surface before the subscriber exists.
    let cfg = match build_config(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e:#}");
            std::process::exit(2);
        }
    };

    telemetry::init(cfg.telemetry.format);
    let cfg = Arc::new(cfg);

    let zone = Arc::new(Zone::new(&cfg.zone.name).map_err(anyhow::Error::msg)?);
    let sessions = Arc::new(SessionStore::new(
        Duration::from_secs(cfg.session.ttl_secs),
        cfg.session.max_sessions,
    ));
    let metrics = Metrics::new();
    let handler = Arc::new(
        Handler::new(cfg.clone(), zone.clone(), sessions.clone(), metrics.clone())
            .map_err(anyhow::Error::msg)?,
    );

    let addr = cfg.listen_addr();
    tracing::info!(
        target: "simdns",
        zone = %cfg.zone.name,
        %addr,
        udp = cfg.server.udp,
        tcp = cfg.server.tcp,
        encoding = %cfg.channel.encoding,
        "simdns starting"
    );

    let mut listeners = Vec::new();

    if cfg.server.udp {
        let sock = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding UDP {addr}"))?;
        let sock = Arc::new(sock);
        let h = handler.clone();
        tracing::info!(target: "simdns", %addr, "UDP listener bound");
        listeners.push(tokio::spawn(async move { net::serve_udp(sock, h).await }));
    }

    if cfg.server.tcp {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding TCP {addr}"))?;
        let h = handler.clone();
        let max_conn = cfg.server.tcp_max_connections;
        let max_msg = cfg.server.tcp_max_message_bytes;
        tracing::info!(target: "simdns", %addr, "TCP listener bound");
        listeners.push(tokio::spawn(async move {
            net::serve_tcp(listener, h, max_conn, max_msg).await
        }));
    }

    // Periodic session eviction keeps memory bounded and the live gauge honest.
    {
        let sessions = sessions.clone();
        let sweep_every = Duration::from_secs((cfg.session.ttl_secs / 2).max(5));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(sweep_every);
            loop {
                tick.tick().await;
                let removed = sessions.sweep();
                if removed > 0 {
                    tracing::debug!(target: "simdns::session", removed, "evicted idle sessions");
                }
            }
        });
    }

    // Optional metrics HTTP endpoint.
    if cfg.metrics.enabled {
        let sessions_gauge = sessions.clone();
        let router = metrics::router(
            metrics.clone(),
            Arc::new(move || sessions_gauge.len()),
        );
        let bind = cfg.metrics.bind;
        let listener = TcpListener::bind(bind)
            .await
            .with_context(|| format!("binding metrics endpoint {bind}"))?;
        tracing::info!(target: "simdns", %bind, "metrics endpoint listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!(target: "simdns", error = %e, "metrics server exited");
            }
        });
    }

    shutdown_signal().await;
    tracing::info!(target: "simdns", "shutdown signal received; stopping");
    for l in listeners {
        l.abort();
    }
    Ok(())
}

/// Resolve on Ctrl-C or SIGTERM for clean container/systemd shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
