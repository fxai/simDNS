//! Tracing subscriber setup. JSON is the default so logs drop straight into a
//! SIEM; `pretty` is offered for interactive debugging.
//!
//! Verbosity is controlled with `RUST_LOG` (e.g. `RUST_LOG=simdns=debug`),
//! defaulting to `info`.

use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

pub fn init(format: LogFormat) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(true);
    match format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Pretty => builder.pretty().init(),
    }
}
