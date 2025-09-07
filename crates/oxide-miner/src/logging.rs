use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize console/file logging depending on the `debug` flag.
/// Returns a guard to keep the file writer alive when debug logging is enabled.
pub fn init_logging(debug: bool) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if debug {
            EnvFilter::new("debug,oxide_core=debug")
        } else {
            EnvFilter::new("info")
        }
    });

    let console_layer = fmt::layer().with_writer(std::io::stdout).with_target(true);

    if debug {
        let _ = std::fs::create_dir_all("logs");
        let file_appender = tracing_appender::rolling::daily("logs", "oxide-miner.log");
        let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = fmt::layer()
            .with_ansi(false)
            .with_writer(file_writer)
            .with_target(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .with(file_layer)
            .init();
        info!("debug logging enabled; writing rotating logs under ./logs/");
        Some(guard)
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .init();
        None
    }
}
