//! Logs to stderr always; traces, metrics and logs over OTLP/HTTP to the company's own
//! collector when `[telemetry] enabled = true`. Nothing is exported by default, and
//! nothing ever goes to InOrbit this way.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::config::TelemetryConfig;
use crate::error::{Error, Result};

/// The log filter variable (`info`, `iohr_agent=debug`).
pub const LOG_ENV: &str = "IOHR_AGENT_LOG";

/// Keeps the exporters alive; flushes them on [`Telemetry::shutdown`].
#[derive(Debug, Default)]
pub struct Telemetry {
    tracer: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl Telemetry {
    /// Flushes and stops the exporters.
    pub fn shutdown(self) {
        if let Some(t) = self.tracer {
            let _ = t.shutdown();
        }
        if let Some(m) = self.meter {
            let _ = m.shutdown();
        }
        if let Some(l) = self.logger {
            let _ = l.shutdown();
        }
    }
}

/// Sets up logging and, if enabled, OTLP export. Call before the async runtime starts:
/// the OTLP HTTP client runs on its own threads.
///
/// # Errors
/// When an exporter cannot be built.
pub fn init(cfg: &TelemetryConfig, json: bool) -> Result<Telemetry> {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false);
    let fmt = if json {
        fmt.json().boxed()
    } else {
        fmt.boxed()
    };
    if !cfg.enabled {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt)
            .with(crate::logbuf::RingLayer)
            .try_init();
        return Ok(Telemetry::default());
    }
    let base = cfg.endpoint.trim_end_matches('/');
    let resource = Resource::builder()
        .with_service_name(cfg.service_name.clone())
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build();
    let err = |e: &dyn std::fmt::Display| Error::Telemetry(e.to_string());

    let spans = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/traces"))
        .build()
        .map_err(|e| err(&e))?;
    let tracer = SdkTracerProvider::builder()
        .with_batch_exporter(spans)
        .with_resource(resource.clone())
        .build();

    let metrics = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/metrics"))
        .build()
        .map_err(|e| err(&e))?;
    let meter = SdkMeterProvider::builder()
        .with_periodic_exporter(metrics)
        .with_resource(resource.clone())
        .build();
    opentelemetry::global::set_meter_provider(meter.clone());

    let logs = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/logs"))
        .build()
        .map_err(|e| err(&e))?;
    let logger = SdkLoggerProvider::builder()
        .with_batch_exporter(logs)
        .with_resource(resource)
        .build();

    let otel_traces = tracing_opentelemetry::layer().with_tracer(tracer.tracer("iohr-agent"));
    let otel_logs = opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger);
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .with(crate::logbuf::RingLayer)
        .with(otel_traces)
        .with(otel_logs)
        .try_init();
    Ok(Telemetry {
        tracer: Some(tracer),
        meter: Some(meter),
        logger: Some(logger),
    })
}

use tracing_subscriber::Layer as _;
