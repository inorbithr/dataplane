//! Metrics as evidence: named queries against a Prometheus-compatible HTTP API
//! (Prometheus, `VictoriaMetrics`, Thanos, Mimir), evaluated at the instants an
//! investigation asks about, recorded as aggregate numbers with their provenance.
//!
//! What keeps this safe, because read-only is not automatically safe:
//! - The queries come only from a local file the company writes (`[[metric]]` in a TOML
//!   file); nothing the platform sends can make the agent run a query of its choosing,
//!   so a metrics endpoint cannot be used to enumerate what a company measures.
//! - The endpoint passes the policy like every other target (host, port, networks).
//! - Only numbers are recorded, plus the label values a query names in `keep_labels`;
//!   every other label (pod names, paths, users, tenants) is dropped before anything is
//!   written. The answer's bytes are digested as the artefact, never stored.
//! - A query that answers more than `MAX_SERIES` series is refused, not truncated:
//!   a query that broad is a mistake, and a silent cut would bias the evidence.

use std::path::Path;
use std::time::Duration;

use iohr_evidence::digest::ContentDigest;
use iohr_evidence::evidence::EvidenceRef;
use iohr_evidence::vocabulary::Value as EvValue;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::common::Ctx;
use super::record::Sink;
use crate::error::{Error, Result};
use crate::policy::{Policy, TargetError};

/// The method this reader writes through.
pub const METHOD: &str = "prometheus.query";

/// The most series one query may answer.
pub const MAX_SERIES: usize = 64;

/// The largest answer read.
const MAX_ANSWER: usize = 1 << 20;

/// The local file of named queries.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsFile {
    /// The Prometheus-compatible API, e.g. `http://victoria-metrics.observability:8428`.
    pub endpoint: String,
    /// The queries.
    #[serde(rename = "metric", default)]
    pub metrics: Vec<MetricQuery>,
}

/// One named query.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricQuery {
    /// The name evidence carries, e.g. `envoy.upstream.p95`.
    pub name: String,
    /// The `PromQL` query.
    pub query: String,
    /// The unit of the answer: `ms` or `s` (converted to milliseconds), or `count`.
    pub unit: Unit,
    /// Label values kept in the entity key (everything else is dropped).
    #[serde(default)]
    pub keep_labels: Vec<String>,
}

/// What a query answers in.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Unit {
    /// Milliseconds.
    Ms,
    /// Seconds.
    S,
    /// A plain number.
    Count,
}

impl MetricsFile {
    /// Reads and checks a metrics file.
    ///
    /// # Errors
    /// Unreadable, not TOML, an unknown key, a bad endpoint or a malformed name.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Atlas(format!("{}: {e}", path.display())))?;
        let f: Self =
            toml::from_str(&text).map_err(|e| Error::Atlas(format!("{}: {e}", path.display())))?;
        let url = Url::parse(&f.endpoint)
            .map_err(|e| Error::Atlas(format!("endpoint {}: {e}", f.endpoint)))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(Error::Atlas(format!(
                "endpoint {} is not an http(s) URL with a host",
                f.endpoint
            )));
        }
        for m in &f.metrics {
            if m.name.is_empty()
                || !m
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                return Err(Error::Atlas(format!(
                    "metric name {:?} is malformed",
                    m.name
                )));
            }
        }
        Ok(f)
    }
}

/// One series of one answer, already reduced to what may be recorded.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// The kept label values, `key=value`, sorted.
    pub labels: Vec<String>,
    /// The value in the query's unit, as reported.
    pub value: f64,
}

/// Parses an instant-query answer, keeping only `keep` labels.
///
/// # Errors
/// Not a successful vector answer, or more than [`MAX_SERIES`] series.
pub fn parse_answer(bytes: &[u8], keep: &[String]) -> Result<Vec<Sample>> {
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::Atlas("the metrics answer is not JSON".into()))?;
    if v.get("status").and_then(Value::as_str) != Some("success") {
        return Err(Error::Atlas(
            "the metrics API did not answer success".into(),
        ));
    }
    let result = v
        .pointer("/data/result")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Atlas("the metrics answer has no result vector".into()))?;
    if result.len() > MAX_SERIES {
        return Err(Error::Atlas(format!(
            "the query answered {} series, more than {MAX_SERIES}: narrow it",
            result.len()
        )));
    }
    let mut out = Vec::new();
    for s in result {
        let Some(raw) = s.pointer("/value/1").and_then(Value::as_str) else {
            continue;
        };
        let Ok(value) = raw.parse::<f64>() else {
            continue;
        };
        if !value.is_finite() {
            continue;
        }
        let mut labels: Vec<String> = keep
            .iter()
            .filter_map(|k| {
                s.pointer(&format!("/metric/{k}"))
                    .and_then(Value::as_str)
                    .map(|v| format!("{k}={v}"))
            })
            .collect();
        labels.sort();
        out.push(Sample { labels, value });
    }
    Ok(out)
}

/// The entity key of one series of one metric.
#[must_use]
pub fn series_key(name: &str, labels: &[String]) -> String {
    if labels.is_empty() {
        format!("metric/{name}")
    } else {
        format!("metric/{name}{{{}}}", labels.join(","))
    }
}

/// Records one evaluated query: the answer's digest (`answer_digest`), and per series
/// `measured_ms` (or `measured`) at `at`, with `measured_at` and `query` as text.
///
/// # Errors
/// An observation could not be built.
pub fn observe_answer(
    ctx: &Ctx,
    sink: &mut Sink,
    q: &MetricQuery,
    at: &str,
    endpoint: &str,
    answer: &[u8],
) -> Result<usize> {
    let samples = parse_answer(answer, &q.keep_labels)?;
    // The answer itself, by digest only: whoever holds the same answer can check it.
    let answer_key = format!("query/{}@{at}", q.name);
    let digest = ctx.observe(
        sink,
        &answer_key,
        "answer_digest",
        EvValue::Digest(ContentDigest::of_bytes(answer)),
        &[],
    )?;
    ctx.observe(
        sink,
        &answer_key,
        "endpoint",
        EvValue::Text(endpoint.to_owned()),
        &[],
    )?;
    let from = [EvidenceRef::Observation(digest)];
    for s in &samples {
        let key = format!("{}@{at}", series_key(&q.name, &s.labels));
        match q.unit {
            Unit::Ms | Unit::S => {
                let ms = if q.unit == Unit::S {
                    s.value * 1000.0
                } else {
                    s.value
                };
                // Rounded to the millisecond; negative values are not durations.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let ms = ms.max(0.0).round() as u64;
                ctx.observe_from(sink, &key, "measured_ms", EvValue::Millis(ms), &from)?;
            }
            Unit::Count => {
                #[allow(clippy::cast_possible_truncation)]
                let n = s.value.round() as i64;
                ctx.observe_from(sink, &key, "measured", EvValue::Int(n), &from)?;
            }
        }
        ctx.observe_from(
            sink,
            &key,
            "measured_at",
            EvValue::Text(at.to_owned()),
            &from,
        )?;
        ctx.observe_from(sink, &key, "query", EvValue::Text(q.query.clone()), &from)?;
    }
    Ok(samples.len())
}

/// A client for the file's endpoint, after the policy admitted it.
///
/// # Errors
/// The policy refuses the endpoint.
pub async fn client(file: &MetricsFile, policy: &Policy) -> Result<(Url, reqwest::Client)> {
    let url = Url::parse(&file.endpoint).map_err(|e| Error::Atlas(e.to_string()))?;
    let host = url.host_str().unwrap_or_default().to_owned();
    let port = url.port_or_known_default().unwrap_or(80);
    policy
        .resolve_target(&host, port, Duration::from_secs(5))
        .await
        .map_err(|e| match e {
            TargetError::Refused(r) => Error::Policy(format!(
                "the metrics endpoint {host}:{port} is refused: {r}"
            )),
            TargetError::Dns(r) => Error::Atlas(format!("the metrics endpoint {host}:{port}: {r}")),
        })?;
    crate::tls::install_crypto_provider();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Atlas(format!("metrics client: {e}")))?;
    Ok((url, http))
}

/// Evaluates one query at one instant (RFC 3339) and returns the raw answer.
///
/// # Errors
/// Unreachable, not success, or too large.
pub async fn fetch(http: &reqwest::Client, base: &Url, query: &str, at: &str) -> Result<Vec<u8>> {
    let mut url = base
        .join("api/v1/query")
        .map_err(|e| Error::Atlas(e.to_string()))?;
    url.query_pairs_mut()
        .append_pair("query", query)
        .append_pair("time", at);
    let mut resp = http
        .get(url)
        .send()
        .await
        .map_err(|_| Error::Atlas("could not reach the metrics endpoint".into()))?;
    if !resp.status().is_success() {
        return Err(Error::Atlas(format!(
            "the metrics endpoint answered {}",
            resp.status().as_u16()
        )));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| Error::Atlas("the metrics answer was cut off".into()))?
    {
        if buf.len() + chunk.len() > MAX_ANSWER {
            return Err(Error::Atlas("the metrics answer is too large".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas::common::{ObservedNow, method};
    use crate::atlas::record::Record;
    use iohr_evidence::method::MethodCategory;
    use iohr_evidence::observer::ObserverClass;

    // The real answer for the agents cluster's p95 at 2026-10-09T09:45:51Z (VictoriaMetrics
    // on nevio-server), with one extra label that must not survive.
    const ANSWER: &[u8] = br#"{"status":"success","data":{"resultType":"vector","result":[
      {"metric":{"envoy_cluster_name":"agents","pod":"envoy-7f9c-xyz"},"value":[1791539151,"363.4146341463413"]},
      {"metric":{"envoy_cluster_name":"protocol","pod":"envoy-7f9c-xyz"},"value":[1791539151,"17.93749999999997"]},
      {"metric":{"envoy_cluster_name":"broken"},"value":[1791539151,"NaN"]}]}}"#;

    fn q() -> MetricQuery {
        MetricQuery {
            name: "envoy.upstream.p95".into(),
            query: "histogram_quantile(0.95, sum by (envoy_cluster_name, le) (rate(envoy_cluster_upstream_rq_time_bucket[1h])))".into(),
            unit: Unit::Ms,
            keep_labels: vec!["envoy_cluster_name".into()],
        }
    }

    #[test]
    fn only_numbers_and_kept_labels_survive() {
        let s = parse_answer(ANSWER, &q().keep_labels).unwrap();
        assert_eq!(s.len(), 2, "NaN is not a measurement");
        assert_eq!(s[0].labels, vec!["envoy_cluster_name=agents"]);
        assert!(
            s.iter()
                .all(|x| x.labels.iter().all(|l| !l.contains("pod")))
        );
    }

    #[test]
    fn a_too_broad_query_is_refused_not_cut() {
        let series: Vec<String> = (0..=MAX_SERIES)
            .map(|i| format!(r#"{{"metric":{{"i":"{i}"}},"value":[1,"1"]}}"#))
            .collect();
        let body = format!(
            r#"{{"status":"success","data":{{"result":[{}]}}}}"#,
            series.join(",")
        );
        let e = parse_answer(body.as_bytes(), &[]).unwrap_err();
        assert!(e.to_string().contains("narrow it"), "{e}");
    }

    #[test]
    fn an_answer_becomes_millisecond_observations_with_the_answer_as_artefact() {
        let mut sink = Sink::default();
        let ctx = Ctx::new(
            &mut sink,
            "metrics-reader",
            ObserverClass::ExternalSystem,
            method(METHOD, MethodCategory::Metrics).unwrap(),
            "probe",
            &["query"],
            &ObservedNow::now(),
        )
        .unwrap();
        let n = observe_answer(
            &ctx,
            &mut sink,
            &q(),
            "2026-10-09T09:45:51Z",
            "http://victoria-metrics:8428",
            ANSWER,
        )
        .unwrap();
        assert_eq!(n, 2);
        let ms: Vec<(String, u64)> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Record::Observation(o)
                    if o.statement().predicate.name.as_str() == "measured_ms" =>
                {
                    match o.statement().value {
                        EvValue::Millis(m) => Some((format!("{:?}", o.statement().subject), m)),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect();
        assert_eq!(ms.iter().map(|x| x.1).collect::<Vec<_>>(), vec![363, 18]);
        assert!(
            sink.records()
                .iter()
                .any(|r| matches!(r, Record::Observation(o)
                if o.statement().predicate.name.as_str() == "answer_digest")),
            "the answer is evidence by digest"
        );
    }

    #[test]
    fn the_file_refuses_unknown_keys_and_bad_names() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("m.toml");
        std::fs::write(
            &p,
            "endpoint = \"http://vm:8428\"\n[[metric]]\nname = \"a b\"\nquery = \"up\"\nunit = \"count\"\n",
        )
        .unwrap();
        assert!(
            MetricsFile::load(&p)
                .unwrap_err()
                .to_string()
                .contains("malformed")
        );
        std::fs::write(&p, "endpoint = \"http://vm:8428\"\nsurprise = 1\n").unwrap();
        assert!(MetricsFile::load(&p).is_err());
        std::fs::write(&p, "endpoint = \"file:///etc/passwd\"\n").unwrap();
        assert!(MetricsFile::load(&p).is_err());
    }
}
