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
    /// The histogram the query reads, without `_bucket` (e.g.
    /// `envoy_cluster_upstream_rq_time`), whose bucket bounds are recorded beside the
    /// answer. Default: the one `_bucket` series the query names, if exactly one.
    #[serde(default)]
    pub histogram: Option<String>,
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
            if let Some(h) = &m.histogram
                && !is_metric_name(h)
            {
                return Err(Error::Atlas(format!(
                    "metric {}: histogram {h:?} is not a metric name",
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

/// A Prometheus metric name: `[a-zA-Z_:][a-zA-Z0-9_:]*`. The only text the agent puts
/// into a query of its own, so nothing else can reach the endpoint.
#[must_use]
pub fn is_metric_name(s: &str) -> bool {
    let mut cs = s.chars();
    cs.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

impl MetricQuery {
    /// The histogram whose buckets this query reads: the file's `histogram`, else the one
    /// `<name>_bucket` series the query names. None when it names none, or several.
    #[must_use]
    pub fn histogram(&self) -> Option<String> {
        if let Some(h) = &self.histogram {
            return Some(h.clone());
        }
        let mut found: Vec<String> = Vec::new();
        let bytes = self.query.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_alphabetic() || c == b'_' || c == b':' {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b':')
                {
                    i += 1;
                }
                if let Some(base) = self.query[start..i].strip_suffix("_bucket")
                    && is_metric_name(base)
                    && !found.iter().any(|f| f == base)
                {
                    found.push(base.to_owned());
                }
            } else {
                i += 1;
            }
        }
        (found.len() == 1).then(|| found.remove(0))
    }
}

/// The query that lists a histogram's bucket bounds: one series per `le`.
#[must_use]
pub fn buckets_query(histogram: &str) -> String {
    format!("count by (le) ({histogram}_bucket)")
}

/// The bucket bounds in a `count by (le)` answer, ascending, `+Inf` last, as Prometheus
/// writes them (`0.5`, `1`, `+Inf`).
///
/// # Errors
/// Not a successful vector answer, more than [`MAX_SERIES`] buckets, or no bucket.
pub fn parse_bounds(bytes: &[u8]) -> Result<Vec<String>> {
    let samples = parse_answer(bytes, &["le".to_owned()])?;
    let mut bounds: Vec<(f64, String)> = samples
        .iter()
        .filter_map(|s| s.labels.iter().find_map(|l| l.strip_prefix("le=")))
        .filter_map(|le| {
            let v = if le == "+Inf" {
                f64::INFINITY
            } else {
                le.parse::<f64>().ok()?
            };
            Some((v, le.to_owned()))
        })
        .collect();
    if bounds.is_empty() {
        return Err(Error::Atlas("the histogram answered no buckets".into()));
    }
    bounds.sort_by(|a, b| a.0.total_cmp(&b.0));
    bounds.dedup_by(|a, b| a.1 == b.1);
    Ok(bounds.into_iter().map(|b| b.1).collect())
}

/// Records a histogram's bucket bounds at `at`: `bucket_bounds` (the `le` values,
/// ascending, comma-separated) and `bucket_count` on `metric/<name>@<at>`, from the
/// answer's digest. A quantile from this histogram cannot be finer than its buckets.
///
/// # Errors
/// The answer is not a bucket list, or an observation could not be built.
pub fn observe_bounds(
    ctx: &Ctx,
    sink: &mut Sink,
    q: &MetricQuery,
    histogram: &str,
    at: &str,
    answer: &[u8],
) -> Result<usize> {
    let bounds = parse_bounds(answer)?;
    let answer_key = format!("query/{}.buckets@{at}", q.name);
    let digest = ctx.observe(
        sink,
        &answer_key,
        "answer_digest",
        EvValue::Digest(ContentDigest::of_bytes(answer)),
        &[],
    )?;
    let from = [EvidenceRef::Observation(digest)];
    let key = format!("{}@{at}", series_key(&q.name, &[]));
    ctx.observe_from(
        sink,
        &key,
        "histogram",
        EvValue::Text(histogram.to_owned()),
        &from,
    )?;
    ctx.observe_from(
        sink,
        &key,
        "bucket_bounds",
        EvValue::Text(bounds.join(",")),
        &from,
    )?;
    ctx.observe_from(
        sink,
        &key,
        "bucket_count",
        EvValue::Int(i64::try_from(bounds.len()).unwrap_or(i64::MAX)),
        &from,
    )?;
    Ok(bounds.len())
}

/// The most instants one run evaluates: a week, hourly.
pub const MAX_INSTANTS: usize = 169;

/// Expands `--at` values into instants (RFC 3339, UTC, `Z`). A value is one instant, or
/// a range `START..END/STEP` (`STEP` in `m` or `h`, default `1h`), both ends included:
/// `2026-10-09T00:00:00Z..2026-10-09T12:00:00Z` is the 13 hours from midnight to noon.
///
/// # Errors
/// A malformed instant or step, an end before its start, or more than
/// [`MAX_INSTANTS`] instants in all.
pub fn instants(values: &[String]) -> Result<Vec<String>> {
    use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
    let parse = |s: &str| -> Result<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| Error::Atlas(format!("--at {s}: {e}")))
    };
    let mut out = Vec::new();
    for v in values {
        let Some((start, rest)) = v.split_once("..") else {
            out.push(parse(v)?.to_rfc3339_opts(SecondsFormat::Secs, true));
            continue;
        };
        let (end, step) = rest.split_once('/').unwrap_or((rest, "1h"));
        let (n, unit) = step.split_at(step.len().saturating_sub(1));
        let n: i64 = n.parse().ok().filter(|n| *n > 0).ok_or_else(|| {
            Error::Atlas(format!("--at {v}: the step {step:?} is not like 1h or 15m"))
        })?;
        let step = match unit {
            "h" => TimeDelta::hours(n),
            "m" => TimeDelta::minutes(n),
            _ => {
                return Err(Error::Atlas(format!(
                    "--at {v}: the step {step:?} is not like 1h or 15m"
                )));
            }
        };
        let (from, to) = (parse(start)?, parse(end)?);
        if to < from {
            return Err(Error::Atlas(format!(
                "--at {v}: the end is before the start"
            )));
        }
        let mut t = from;
        while t <= to {
            out.push(t.to_rfc3339_opts(SecondsFormat::Secs, true));
            if out.len() > MAX_INSTANTS {
                break;
            }
            t += step;
        }
    }
    if out.len() > MAX_INSTANTS {
        return Err(Error::Atlas(format!(
            "--at names more than {MAX_INSTANTS} instants: narrow the range or widen the step"
        )));
    }
    out.dedup();
    Ok(out)
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
            histogram: None,
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

    // A `count by (le)` answer for envoy's upstream request time, out of order, with a
    // label that must not matter.
    const BUCKETS: &[u8] = br#"{"status":"success","data":{"resultType":"vector","result":[
      {"metric":{"le":"+Inf"},"value":[1791539151,"12"]},
      {"metric":{"le":"0.5"},"value":[1791539151,"12"]},
      {"metric":{"le":"1000"},"value":[1791539151,"12"]},
      {"metric":{"le":"25"},"value":[1791539151,"12"]},
      {"metric":{"le":"250","pod":"x"},"value":[1791539151,"12"]}]}}"#;

    #[test]
    fn a_query_names_its_histogram_or_the_file_does() {
        assert_eq!(
            q().histogram().as_deref(),
            Some("envoy_cluster_upstream_rq_time")
        );
        let mut two = q();
        two.query = "a_bucket / b_bucket".into();
        assert_eq!(
            two.histogram(),
            None,
            "two histograms: ambiguous, the file must say"
        );
        two.histogram = Some("a".into());
        assert_eq!(two.histogram().as_deref(), Some("a"));
        let mut none = q();
        none.query = "up".into();
        assert_eq!(none.histogram(), None);
        assert_eq!(buckets_query("envoy_x"), "count by (le) (envoy_x_bucket)");
        assert!(is_metric_name("envoy_cluster:rate5m"));
        for bad in ["", "1x", "x{a=\"b\"}", "x) or vector(1", "x y"] {
            assert!(!is_metric_name(bad), "{bad}");
        }
    }

    #[test]
    fn bucket_bounds_are_recorded_ascending_with_inf_last() {
        assert_eq!(
            parse_bounds(BUCKETS).unwrap(),
            vec!["0.5", "25", "250", "1000", "+Inf"]
        );
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
        let n = observe_bounds(
            &ctx,
            &mut sink,
            &q(),
            "envoy_cluster_upstream_rq_time",
            "2026-10-09T09:00:00Z",
            BUCKETS,
        )
        .unwrap();
        assert_eq!(n, 5);
        let bounds: Vec<String> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Record::Observation(o)
                    if o.statement().predicate.name.as_str() == "bucket_bounds" =>
                {
                    match o.statement().value {
                        EvValue::Text(t) => Some(t),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect();
        assert_eq!(bounds, vec!["0.5,25,250,1000,+Inf"]);
        let empty = br#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
        assert!(
            parse_bounds(empty).is_err(),
            "no buckets is not an empty list of bounds"
        );
    }

    #[test]
    fn envoy_s_real_buckets_parse_in_order() {
        // `count by (le) (envoy_cluster_upstream_rq_time_bucket)` at 2026-10-09T09:00:00Z,
        // from VictoriaMetrics on nevio-server.
        let real = include_bytes!("../../tests/fixtures/metrics-envoy-buckets.json");
        let b = parse_bounds(real).unwrap();
        assert_eq!(b.first().map(String::as_str), Some("0.5"));
        assert_eq!(b.last().map(String::as_str), Some("+Inf"));
        let finite: Vec<f64> = b[..b.len() - 1].iter().map(|x| x.parse().unwrap()).collect();
        assert!(finite.windows(2).all(|w| w[0] < w[1]), "{b:?}");
    }

    #[test]
    fn hourly_ranges_expand_and_are_bounded() {
        let v = instants(&["2026-10-09T00:00:00Z..2026-10-09T03:00:00Z".into()]).unwrap();
        assert_eq!(
            v,
            vec![
                "2026-10-09T00:00:00Z",
                "2026-10-09T01:00:00Z",
                "2026-10-09T02:00:00Z",
                "2026-10-09T03:00:00Z"
            ]
        );
        let q = instants(&["2026-10-09T00:00:00Z..2026-10-09T00:30:00Z/15m".into()]).unwrap();
        assert_eq!(q.len(), 3);
        let one = instants(&["2026-10-09T11:45:51+02:00".into()]).unwrap();
        assert_eq!(one, vec!["2026-10-09T09:45:51Z"], "instants are UTC");
        assert!(instants(&["2026-10-09T03:00:00Z..2026-10-09T00:00:00Z".into()]).is_err());
        assert!(
            instants(&["2026-10-01T00:00:00Z..2026-10-09T00:00:00Z".into()]).is_err(),
            "over a week hourly"
        );
        assert!(instants(&["2026-10-09T00:00:00Z..2026-10-09T01:00:00Z/1d".into()]).is_err());
        assert!(instants(&["2026-10-09T00:00:00Z..2026-10-09T01:00:00Z/0h".into()]).is_err());
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
