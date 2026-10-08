//! A rolling window of hwmon readings and disk counters, sampled on an interval (10 s by
//! default). It reads only the `*_input` files found at discovery and one
//! `/proc/diskstats`, rediscovers the chips every few minutes (hwmon numbers change
//! when a driver reloads), and keeps nothing on disk: after a restart the window starts
//! empty and rates are unknown until two samples exist.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use super::hwmon::{self, Kind};
use super::storage::{IoCounters, IoRates, parse_diskstats};
use super::sysfs::Root;

/// Rediscover chips every this many samples.
const REDISCOVER_EVERY: u32 = 30;

/// One sample.
#[derive(Debug, Clone)]
pub struct Sample {
    /// Milliseconds since the sampler started.
    pub at_ms: u64,
    /// Unix seconds.
    pub wall: i64,
    /// Sensor key → value.
    pub values: BTreeMap<String, i64>,
    /// Disk → counters.
    pub io: BTreeMap<String, IoCounters>,
}

#[derive(Debug, Clone)]
struct Probe {
    key: String,
    path: String,
    kind: Kind,
    chip: String,
}

/// The window.
#[derive(Debug)]
pub struct Sampler {
    root: Root,
    chips: Vec<hwmon::Chip>,
    probes: Vec<Probe>,
    started: Instant,
    window: Duration,
    samples: VecDeque<Sample>,
    ticks: u32,
    /// How long the last sample took to read.
    pub last_cost: Duration,
    /// The slowest sample so far.
    pub max_cost: Duration,
}

/// A sampler shared between its task and its readers (the hwmon check).
pub type Shared = Arc<Mutex<Sampler>>;

impl Sampler {
    /// A sampler over `root`, keeping `window` of history.
    #[must_use]
    pub fn new(root: Root, window: Duration) -> Self {
        let mut s = Self {
            root,
            chips: Vec::new(),
            probes: Vec::new(),
            started: Instant::now(),
            window,
            samples: VecDeque::new(),
            ticks: 0,
            last_cost: Duration::ZERO,
            max_cost: Duration::ZERO,
        };
        s.discover();
        s
    }

    fn discover(&mut self) {
        self.chips = hwmon::read(&self.root);
        self.probes = self
            .chips
            .iter()
            .flat_map(|c| {
                c.sensors.iter().map(|s| Probe {
                    key: c.key(s),
                    path: s.input_path.clone(),
                    kind: s.kind,
                    chip: c.name.clone(),
                })
            })
            .collect();
    }

    /// Reads one sample now.
    pub fn tick(&mut self) {
        let t = Instant::now();
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks.is_multiple_of(REDISCOVER_EVERY) {
            self.discover();
        }
        let mut values = BTreeMap::new();
        for p in &self.probes {
            if let Some(v) = self.root.int(&p.path) {
                // A disconnected probe's sentinel is never a value.
                if !(p.kind == Kind::Temp && p.chip == "asusec" && v == -40_000) {
                    values.insert(p.key.clone(), v);
                }
            }
        }
        let io = self
            .root
            .read("/proc/diskstats")
            .map(|t| parse_diskstats(&t))
            .unwrap_or_default();
        self.push(Sample {
            at_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            wall: chrono::Utc::now().timestamp(),
            values,
            io,
        });
        self.last_cost = t.elapsed();
        self.max_cost = self.max_cost.max(self.last_cost);
    }

    /// Adds a sample (tests feed synthetic ones) and drops what fell out of the window.
    pub fn push(&mut self, s: Sample) {
        let now = s.at_ms;
        self.samples.push_back(s);
        let keep = u64::try_from(self.window.as_millis()).unwrap_or(u64::MAX);
        while self
            .samples
            .front()
            .is_some_and(|f| now.saturating_sub(f.at_ms) > keep)
        {
            self.samples.pop_front();
        }
    }

    /// Sensors sampled.
    #[must_use]
    pub fn sensor_count(&self) -> usize {
        self.probes.len()
    }

    /// The chips found at the last discovery.
    #[must_use]
    pub fn chips(&self) -> &[hwmon::Chip] {
        &self.chips
    }

    /// The samples held.
    #[must_use]
    pub fn samples(&self) -> &VecDeque<Sample> {
        &self.samples
    }

    /// The newest sample's time, ms since start.
    #[must_use]
    pub fn now_ms(&self) -> Option<u64> {
        self.samples.back().map(|s| s.at_ms)
    }

    /// The newest value of a sensor.
    #[must_use]
    pub fn latest(&self, key: &str) -> Option<i64> {
        self.samples.back()?.values.get(key).copied()
    }

    /// `(at_ms, value)` for a sensor across the window.
    #[must_use]
    pub fn series(&self, key: &str) -> Vec<(u64, i64)> {
        self.samples
            .iter()
            .filter_map(|s| s.values.get(key).map(|v| (s.at_ms, *v)))
            .collect()
    }

    /// The highest (or, `below`, lowest) value since `since_ms`.
    #[must_use]
    pub fn extreme_since(&self, key: &str, since_ms: u64, below: bool) -> Option<i64> {
        let it = self
            .samples
            .iter()
            .filter(|s| s.at_ms >= since_ms)
            .filter_map(|s| s.values.get(key).copied());
        if below { it.min() } else { it.max() }
    }

    /// The slope over the last `over`, in the sensor's unit per minute (least squares).
    /// `None` with fewer than two samples or less than 20 s between the first and last.
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)] // a slope, rounded
    pub fn rate_per_min(&self, key: &str, over: Duration) -> Option<i64> {
        let now = self.now_ms()?;
        let over = u64::try_from(over.as_millis()).unwrap_or(u64::MAX);
        let pts: Vec<(f64, f64)> = self
            .series(key)
            .into_iter()
            .filter(|(t, _)| now.saturating_sub(*t) <= over)
            .map(|(t, v)| (t as f64 / 60_000.0, v as f64))
            .collect();
        slope(&pts).map(|s| s.round() as i64)
    }

    /// Disk I/O rates between consecutive samples: `(at_ms, rates)`.
    #[must_use]
    pub fn io_series(&self, disk: &str) -> Vec<(u64, IoRates)> {
        self.samples
            .iter()
            .zip(self.samples.iter().skip(1))
            .filter_map(|(a, b)| {
                let (x, y) = (a.io.get(disk)?, b.io.get(disk)?);
                Some((b.at_ms, y.rates_since(x, b.at_ms.saturating_sub(a.at_ms))))
            })
            .collect()
    }
}

/// Least-squares slope of `(x, y)`; `None` for fewer than two points or an x span under
/// 1/3 minute.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn slope(pts: &[(f64, f64)]) -> Option<f64> {
    if pts.len() < 2 {
        return None;
    }
    let (first, last) = (pts.first()?.0, pts.last()?.0);
    if last - first < 1.0 / 3.0 {
        return None;
    }
    let n = pts.len() as f64;
    let mx = pts.iter().map(|p| p.0).sum::<f64>() / n;
    let my = pts.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = pts.iter().map(|p| (p.0 - mx).powi(2)).sum();
    let sxy: f64 = pts.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    (sxx > 0.0).then(|| sxy / sxx)
}

/// Samples `shared` every `interval` until `shutdown`; `after` sees each sample.
pub async fn run(
    shared: Shared,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
    after: impl Fn(&Sampler) + Send + Sync + 'static,
) {
    let after = Arc::new(after);
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tick.tick() => {
                let s = Arc::clone(&shared);
                let after = Arc::clone(&after);
                let _ = tokio::task::spawn_blocking(move || {
                    let mut g = match s.lock() { Ok(g) => g, Err(p) => p.into_inner() };
                    g.tick();
                    after(&g);
                }).await;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A sample at `at_ms` with one sensor and one disk's written sectors.
    pub(crate) fn sample(at_ms: u64, key: &str, v: i64, disk: &str, written: u64) -> Sample {
        let mut values = BTreeMap::new();
        values.insert(key.to_owned(), v);
        let mut io = BTreeMap::new();
        io.insert(
            disk.to_owned(),
            IoCounters {
                sectors_written: written,
                writes: written / 8,
                ..IoCounters::default()
            },
        );
        Sample {
            at_ms,
            wall: 0,
            values,
            io,
        }
    }

    #[test]
    fn window_rates_and_extremes() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Sampler::new(Root::at(dir.path()), Duration::from_secs(300));
        assert_eq!(s.rate_per_min("k", Duration::from_secs(120)), None);
        // +1 °C every 10 s: 6 °C per minute.
        for i in 0..7u64 {
            s.push(sample(
                i * 10_000,
                "k",
                100_000 + i64::try_from(i).unwrap() * 1_000,
                "d",
                i * 1_000,
            ));
        }
        assert_eq!(s.rate_per_min("k", Duration::from_secs(120)), Some(6_000));
        assert_eq!(s.latest("k"), Some(106_000));
        assert_eq!(s.extreme_since("k", 30_000, false), Some(106_000));
        assert_eq!(s.extreme_since("k", 30_000, true), Some(103_000));
        let io = s.io_series("d");
        assert_eq!(io.len(), 6);
        assert_eq!(io[0].1.write_bytes_per_s, 100 * 512);
        // Old samples fall out of the window.
        s.push(sample(1_000_000, "k", 1, "d", 0));
        assert_eq!(s.samples().len(), 1);
    }

    #[test]
    fn the_fixture_samples_every_sensor_but_sentinels() {
        let root = Root::at(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/host/trx40/root"),
        );
        let mut s = Sampler::new(root, Duration::from_secs(600));
        s.tick();
        assert_eq!(s.latest("asusec/temp/Chipset"), Some(107_000));
        assert_eq!(
            s.latest("asusec/temp/T_Sensor"),
            None,
            "the -40 °C sentinel"
        );
        assert!(s.samples()[0].io.contains_key("nvme8n1"));
    }
}
