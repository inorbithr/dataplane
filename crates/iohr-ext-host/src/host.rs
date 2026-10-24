//! The engine, the per-extension store and the host side of `wit/host.wit`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wasmtime::component::{Component, HasSelf, Linker, ResourceTable};
use wasmtime::{Config, Engine, ResourceLimiter, Store, Trap};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::limits::{
    EPOCH_TICK_MS, Limits, LimitsHandle, MAX_ATTRS, MAX_INSTANCES, MAX_LOG_BYTES, MAX_MEMORIES,
    MAX_NAME, MAX_TABLE_ELEMENTS, MAX_TABLES, MAX_WASM_STACK, MEMORY_RESERVATION,
};
use crate::manifest::Capability;
use crate::{Error, Package};

mod bindings {
    wasmtime::component::bindgen!({ path: "wit", world: "extension" });
}
use bindings::iohr::ext::{config, log, sensor, timer, trail};

/// One sensor reading, as the agent's probes and checks publish it.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// The sensor's name.
    pub name: String,
    /// Its value.
    pub value: f64,
    /// Its unit.
    pub unit: String,
    /// When it was read, milliseconds since the Unix epoch.
    pub at_ms: u64,
}

/// What an extension reads: the agent's sensor readings.
pub trait Sensors: Send + Sync {
    /// The latest reading of `name`.
    fn read(&self, name: &str) -> Option<Reading>;
    /// Every sensor name.
    fn list(&self) -> Vec<String>;
}

/// One event an extension puts in the agent's trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The event name.
    pub name: String,
    /// Its attributes.
    pub attrs: Vec<(String, String)>,
}

/// Where an extension's trail events go.
pub trait Trail: Send + Sync {
    /// Records `event` for the extension `ext` (its manifest id).
    fn emit(&self, ext: &str, event: Event);
}

/// Advances the engine's epoch every [`EPOCH_TICK_MS`], which is what ends a call that
/// runs past its deadline. Stops when the last owner drops it.
#[derive(Debug)]
struct Ticker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Ticker {
    fn start(engine: &Engine) -> Result<Self, Error> {
        let stop = Arc::new(AtomicBool::new(false));
        let (e, s) = (engine.clone(), Arc::clone(&stop));
        let thread = std::thread::Builder::new()
            .name("iohr-ext-epoch".into())
            .spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                    e.increment_epoch();
                }
            })
            .map_err(|e| Error::Engine(e.to_string()))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The engine every extension runs on, with the sources it reads from and the sink it
/// writes to.
#[derive(Clone)]
pub struct Host {
    engine: Engine,
    ticker: Arc<Ticker>,
    limits: LimitsHandle,
    sensors: Arc<dyn Sensors>,
    trail: Arc<dyn Trail>,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Host {
    /// Starts the engine (fuel, epoch deadline, bounded stack and memory reservation).
    ///
    /// # Errors
    /// [`Error::Engine`] when wasmtime cannot be configured or the ticker not started.
    pub fn new(
        limits: LimitsHandle,
        sensors: Arc<dyn Sensors>,
        trail: Arc<dyn Trail>,
    ) -> Result<Self, Error> {
        let mut c = Config::new();
        c.wasm_component_model(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(MAX_WASM_STACK)
            .memory_reservation(MEMORY_RESERVATION);
        let engine = Engine::new(&c).map_err(|e| Error::Engine(e.to_string()))?;
        Ok(Self {
            ticker: Arc::new(Ticker::start(&engine)?),
            engine,
            limits,
            sensors,
            trail,
        })
    }

    /// Compiles a verified package and instantiates it with the interfaces in
    /// `granted` (the policy's yes). Every import must be a capability the manifest
    /// declares and `granted` holds, or plain WASI (linked with nothing granted:
    /// no files, environment or sockets). `config` overrides the manifest's `[config]`.
    ///
    /// # Errors
    /// [`Error::Component`] for a component that does not compile or imports something
    /// else, [`Error::Capability`] for an import not declared and granted, [`Error::Limit`]
    /// or [`Error::Trap`] when instantiation breaks a bound.
    pub fn load(
        &self,
        package: &Package,
        granted: &BTreeSet<Capability>,
        config: &BTreeMap<String, String>,
    ) -> Result<Loaded, Error> {
        let component = Component::new(&self.engine, &package.component)
            .map_err(|e| Error::Component(first_line(&e)))?;
        let component_type = component.component_type();
        let imports = component_type.imports(&self.engine);
        let mut used = BTreeSet::new();
        for (name, _) in imports {
            if let Some(cap) = Capability::from_import(name) {
                if !package.manifest.capabilities.contains(&cap) {
                    return Err(Error::Capability(format!(
                        "imports {} but the manifest does not declare {:?}",
                        cap.name(),
                        cap.name()
                    )));
                }
                if !granted.contains(&cap) {
                    return Err(Error::Capability(format!(
                        "imports {} but the policy does not grant it",
                        cap.name()
                    )));
                }
                used.insert(cap);
            } else if !name.starts_with("wasi:") {
                return Err(Error::Component(format!(
                    "import {:?} is not offered",
                    crate::manifest::shown(name)
                )));
            }
        }

        let mut linker = Linker::<Ctx>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(|e| Error::Engine(first_line(&e)))?;
        let link = |r: wasmtime::Result<()>| r.map_err(|e| Error::Engine(first_line(&e)));
        for cap in &used {
            link(match cap {
                Capability::Log => log::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |c| c),
                Capability::Config => {
                    config::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |c| c)
                }
                Capability::Timer => timer::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |c| c),
                Capability::Sensor => {
                    sensor::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |c| c)
                }
                Capability::Trail => trail::add_to_linker::<Ctx, HasSelf<Ctx>>(&mut linker, |c| c),
            })?;
        }

        let mut settings = package.manifest.config.clone();
        settings.extend(config.iter().map(|(k, v)| (k.clone(), v.clone())));
        let limits = self.limits.get();
        let ctx = Ctx {
            id: package.manifest.id.clone(),
            config: settings,
            sensors: Arc::clone(&self.sensors),
            trail: Arc::clone(&self.trail),
            interval_ms: limits.clamp_interval(0),
            min_interval_ms: limits.min_interval_ms,
            call: Budget::new(&limits),
            bounds: Bounds::new(&limits),
            wasi: WasiCtx::builder().build(),
            table: ResourceTable::new(),
        };
        let mut store = Store::new(&self.engine, ctx);
        store.limiter(|c| &mut c.bounds);
        begin_call(&mut store, &self.limits.get())?;
        let instance = bindings::Extension::instantiate(&mut store, &component, &linker)
            .map_err(|e| map_error(&e))?;
        Ok(Loaded {
            id: package.manifest.id.clone(),
            limits: self.limits.clone(),
            store,
            instance,
            stopped: false,
            _ticker: Arc::clone(&self.ticker),
        })
    }
}

/// An instantiated extension. After a trap or a limit it is stopped: every later call
/// is refused, and the agent loads it again if it wants it back.
pub struct Loaded {
    id: String,
    limits: LimitsHandle,
    store: Store<Ctx>,
    instance: bindings::Extension,
    stopped: bool,
    _ticker: Arc<Ticker>,
}

impl std::fmt::Debug for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loaded")
            .field("id", &self.id)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}

impl Loaded {
    /// The manifest id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Milliseconds between ticks: what the extension asked for through
    /// `timer.set-interval`, clamped, else the shortest allowed.
    #[must_use]
    pub fn interval_ms(&self) -> u32 {
        self.store.data().interval_ms
    }

    /// Whether a trap or a limit stopped it.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Calls `init`; an error from the guest refuses the start.
    ///
    /// # Errors
    /// [`Error::Guest`] for an error result, [`Error::Limit`] or [`Error::Trap`] for a
    /// call that broke a bound or trapped.
    pub fn init(&mut self) -> Result<(), Error> {
        self.call(|i, s| i.call_init(s))
    }

    /// Calls `tick`.
    ///
    /// # Errors
    /// As [`Loaded::init`].
    pub fn tick(&mut self) -> Result<(), Error> {
        self.call(|i, s| i.call_tick(s))
    }

    fn call(
        &mut self,
        f: impl FnOnce(&bindings::Extension, &mut Store<Ctx>) -> wasmtime::Result<Result<(), String>>,
    ) -> Result<(), Error> {
        if self.stopped {
            return Err(Error::Trap(
                "the extension stopped after an earlier failure".into(),
            ));
        }
        begin_call(&mut self.store, &self.limits.get())?;
        match f(&self.instance, &mut self.store) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => Err(Error::Guest(crate::manifest::shown(&msg))),
            Err(e) => {
                self.stopped = true;
                Err(map_error(&e))
            }
        }
    }
}

/// Fresh fuel, deadline and budgets from `limits`, for the next call.
fn begin_call(store: &mut Store<Ctx>, limits: &Limits) -> Result<(), Error> {
    store
        .set_fuel(limits.fuel)
        .map_err(|e| Error::Engine(first_line(&e)))?;
    store.set_epoch_deadline(limits.deadline_ticks());
    let ctx = store.data_mut();
    ctx.call = Budget::new(limits);
    ctx.bounds.max_bytes = limits.memory_bytes;
    ctx.min_interval_ms = limits.min_interval_ms.min(crate::limits::MAX_INTERVAL_MS);
    Ok(())
}

fn map_error(e: &wasmtime::Error) -> Error {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => Error::Limit("fuel"),
        Some(Trap::Interrupt) => Error::Limit("deadline"),
        _ => Error::Trap(first_line(e)),
    }
}

fn first_line(e: &wasmtime::Error) -> String {
    crate::manifest::shown(e.to_string().lines().next().unwrap_or_default())
}

/// What one call may still do.
#[derive(Debug, Clone, Copy)]
struct Budget {
    trail: u32,
    log: u32,
}

impl Budget {
    fn new(l: &Limits) -> Self {
        Self {
            trail: l.trail_per_call,
            log: l.log_per_call,
        }
    }
}

/// Memory, table and instance ceilings for one store.
#[derive(Debug)]
struct Bounds {
    max_bytes: u64,
    held: u64,
}

impl Bounds {
    fn new(l: &Limits) -> Self {
        Self {
            max_bytes: l.memory_bytes,
            held: 0,
        }
    }
}

impl ResourceLimiter for Bounds {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let grow = u64::try_from(desired.saturating_sub(current)).unwrap_or(u64::MAX);
        let total = self.held.saturating_add(grow);
        if total > self.max_bytes {
            return Ok(false);
        }
        self.held = total;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }

    fn instances(&self) -> usize {
        MAX_INSTANCES
    }

    fn memories(&self) -> usize {
        MAX_MEMORIES
    }

    fn tables(&self) -> usize {
        MAX_TABLES
    }
}

/// The store's data: what the host interfaces read and write.
struct Ctx {
    id: String,
    config: BTreeMap<String, String>,
    sensors: Arc<dyn Sensors>,
    trail: Arc<dyn Trail>,
    interval_ms: u32,
    min_interval_ms: u32,
    call: Budget,
    bounds: Bounds,
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl log::Host for Ctx {
    fn write(&mut self, level: log::Level, message: String) {
        if self.call.log == 0 {
            return;
        }
        self.call.log -= 1;
        let mut line: String = message.chars().filter(|c| !c.is_control()).collect();
        let mut end = line.len().min(MAX_LOG_BYTES);
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
        let ext = self.id.as_str();
        match level {
            log::Level::Trace => tracing::trace!(ext, "{line}"),
            log::Level::Debug => tracing::debug!(ext, "{line}"),
            log::Level::Info => tracing::info!(ext, "{line}"),
            log::Level::Warn => tracing::warn!(ext, "{line}"),
            log::Level::Error => tracing::error!(ext, "{line}"),
        }
    }
}

impl config::Host for Ctx {
    fn get(&mut self, key: String) -> Option<String> {
        self.config.get(&key).cloned()
    }

    fn keys(&mut self) -> Vec<String> {
        self.config.keys().cloned().collect()
    }
}

impl timer::Host for Ctx {
    fn now_ms(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn set_interval(&mut self, ms: u32) -> u32 {
        self.interval_ms = ms.clamp(self.min_interval_ms, crate::limits::MAX_INTERVAL_MS);
        self.interval_ms
    }
}

impl sensor::Host for Ctx {
    fn read(&mut self, name: String) -> Option<sensor::Reading> {
        self.sensors.read(&name).map(|r| sensor::Reading {
            name: r.name,
            value: r.value,
            unit: r.unit,
            at_ms: r.at_ms,
        })
    }

    fn list(&mut self) -> Vec<String> {
        self.sensors.list()
    }
}

impl trail::Host for Ctx {
    fn emit(&mut self, event: trail::Event) -> bool {
        let fits = |s: &str, max: usize| s.len() <= max;
        if self.call.trail == 0
            || event.name.is_empty()
            || !fits(&event.name, MAX_NAME)
            || event.attrs.len() > MAX_ATTRS
            || event.attrs.iter().any(|(k, v)| {
                k.is_empty() || !fits(k, MAX_NAME) || !fits(v, crate::limits::MAX_VALUE)
            })
        {
            return false;
        }
        self.call.trail -= 1;
        self.trail.emit(
            &self.id,
            Event {
                name: event.name,
                attrs: event.attrs,
            },
        );
        true
    }
}
