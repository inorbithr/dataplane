//! `[metadata]` in `agent.toml`: where this agent runs, who owns it, what binds it and
//! what it can be trusted for (RFC 0088 in inorbithr/core). Every field is optional; a
//! field that is not set is unknown, never a default. Values are typed and short, the
//! enumerations are closed, and the rules between fields are checked by
//! [`MetadataConfig::problems`].
//!
//! Only the part [`MetadataConfig::reported`] returns leaves the machine, in the hello.
//! Rack and row, the DNS and NTP names, the certificate authority, the secrets backend,
//! the audit destination and the whole `operations` section never do.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// The longest string any field takes.
pub const MAX_STR: usize = 128;
/// The most entries any list takes.
pub const MAX_LIST: usize = 32;
/// The most pairs `asset.tags` takes.
pub const MAX_TAGS: usize = 32;
/// The largest clock uncertainty that is still a clock, in milliseconds.
pub const MAX_CLOCK_UNCERTAINTY_MS: u32 = 60_000;
/// The prefix of an environment override: `IOHR_AGENT_META_<SECTION>_<FIELD>`.
pub const ENV_PREFIX: &str = "IOHR_AGENT_META_";

const SECTIONS: [&str; 9] = [
    "placement",
    "organisation",
    "environment",
    "asset",
    "compliance",
    "security",
    "network",
    "operations",
    "platform",
];

/// Fields that take a list; an override splits them on commas.
const LIST_FIELDS: [&str; 8] = [
    "change_freeze",
    "maintenance_windows",
    "slo_refs",
    "catalogue_refs",
    "regimes",
    "data_classes_allowed",
    "may_leave_jurisdiction",
    "external_models_may_see",
];

/// The `[metadata]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct MetadataConfig {
    /// Send the reported subset to the platform in the hello (RFC 0088, "What leaves
    /// the machine"). Off, nothing of this table leaves the machine.
    pub report: bool,
    /// Where it runs.
    pub placement: Placement,
    /// Who owns it.
    pub organisation: Organisation,
    /// What kind of environment it serves.
    pub environment: EnvironmentMeta,
    /// What it is in the inventory.
    pub asset: Asset,
    /// What binds it.
    pub compliance: Compliance,
    /// What it can be trusted for.
    pub security: Security,
    /// Its network and clock.
    pub network: Network,
    /// How it is operated. Never reported.
    pub operations: Operations,
    /// What it believes about its place on the platform, as information.
    pub platform: PlatformMeta,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            report: true,
            placement: Placement::default(),
            organisation: Organisation::default(),
            environment: EnvironmentMeta::default(),
            asset: Asset::default(),
            compliance: Compliance::default(),
            security: Security::default(),
            network: Network::default(),
            operations: Operations::default(),
            platform: PlatformMeta::default(),
        }
    }
}

/// `[metadata.placement]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Placement {
    /// Cloud, on-premises, colocation or edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderKind>,
    /// The provider's name (a cloud, a colocation company, "own").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// The site or datacentre id, as the inventory names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    /// The site's name for people.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
    /// The region, in the provider's or the company's words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The availability zone, hall or failure zone within the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// The rack. Never reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rack: Option<String>,
    /// The row. Never reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row: Option<String>,
    /// ISO 3166-1 alpha-2, upper case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<CountryCode>,
    /// The jurisdiction whose law applies, e.g. `EU`, `US-CA`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    /// The data-residency zone the company defines; needs `country`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub residency_zone: Option<String>,
    /// The latency zone the company defines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_zone: Option<String>,
}

/// `[metadata.organisation]`. References and roles, never a person's data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Organisation {
    /// The legal entity that runs the machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_entity: Option<String>,
    /// The business unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_unit: Option<String>,
    /// The department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// The team.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// The cost centre.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_centre: Option<String>,
    /// The project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The role that owns it ("service owner"), not a name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_role: Option<String>,
    /// A channel to reach the owners (`#payments-oncall`), not a person.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_channel: Option<String>,
    /// An on-call rota as a reference (`pagerduty:P7Q2`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_call_rota: Option<String>,
    /// An escalation policy as a reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_policy: Option<String>,
}

/// `[metadata.environment]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct EnvironmentMeta {
    /// Production, staging, development, test or disaster recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// How much depends on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criticality: Option<Criticality>,
    /// Date intervals (`2026-12-20/2027-01-05`) during which nothing changes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub change_freeze: Vec<DateInterval>,
    /// Maintenance windows, in the company's words (`Sun 02:00-04:00 Europe/Berlin`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub maintenance_windows: Vec<String>,
    /// The SLA, as a reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_ref: Option<String>,
    /// SLOs, as references.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub slo_refs: Vec<String>,
}

/// `[metadata.asset]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Asset {
    /// The configuration item in the CMDB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdb_id: Option<String>,
    /// Service-catalogue references (`backstage:component:checkout`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub catalogue_refs: Vec<String>,
    /// Bare metal, virtual machine, container or serverless.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_class: Option<HardwareClass>,
    /// When it was commissioned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commissioned: Option<IsoDate>,
    /// When it is planned to go away; after `commissioned`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decommission_planned: Option<IsoDate>,
    /// Free tags for what has no typed home.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
}

/// `[metadata.compliance]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Compliance {
    /// The regimes in scope, as the company declares them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub regimes: Vec<Regime>,
    /// The data classes that may be on this machine.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub data_classes_allowed: Vec<DataClass>,
    /// The classes that may leave the jurisdiction; a subset of `data_classes_allowed`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub may_leave_jurisdiction: Vec<DataClass>,
    /// The classes a third-party model may see; a subset of `may_leave_jurisdiction`,
    /// never `restricted`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_models_may_see: Vec<DataClass>,
    /// The retention policy, as a reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<String>,
    /// Where audit records go, as a reference. Never reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_destination: Option<String>,
}

/// `[metadata.security]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Security {
    /// The trust domain: machines that fail together share one. Observations from one
    /// domain count as one independent source (RFC 0086).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// What the machine can attest about its boot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    /// How isolated it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<Isolation>,
    /// The certificate authority it trusts, as a name. Never reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_authority: Option<String>,
    /// The secrets backend, as a reference (`vault:kv/prod`). Never reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_backend: Option<String>,
}

/// `[metadata.network]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Network {
    /// The network zone (`dmz`, `internal`, `management`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// How it reaches outside.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    /// The DNS source, as a name. Never reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    /// The NTP source, as a name. Never reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ntp: Option<String>,
    /// The clock source (RFC 0086's clock quality).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_source: Option<ClockSource>,
    /// The clock's worst-case error, in milliseconds, at most a minute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_uncertainty_ms: Option<u32>,
}

/// `[metadata.operations]`. Never reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Operations {
    /// The collector profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// The runbook, as a reference or address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runbook: Option<String>,
}

/// `[metadata.platform]`. Information only: the platform's own labels decide targeting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PlatformMeta {
    /// The agent group it believes it belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

macro_rules! closed_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
        pub enum $name {
            $($(#[$vdoc])* #[serde(rename = $wire)] $variant,)+
        }

        impl $name {
            /// The wire name.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

closed_enum! {
    /// Who provides the machine.
    ProviderKind {
        /// A public cloud.
        Cloud => "cloud",
        /// The company's own premises.
        OnPrem => "on_prem",
        /// A colocation provider's datacentre.
        Colocation => "colocation",
        /// An edge site.
        Edge => "edge",
    }
}

closed_enum! {
    /// What kind of environment the machine serves.
    Tier {
        /// Production.
        Production => "production",
        /// Staging.
        Staging => "staging",
        /// Development.
        Development => "development",
        /// Test.
        Test => "test",
        /// Disaster recovery.
        DisasterRecovery => "disaster_recovery",
    }
}

closed_enum! {
    /// How much depends on the machine.
    Criticality {
        /// The business stops without it.
        Critical => "critical",
        /// High.
        High => "high",
        /// Medium.
        Medium => "medium",
        /// Low.
        Low => "low",
    }
}

closed_enum! {
    /// What the machine is.
    HardwareClass {
        /// Bare metal.
        BareMetal => "bare_metal",
        /// A virtual machine.
        VirtualMachine => "virtual_machine",
        /// A container.
        Container => "container",
        /// A serverless runtime.
        Serverless => "serverless",
    }
}

closed_enum! {
    /// A data class, as RFC 0086 names them.
    DataClass {
        /// May be published.
        Public => "public",
        /// Internal to the company.
        Internal => "internal",
        /// Confidential.
        Confidential => "confidential",
        /// Secrets, personal or health data: stays where it was read.
        Restricted => "restricted",
    }
}

closed_enum! {
    /// What the machine can attest about its boot.
    Attestation {
        /// Nothing.
        None => "none",
        /// A TPM.
        Tpm => "tpm",
        /// Measured boot.
        MeasuredBoot => "measured_boot",
        /// A confidential virtual machine.
        ConfidentialVm => "confidential_vm",
    }
}

closed_enum! {
    /// How isolated the machine is.
    Isolation {
        /// Shared with other tenants or workloads.
        Shared => "shared",
        /// Dedicated to this workload.
        Dedicated => "dedicated",
        /// No network path to the outside.
        AirGapped => "air_gapped",
    }
}

closed_enum! {
    /// How the machine reaches outside.
    Egress {
        /// Directly.
        Direct => "direct",
        /// Through a proxy.
        Proxy => "proxy",
        /// Not at all.
        None => "none",
    }
}

closed_enum! {
    /// Which clock the machine keeps.
    ClockSource {
        /// NTP.
        Ntp => "ntp",
        /// PTP.
        Ptp => "ptp",
        /// A real-time clock with no sync.
        Rtc => "rtc",
        /// Not known.
        Unknown => "unknown",
    }
}

closed_enum! {
    /// Which collectors run.
    Profile {
        /// Minimal.
        Minimal => "minimal",
        /// Standard.
        Standard => "standard",
        /// Deep.
        Deep => "deep",
        /// Raised for an incident.
        Incident => "incident",
        /// Forensic, under explicit authority.
        Forensic => "forensic",
    }
}

/// A compliance regime in scope: a known one, or `other:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Regime {
    /// The EU General Data Protection Regulation.
    Gdpr,
    /// The US Health Insurance Portability and Accountability Act.
    Hipaa,
    /// The EU Digital Operational Resilience Act.
    Dora,
    /// SOC 2.
    Soc2,
    /// ISO/IEC 27001.
    Iso27001,
    /// PCI DSS.
    PciDss,
    /// The EU NIS2 directive.
    Nis2,
    /// The California Consumer Privacy Act.
    Ccpa,
    /// A regime not listed, by name.
    Other(String),
}

const REGIME_PATTERN: &str =
    "^(gdpr|hipaa|dora|soc2|iso27001|pci_dss|nis2|ccpa|other:[a-z0-9_-]{1,32})$";

impl Regime {
    /// The wire form.
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            Self::Gdpr => "gdpr".into(),
            Self::Hipaa => "hipaa".into(),
            Self::Dora => "dora".into(),
            Self::Soc2 => "soc2".into(),
            Self::Iso27001 => "iso27001".into(),
            Self::PciDss => "pci_dss".into(),
            Self::Nis2 => "nis2".into(),
            Self::Ccpa => "ccpa".into(),
            Self::Other(name) => format!("other:{name}"),
        }
    }
}

impl TryFrom<String> for Regime {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        Ok(match s.as_str() {
            "gdpr" => Self::Gdpr,
            "hipaa" => Self::Hipaa,
            "dora" => Self::Dora,
            "soc2" => Self::Soc2,
            "iso27001" => Self::Iso27001,
            "pci_dss" => Self::PciDss,
            "nis2" => Self::Nis2,
            "ccpa" => Self::Ccpa,
            other => {
                let name = other.strip_prefix("other:").ok_or_else(|| {
                    format!(
                        "{other:?} is not a regime: gdpr, hipaa, dora, soc2, iso27001, pci_dss, nis2, ccpa, or other:<name>"
                    )
                })?;
                let ok = (1..=32).contains(&name.len())
                    && name.bytes().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-'
                    });
                if !ok {
                    return Err(format!(
                        "{other:?}: the name after other: is 1 to 32 of a-z, 0-9, _ and -"
                    ));
                }
                Self::Other(name.to_owned())
            }
        })
    }
}

impl From<Regime> for String {
    fn from(r: Regime) -> Self {
        r.as_string()
    }
}

impl JsonSchema for Regime {
    fn schema_name() -> Cow<'static, str> {
        "Regime".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "A compliance regime: gdpr, hipaa, dora, soc2, iso27001, pci_dss, nis2, ccpa, or other:<name>.",
            "pattern": REGIME_PATTERN,
        })
    }
}

/// An ISO 3166-1 alpha-2 country code, upper case.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CountryCode(String);

impl CountryCode {
    /// The code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CountryCode {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        if s.len() == 2 && ISO_3166_1_ALPHA_2.binary_search(&s.as_str()).is_ok() {
            Ok(Self(s))
        } else {
            Err(format!(
                "{s:?} is not an ISO 3166-1 alpha-2 country code (upper case, e.g. DE)"
            ))
        }
    }
}

impl From<CountryCode> for String {
    fn from(c: CountryCode) -> Self {
        c.0
    }
}

impl JsonSchema for CountryCode {
    fn schema_name() -> Cow<'static, str> {
        "CountryCode".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "An ISO 3166-1 alpha-2 country code, upper case.",
            "pattern": "^[A-Z]{2}$",
        })
    }
}

/// A calendar date, `YYYY-MM-DD`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IsoDate(time::Date);

impl IsoDate {
    /// The date.
    #[must_use]
    pub const fn date(&self) -> time::Date {
        self.0
    }
}

impl TryFrom<String> for IsoDate {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        time::Date::parse(
            &s,
            time::macros::format_description!("[year]-[month]-[day]"),
        )
        .map(Self)
        .map_err(|e| format!("{s:?} is not a date (YYYY-MM-DD): {e}"))
    }
}

impl From<IsoDate> for String {
    fn from(d: IsoDate) -> Self {
        d.to_string()
    }
}

impl fmt::Display for IsoDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, m, d) = (self.0.year(), u8::from(self.0.month()), self.0.day());
        write!(f, "{y:04}-{m:02}-{d:02}")
    }
}

impl JsonSchema for IsoDate {
    fn schema_name() -> Cow<'static, str> {
        "IsoDate".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "date",
            "description": "A calendar date, YYYY-MM-DD.",
        })
    }
}

/// A date interval, `from/to`, both inclusive, `from` not after `to`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DateInterval {
    /// The first day.
    pub from: IsoDate,
    /// The last day.
    pub to: IsoDate,
}

impl TryFrom<String> for DateInterval {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let (a, b) = s
            .split_once('/')
            .ok_or_else(|| format!("{s:?} is not an interval (YYYY-MM-DD/YYYY-MM-DD)"))?;
        let from = IsoDate::try_from(a.to_owned())?;
        let to = IsoDate::try_from(b.to_owned())?;
        if from > to {
            return Err(format!("{s:?} ends before it starts"));
        }
        Ok(Self { from, to })
    }
}

impl From<DateInterval> for String {
    fn from(i: DateInterval) -> Self {
        format!("{}/{}", i.from, i.to)
    }
}

impl JsonSchema for DateInterval {
    fn schema_name() -> Cow<'static, str> {
        "DateInterval".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "A date interval, YYYY-MM-DD/YYYY-MM-DD, both days inclusive.",
            "pattern": r"^\d{4}-\d{2}-\d{2}/\d{4}-\d{2}-\d{2}$",
        })
    }
}

/// Something wrong with the metadata: the field, by its path, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// `metadata.<section>.<field>`, or the environment variable that set it.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Prefixes and shapes of values that are keys or tokens, which never belong here.
fn looks_like_secret(s: &str) -> bool {
    const PREFIXES: [&str; 9] = [
        "-----BEGIN",
        "sk-",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "hvs.",
        "glpat-",
    ];
    PREFIXES.iter().any(|p| s.starts_with(p))
        || (s.len() >= 40
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
            && s.bytes().any(|c| c.is_ascii_digit())
            && s.bytes().any(|c| c.is_ascii_uppercase())
            && s.bytes().any(|c| c.is_ascii_lowercase()))
}

impl MetadataConfig {
    /// Every rule the table breaks, each with the field's path. Empty when it is fine.
    #[must_use]
    pub fn problems(&self) -> Vec<Problem> {
        let mut out = Vec::new();
        // Shape: every string short and printable, every list and map short. Walked over
        // the serialised form so no field can be forgotten.
        if let Ok(value) = serde_json::to_value(self) {
            walk(&value, "metadata", &mut out);
        }
        let problem = |path: &str, message: String| Problem {
            path: path.to_owned(),
            message,
        };
        let c = &self.compliance;
        for class in &c.may_leave_jurisdiction {
            if !c.data_classes_allowed.contains(class) {
                out.push(problem(
                    "metadata.compliance.may_leave_jurisdiction",
                    format!("{class} is not in data_classes_allowed"),
                ));
            }
        }
        for class in &c.external_models_may_see {
            if !c.may_leave_jurisdiction.contains(class) {
                out.push(problem(
                    "metadata.compliance.external_models_may_see",
                    format!("{class} is not in may_leave_jurisdiction"),
                ));
            }
        }
        if c.external_models_may_see.contains(&DataClass::Restricted) {
            out.push(problem(
                "metadata.compliance.external_models_may_see",
                "restricted data never reaches a third-party model".into(),
            ));
        }
        if self.placement.residency_zone.is_some() && self.placement.country.is_none() {
            out.push(problem(
                "metadata.placement.residency_zone",
                "a residency zone needs placement.country".into(),
            ));
        }
        if let (Some(from), Some(to)) = (&self.asset.commissioned, &self.asset.decommission_planned)
            && to <= from
        {
            out.push(problem(
                "metadata.asset.decommission_planned",
                format!("{to} is not after commissioned {from}"),
            ));
        }
        if let Some(ms) = self.network.clock_uncertainty_ms
            && ms > MAX_CLOCK_UNCERTAINTY_MS
        {
            out.push(problem(
                "metadata.network.clock_uncertainty_ms",
                format!("{ms} ms is more than a minute; a clock that uncertain is not a clock"),
            ));
        }
        out
    }

    /// Whether anything at all is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let empty = Self {
            report: self.report,
            ..Self::default()
        };
        *self == empty
    }

    /// Whether this is the default table: nothing set, reporting on. `to_toml` skips it then.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// How many fields are set.
    #[must_use]
    pub fn set_fields(&self) -> usize {
        let mut n = 0;
        if let Ok(value) = serde_json::to_value(self) {
            count_leaves(&value, &mut n);
        }
        n.saturating_sub(1) // `report` is always there
    }

    /// What leaves the machine in the hello: `None` when reporting is off or nothing is
    /// set. Rack and row, the DNS and NTP names, the certificate authority, the secrets
    /// backend, the audit destination and the operations section are never in it.
    #[must_use]
    pub fn reported(&self) -> Option<Reported> {
        if !self.report || self.is_empty() {
            return None;
        }
        let pl = &self.placement;
        let c = &self.compliance;
        let s = &self.security;
        let n = &self.network;
        Some(Reported {
            placement: ReportedPlacement {
                provider: pl.provider,
                provider_name: pl.provider_name.clone(),
                site_id: pl.site_id.clone(),
                site_name: pl.site_name.clone(),
                region: pl.region.clone(),
                zone: pl.zone.clone(),
                country: pl.country.clone(),
                jurisdiction: pl.jurisdiction.clone(),
                residency_zone: pl.residency_zone.clone(),
                latency_zone: pl.latency_zone.clone(),
            },
            organisation: self.organisation.clone(),
            environment: self.environment.clone(),
            asset: self.asset.clone(),
            compliance: ReportedCompliance {
                regimes: c.regimes.clone(),
                data_classes_allowed: c.data_classes_allowed.clone(),
                may_leave_jurisdiction: c.may_leave_jurisdiction.clone(),
                external_models_may_see: c.external_models_may_see.clone(),
                retention_policy: c.retention_policy.clone(),
            },
            security: ReportedSecurity {
                trust_domain: s.trust_domain.clone(),
                attestation: s.attestation,
                isolation: s.isolation,
            },
            network: ReportedNetwork {
                zone: n.zone.clone(),
                egress: n.egress,
                clock_source: n.clock_source,
                clock_uncertainty_ms: n.clock_uncertainty_ms,
            },
            platform: self.platform.clone(),
        })
    }

    /// Apply `IOHR_AGENT_META_<SECTION>_<FIELD>` variables over this table: a list field
    /// splits on commas, `asset.tags` takes `key=value,key=value`, numbers and booleans
    /// are parsed, anything else is a string. The result is checked exactly like a value
    /// written in the file.
    ///
    /// # Errors
    /// An unknown section or field, or a value of the wrong kind, each named with the
    /// variable that set it.
    pub fn apply_env<I, K, V>(&mut self, vars: I) -> Result<usize, Vec<Problem>>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut value = serde_json::to_value(&*self).map_err(|e| {
            vec![Problem {
                path: "metadata".into(),
                message: e.to_string(),
            }]
        })?;
        let mut problems = Vec::new();
        let mut applied = 0;
        for (k, v) in vars {
            let (k, v) = (k.as_ref(), v.as_ref());
            let Some(rest) = k.strip_prefix(ENV_PREFIX) else {
                continue;
            };
            let (section, field, parsed) = match override_value(rest, v) {
                Ok(o) => o,
                Err(message) => {
                    problems.push(Problem {
                        path: k.to_owned(),
                        message,
                    });
                    continue;
                }
            };
            // Each override is checked on its own, so a problem names its variable.
            let mut next = value.clone();
            match section {
                Some(section) => next[section][field] = parsed,
                None => next["report"] = parsed,
            }
            match serde_json::from_value::<Self>(next.clone()) {
                Ok(_) => {
                    value = next;
                    applied += 1;
                }
                Err(e) => problems.push(Problem {
                    path: k.to_owned(),
                    message: e.to_string(),
                }),
            }
        }
        if !problems.is_empty() {
            return Err(problems);
        }
        *self = serde_json::from_value(value).map_err(|e| {
            vec![Problem {
                path: "metadata".into(),
                message: e.to_string(),
            }]
        })?;
        Ok(applied)
    }
}

/// One override: `(section, field, value)`, or `(None, "", bool)` for `REPORT`.
fn override_value(
    rest: &str,
    v: &str,
) -> Result<(Option<String>, String, serde_json::Value), String> {
    if rest.eq_ignore_ascii_case("REPORT") {
        return match v {
            "true" => Ok((None, String::new(), serde_json::Value::Bool(true))),
            "false" => Ok((None, String::new(), serde_json::Value::Bool(false))),
            other => Err(format!("{other:?} is not true or false")),
        };
    }
    let (section, field) = match rest.split_once('_') {
        Some((s, f)) if !f.is_empty() => (s.to_ascii_lowercase(), f.to_ascii_lowercase()),
        _ => return Err(format!("expected {ENV_PREFIX}<SECTION>_<FIELD>")),
    };
    if !SECTIONS.contains(&section.as_str()) {
        return Err(format!("{section:?} is not a metadata section"));
    }
    let parsed = if field == "tags" {
        let mut map = serde_json::Map::new();
        for pair in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let Some((tk, tv)) = pair.split_once('=') else {
                return Err(format!("{pair:?} is not key=value"));
            };
            map.insert(
                tk.trim().to_owned(),
                serde_json::Value::String(tv.trim().to_owned()),
            );
        }
        serde_json::Value::Object(map)
    } else if LIST_FIELDS.contains(&field.as_str()) {
        serde_json::Value::Array(
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| serde_json::Value::String(s.to_owned()))
                .collect(),
        )
    } else if field == "clock_uncertainty_ms" {
        let n: u32 = v
            .trim()
            .parse()
            .map_err(|_| format!("{v:?} is not a number of milliseconds"))?;
        serde_json::Value::from(n)
    } else {
        serde_json::Value::String(v.to_owned())
    };
    Ok((Some(section), field, parsed))
}

/// Where a problem's field sits in the file, by line and column (1-based), for messages.
/// Looks for the field's table header and then its key; `None` when it is not in the text
/// (set by an environment override, say).
#[must_use]
pub fn locate(text: &str, path: &str) -> Option<(usize, usize)> {
    let mut parts = path.split('.');
    if parts.next() != Some("metadata") {
        return None;
    }
    let section = parts.next()?;
    let field = parts.next();
    let header = format!("[metadata.{section}]");
    let mut in_section = false;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let column = line.len() - trimmed.len() + 1;
        if trimmed.starts_with('[') {
            if in_section && !trimmed.starts_with(&header[..header.len() - 1]) {
                return None;
            }
            in_section = trimmed == header || trimmed.starts_with(&format!("[metadata.{section}."));
            if trimmed == header && field.is_none() {
                return Some((i + 1, column));
            }
            continue;
        }
        if in_section
            && let Some(field) = field
            && let Some(rest) = trimmed.strip_prefix(field)
            && rest.trim_start().starts_with('=')
        {
            return Some((i + 1, column));
        }
    }
    None
}

fn count_leaves(value: &serde_json::Value, n: &mut usize) {
    match value {
        serde_json::Value::Object(map) => {
            for v in map.values() {
                count_leaves(v, n);
            }
        }
        serde_json::Value::Null => {}
        _ => *n += 1,
    }
}

fn walk(value: &serde_json::Value, path: &str, out: &mut Vec<Problem>) {
    match value {
        serde_json::Value::String(s) => {
            if s.chars().count() > MAX_STR {
                out.push(Problem {
                    path: path.to_owned(),
                    message: format!("longer than {MAX_STR} characters"),
                });
            }
            if s.chars().any(char::is_control) {
                out.push(Problem {
                    path: path.to_owned(),
                    message: "contains a control character".into(),
                });
            }
            if looks_like_secret(s) {
                out.push(Problem {
                    path: path.to_owned(),
                    message:
                        "looks like a key or a token; metadata holds references, never secrets"
                            .into(),
                });
            }
        }
        serde_json::Value::Array(items) => {
            if items.len() > MAX_LIST {
                out.push(Problem {
                    path: path.to_owned(),
                    message: format!("more than {MAX_LIST} entries"),
                });
            }
            for item in items {
                walk(item, path, out);
            }
        }
        serde_json::Value::Object(map) => {
            let is_tags = path.rsplit('.').next() == Some("tags");
            if is_tags && map.len() > MAX_TAGS {
                out.push(Problem {
                    path: path.to_owned(),
                    message: format!("more than {MAX_TAGS} tags"),
                });
            }
            for (k, v) in map {
                if is_tags {
                    walk(&serde_json::Value::String(k.clone()), path, out);
                    walk(v, path, out);
                } else {
                    walk(v, &format!("{path}.{k}"), out);
                }
            }
        }
        _ => {}
    }
}

/// The reported subset of the metadata, as the hello carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Reported {
    /// Placement without rack and row.
    pub placement: ReportedPlacement,
    /// All of it.
    pub organisation: Organisation,
    /// All of it.
    pub environment: EnvironmentMeta,
    /// All of it.
    pub asset: Asset,
    /// Without the audit destination.
    pub compliance: ReportedCompliance,
    /// Trust domain, attestation and isolation only.
    pub security: ReportedSecurity,
    /// Zone, egress and clock only.
    pub network: ReportedNetwork,
    /// All of it.
    pub platform: PlatformMeta,
}

/// Placement as reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ReportedPlacement {
    /// See [`Placement::provider`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderKind>,
    /// See [`Placement::provider_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// See [`Placement::site_id`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    /// See [`Placement::site_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
    /// See [`Placement::region`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// See [`Placement::zone`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// See [`Placement::country`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<CountryCode>,
    /// See [`Placement::jurisdiction`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    /// See [`Placement::residency_zone`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub residency_zone: Option<String>,
    /// See [`Placement::latency_zone`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_zone: Option<String>,
}

/// Compliance as reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ReportedCompliance {
    /// See [`Compliance::regimes`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub regimes: Vec<Regime>,
    /// See [`Compliance::data_classes_allowed`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub data_classes_allowed: Vec<DataClass>,
    /// See [`Compliance::may_leave_jurisdiction`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub may_leave_jurisdiction: Vec<DataClass>,
    /// See [`Compliance::external_models_may_see`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_models_may_see: Vec<DataClass>,
    /// See [`Compliance::retention_policy`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<String>,
}

/// Security as reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ReportedSecurity {
    /// See [`Security::trust_domain`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// See [`Security::attestation`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    /// See [`Security::isolation`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<Isolation>,
}

/// Network as reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ReportedNetwork {
    /// See [`Network::zone`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// See [`Network::egress`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    /// See [`Network::clock_source`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_source: Option<ClockSource>,
    /// See [`Network::clock_uncertainty_ms`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_uncertainty_ms: Option<u32>,
}

/// The `[metadata]` block `iohr-agent init` writes, every field commented out.
pub const TEMPLATE: &str = r##"
# Where this agent runs, who owns it, what binds it and what it can be trusted for
# (RFC 0088). Every field is optional; an unset field is unknown, never a default.
# `iohr-agent config validate` checks it; `iohr-agent config schema` prints the schema.
# Rack, row, dns, ntp, certificate_authority, secrets_backend, audit_destination and
# [metadata.operations] never leave this machine; `report = false` sends nothing at all.
# Any field can be set from the environment as IOHR_AGENT_META_<SECTION>_<FIELD>.
[metadata]
# report = true

[metadata.placement]
# provider = "colocation"        # cloud, on_prem, colocation, edge
# provider_name = "Equinix"
# site_id = "FRA-DC2"
# site_name = "Frankfurt 2"
# region = "eu-central"
# zone = "fra-dc2-hall-b"
# rack = "B12"
# row = "4"
# country = "DE"                 # ISO 3166-1 alpha-2
# jurisdiction = "EU"
# residency_zone = "eu"          # needs country
# latency_zone = "eu-west"

[metadata.organisation]
# legal_entity = "Example Payments GmbH"
# business_unit = "Payments"
# department = "Platform engineering"
# team = "payments-sre"
# cost_centre = "CC-4411"
# project = "checkout"
# owner_role = "service owner"   # a role, never a name
# contact_channel = "#payments-oncall"
# on_call_rota = "pagerduty:P7Q2"
# escalation_policy = "pagerduty:EP9"

[metadata.environment]
# tier = "production"            # production, staging, development, test, disaster_recovery
# criticality = "critical"       # critical, high, medium, low
# change_freeze = ["2026-12-20/2027-01-05"]
# maintenance_windows = ["Sun 02:00-04:00 Europe/Berlin"]
# sla_ref = "SLA-GOLD"
# slo_refs = ["slo:checkout-p95"]

[metadata.asset]
# cmdb_id = "CI0012345"
# catalogue_refs = ["backstage:component:checkout"]
# hardware_class = "bare_metal"  # bare_metal, virtual_machine, container, serverless
# commissioned = "2024-03-01"
# decommission_planned = "2027-03-01"
# [metadata.asset.tags]
# owner-team = "payments-sre"

[metadata.compliance]
# regimes = ["gdpr", "dora"]     # gdpr, hipaa, dora, soc2, iso27001, pci_dss, nis2, ccpa, other:<name>
# data_classes_allowed = ["public", "internal", "confidential"]
# may_leave_jurisdiction = ["public", "internal"]
# external_models_may_see = ["public"]
# retention_policy = "RET-7Y"
# audit_destination = "siem:splunk-eu"

[metadata.security]
# trust_domain = "example/fra-dc2/payments"
# attestation = "measured_boot"  # none, tpm, measured_boot, confidential_vm
# isolation = "dedicated"        # shared, dedicated, air_gapped
# certificate_authority = "example-internal-ca"
# secrets_backend = "vault:kv/prod"

[metadata.network]
# zone = "internal"
# egress = "proxy"               # direct, proxy, none
# dns = "internal"
# ntp = "ntp.example.internal"
# clock_source = "ntp"           # ntp, ptp, rtc, unknown
# clock_uncertainty_ms = 50

[metadata.operations]
# profile = "standard"           # minimal, standard, deep, incident, forensic
# runbook = "https://runbooks.example.internal/payments"

[metadata.platform]
# group = "eu-payments"
"##;

/// [`TEMPLATE`] with every field uncommented (the explanations stay comments): a full,
/// valid table, for tests.
#[cfg(test)]
#[must_use]
pub fn full_template() -> String {
    TEMPLATE
        .lines()
        .map(uncomment)
        .collect::<Vec<_>>()
        .join("\n")
}

/// A template line with its field or table header uncommented; prose stays as it is.
#[cfg(test)]
fn uncomment(line: &str) -> &str {
    let Some(rest) = line.strip_prefix("# ") else {
        return line;
    };
    let head = rest.trim_end();
    let header = head.starts_with('[') && head.ends_with(']');
    let key = rest.split_once(" = ").is_some_and(|(k, _)| {
        !k.is_empty()
            && k.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
    });
    if header || key { rest } else { line }
}

/// ISO 3166-1 alpha-2, sorted for binary search.
const ISO_3166_1_ALPHA_2: [&str; 249] = [
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Doc {
        metadata: MetadataConfig,
    }

    #[test]
    fn uncommenting_leaves_prose_alone() {
        let text = full_template();
        assert!(text.contains("\n[metadata.placement]\nprovider = \"colocation\""));
        assert!(text.contains("\n# [metadata.operations] never leave this machine"));
        assert!(text.contains("\n# (RFC 0088)."));
    }

    fn full() -> MetadataConfig {
        toml::from_str::<Doc>(&full_template())
            .expect("the template, uncommented, is a full valid table")
            .metadata
    }

    #[test]
    fn the_iso_list_is_sorted_and_complete_enough() {
        assert!(ISO_3166_1_ALPHA_2.windows(2).all(|w| w[0] < w[1]));
        for c in ["HR", "DE", "US", "ZW", "AD"] {
            assert!(CountryCode::try_from(c.to_owned()).is_ok(), "{c}");
        }
        for bad in ["de", "XX", "DEU", ""] {
            assert!(CountryCode::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_template_uncommented_is_valid_and_round_trips() {
        let m = full();
        assert_eq!(m.problems(), Vec::new());
        assert!(!m.is_empty());
        assert_eq!(m.set_fields(), 54);
        assert_eq!(
            m.placement.country.as_ref().map(CountryCode::as_str),
            Some("DE")
        );
        assert_eq!(m.compliance.regimes, vec![Regime::Gdpr, Regime::Dora]);
        let json = serde_json::to_string(&m).unwrap();
        let back: MetadataConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        let toml_text = toml::to_string(&m).unwrap();
        let back: MetadataConfig = toml::from_str(&toml_text).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn the_default_is_empty_and_reports_nothing() {
        let m = MetadataConfig::default();
        assert!(m.report);
        assert!(m.is_empty());
        assert!(m.is_default());
        assert_eq!(m.set_fields(), 0);
        assert!(m.reported().is_none());
        assert_eq!(m.problems(), Vec::new());
    }

    #[test]
    fn reporting_can_be_switched_off() {
        let mut m = full();
        assert!(m.reported().is_some());
        m.report = false;
        assert!(m.reported().is_none());
    }

    #[test]
    fn the_reported_subset_never_carries_what_stays_on_the_machine() {
        let r = full().reported().unwrap();
        let json = serde_json::to_value(&r).unwrap();
        let text = json.to_string();
        for local in [
            "rack",
            "row",
            "dns",
            "ntp",
            "certificate_authority",
            "secrets_backend",
            "audit_destination",
            "operations",
            "runbook",
            "profile",
        ] {
            let key = format!("\"{local}\":");
            assert!(!text.contains(&key), "{local} must not be reported: {text}");
        }
        assert_eq!(json["placement"]["country"], "DE");
        assert_eq!(json["security"]["trust_domain"], "example/fra-dc2/payments");
        assert_eq!(
            json["compliance"]["external_models_may_see"],
            serde_json::json!(["public"])
        );
        assert_eq!(json["network"]["clock_uncertainty_ms"], 50);
    }

    #[test]
    fn class_rules_are_enforced() {
        let mut m = MetadataConfig::default();
        m.compliance.data_classes_allowed = vec![DataClass::Public];
        m.compliance.may_leave_jurisdiction = vec![DataClass::Internal];
        m.compliance.external_models_may_see = vec![DataClass::Restricted];
        let paths: Vec<_> = m.problems().into_iter().map(|p| p.path).collect();
        assert!(paths.contains(&"metadata.compliance.may_leave_jurisdiction".to_owned()));
        assert_eq!(
            paths
                .iter()
                .filter(|p| p.ends_with("external_models_may_see"))
                .count(),
            2
        );
    }

    #[test]
    fn residency_needs_a_country_and_dates_are_ordered() {
        let mut m = MetadataConfig::default();
        m.placement.residency_zone = Some("eu".into());
        m.asset.commissioned = Some(IsoDate::try_from("2027-01-01".to_owned()).unwrap());
        m.asset.decommission_planned = Some(IsoDate::try_from("2026-01-01".to_owned()).unwrap());
        m.network.clock_uncertainty_ms = Some(600_000);
        let paths: Vec<_> = m.problems().into_iter().map(|p| p.path).collect();
        assert_eq!(
            paths,
            vec![
                "metadata.placement.residency_zone",
                "metadata.asset.decommission_planned",
                "metadata.network.clock_uncertainty_ms"
            ]
        );
    }

    #[test]
    fn long_strings_control_characters_and_secrets_are_refused() {
        let mut m = MetadataConfig::default();
        m.organisation.team = Some("x".repeat(129));
        m.organisation.project = Some("a\u{7}b".into());
        m.security.secrets_backend = Some("hvs.CAESIJ8aQ2x5Z3Zr".into());
        m.asset.tags.insert(
            "key".into(),
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789".into(),
        );
        let mut paths: Vec<_> = m.problems().into_iter().map(|p| p.path).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "metadata.asset.tags",
                "metadata.organisation.project",
                "metadata.organisation.team",
                "metadata.security.secrets_backend"
            ]
        );
    }

    #[test]
    fn unknown_fields_and_bad_values_are_errors() {
        let bad = [
            ("[metadata.placement]\ncountry = \"de\"", "ISO 3166"),
            ("[metadata.placement]\ncontinent = \"EU\"", "unknown field"),
            ("[metadata.environment]\ntier = \"prod\"", "unknown variant"),
            (
                "[metadata.environment]\nchange_freeze = [\"2027-01-05/2026-12-20\"]",
                "ends before",
            ),
            (
                "[metadata.compliance]\nregimes = [\"other:With Space\"]",
                "other:",
            ),
            (
                "[metadata.asset]\ncommissioned = \"2024-13-01\"",
                "not a date",
            ),
            (
                "[metadata.network]\nclock_uncertainty_ms = -1",
                "invalid value",
            ),
        ];
        for (text, needle) in bad {
            let err = toml::from_str::<Doc>(text).unwrap_err().to_string();
            assert!(err.contains(needle), "{text}: {err}");
            assert!(err.contains("line 2"), "{text}: {err}");
        }
    }

    #[test]
    fn environment_overrides_apply_and_are_checked_like_the_file() {
        let mut m = MetadataConfig::default();
        let n = m
            .apply_env([
                ("IOHR_AGENT_META_PLACEMENT_COUNTRY", "HR"),
                ("IOHR_AGENT_META_PLACEMENT_ZONE", "eu-central-1a"),
                ("IOHR_AGENT_META_COMPLIANCE_REGIMES", "gdpr, nis2"),
                ("IOHR_AGENT_META_ASSET_TAGS", "owner-team=sre, tier=gold"),
                ("IOHR_AGENT_META_NETWORK_CLOCK_UNCERTAINTY_MS", "25"),
                ("IOHR_AGENT_META_REPORT", "false"),
                ("UNRELATED", "x"),
            ])
            .unwrap();
        assert_eq!(n, 6);
        assert_eq!(
            m.placement.country.as_ref().map(CountryCode::as_str),
            Some("HR")
        );
        assert_eq!(m.placement.zone.as_deref(), Some("eu-central-1a"));
        assert_eq!(m.compliance.regimes, vec![Regime::Gdpr, Regime::Nis2]);
        assert_eq!(m.asset.tags.get("tier").map(String::as_str), Some("gold"));
        assert_eq!(m.network.clock_uncertainty_ms, Some(25));
        assert!(!m.report);

        let mut m = MetadataConfig::default();
        let err = m
            .apply_env([("IOHR_AGENT_META_PLACEMENT_COUNTRY", "Germany")])
            .unwrap_err();
        assert!(err[0].message.contains("ISO 3166"), "{err:?}");
        let err = m
            .apply_env([("IOHR_AGENT_META_GEOGRAPHY_COUNTRY", "DE")])
            .unwrap_err();
        assert_eq!(err[0].path, "IOHR_AGENT_META_GEOGRAPHY_COUNTRY");
        let err = m
            .apply_env([("IOHR_AGENT_META_PLACEMENT_CONTINENT", "EU")])
            .unwrap_err();
        assert!(err[0].message.contains("unknown field"), "{err:?}");
        let err = m
            .apply_env([("IOHR_AGENT_META_REPORT", "yes")])
            .unwrap_err();
        assert!(err[0].message.contains("true or false"), "{err:?}");
    }

    #[test]
    fn locate_finds_a_field_in_its_section_only() {
        let text = "api = \"x\"\n\n[metadata.placement]\n  country = \"DE\"\n\n[metadata.asset]\ncmdb_id = \"c\"\n[metadata.asset.tags]\na = \"b\"\n[metadata.network]\nzone = \"dmz\"\n";
        assert_eq!(locate(text, "metadata.placement.country"), Some((4, 3)));
        assert_eq!(locate(text, "metadata.network.zone"), Some((11, 1)));
        assert_eq!(locate(text, "metadata.network"), Some((10, 1)));
        assert_eq!(locate(text, "metadata.asset.cmdb_id"), Some((7, 1)));
        assert_eq!(locate(text, "metadata.placement.zone"), None);
        assert_eq!(locate(text, "api"), None);
    }

    #[test]
    fn a_json_schema_is_generated_for_the_table() {
        let schema = schemars::schema_for!(MetadataConfig);
        let text = serde_json::to_string(&schema).unwrap();
        for key in [
            "placement",
            "country",
            "^[A-Z]{2}$",
            "trust_domain",
            "external_models_may_see",
            "disaster_recovery",
            REGIME_PATTERN,
        ] {
            assert!(text.contains(key), "{key}");
        }
    }
}
