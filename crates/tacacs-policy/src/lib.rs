// SPDX-License-Identifier: Apache-2.0
//! TACACS+ authorization policy engine.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../docs/NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-3 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-6 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | SI-10 | System and Information Integrity | Implemented | 2026-01-31 | See functions below |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-31",
//!   "control_families": [
//!     "AC",
//!     "SI"
//!   ],
//!   "total_controls": 3,
//!   "file_path": "crates/tacacs-policy/src/lib.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-3 (Access Enforcement)**: Enforces authorization rules based on user,
//!   group membership, and command patterns.
//!
//! - **AC-6 (Least Privilege)**: Supports fine-grained command authorization to
//!   restrict users to minimum required privileges.
//!
//! - **SI-10 (Information Input Validation)**: Validates policy regex patterns
//!   with size limits to prevent ReDoS attacks (CWE-1333).

use anyhow::{Context, Result, anyhow};
use jsonschema::Draft;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum compiled regex size in bytes to prevent ReDoS attacks (CWE-1333).
///
/// # NIST Controls
/// - **SI-10**: Limits regex complexity to prevent denial-of-service via
///   exponentially complex patterns.
///
/// The default limit of 1MB is generous for authorization patterns while
/// preventing pathological cases like `(a+)+$` from consuming excessive CPU.
const MAX_REGEX_SIZE: usize = 1024 * 1024; // 1MB

/// Maximum regex nesting depth to prevent stack overflow.
const MAX_REGEX_NEST_LEVEL: u32 = 100;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// Schedule configuration for a policy rule.
///
/// A rule with a schedule only fires when the current UTC time falls within
/// the specified day(s) and/or hour range.  Both fields are optional;
/// omitting one means "all values match" for that dimension.
///
/// # Examples
///
/// ```json
/// { "days": ["sat", "sun"] }                     // weekends only
/// { "days": ["mon","tue","wed","thu","fri"],
///   "hours": "08:00-18:00" }                      // business hours
/// { "hours": "22:00-06:00" }                      // overnight window
/// ```
///
/// Accepted day names (case-insensitive): `mon tue wed thu fri sat sun
/// weekdays weekends`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Subset of days the rule is active.  Empty list = all days.
    #[serde(default)]
    pub days: Vec<String>,
    /// UTC time range `"HH:MM-HH:MM"`.  `None` = all hours.
    /// Ranges wrapping midnight (e.g. `"22:00-06:00"`) are supported.
    pub hours: Option<String>,
}

/// Compiled schedule extracted from `ScheduleConfig` for fast evaluation.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Time-window enforcement on authz rules |
#[derive(Debug, Clone)]
pub struct CompiledSchedule {
    /// Bitmask of active weekdays: bit 0 = Sunday … bit 6 = Saturday.
    /// All bits set (0x7F) means "every day".
    day_mask: u8,
    /// Start of active hour range in minutes since midnight (UTC).
    hour_start_min: u16,
    /// End of active hour range in minutes since midnight (UTC).
    hour_end_min: u16,
    /// True when the range wraps midnight (start > end).
    wraps_midnight: bool,
}

impl CompiledSchedule {
    /// Return true if the current UTC wall-clock time falls within this schedule.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Enforces time-window restriction on rule |
    pub fn active_now(&self) -> bool {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(secs > 0, "system clock must be set");
        let day_of_week = ((secs / 86400 + 4) % 7) as u8; // 0=Sun … 6=Sat
        if self.day_mask != 0x7F && (self.day_mask >> day_of_week) & 1 == 0 {
            return false;
        }
        let minutes = ((secs % 86400) / 60) as u16;
        if self.wraps_midnight {
            minutes >= self.hour_start_min || minutes < self.hour_end_min
        } else {
            minutes >= self.hour_start_min && minutes < self.hour_end_min
        }
    }
}

/// Parse a day-name string to a weekday index (0=Sun … 6=Sat).
///
/// Returns `None` for unrecognised strings.
fn parse_day_name(s: &str) -> Option<u8> {
    assert!(!s.is_empty(), "day name must not be empty");
    match s.to_lowercase().as_str() {
        "sun" | "sunday" => Some(0),
        "mon" | "monday" => Some(1),
        "tue" | "tuesday" => Some(2),
        "wed" | "wednesday" => Some(3),
        "thu" | "thursday" => Some(4),
        "fri" | "friday" => Some(5),
        "sat" | "saturday" => Some(6),
        _ => None,
    }
}

/// Parse `"HH:MM"` into minutes since midnight.  Returns `None` on error.
fn parse_hhmm(s: &str) -> Option<u16> {
    assert!(!s.is_empty(), "time string must not be empty");
    let (h, m) = s.split_once(':')?;
    let h: u16 = h.parse().ok()?;
    let m: u16 = m.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// Compile a `ScheduleConfig` into a `CompiledSchedule`.
///
/// Returns an error string describing the first invalid field.
fn compile_schedule(cfg: &ScheduleConfig) -> Result<CompiledSchedule, String> {
    assert!(
        cfg.days.len() <= 7,
        "schedule cannot have more than 7 day entries"
    );
    let mut day_mask: u8 = 0x7F; // all days
    if !cfg.days.is_empty() {
        day_mask = 0;
        for name in &cfg.days {
            match name.to_lowercase().as_str() {
                "weekdays" => day_mask |= 0b0111_1110, // Mon-Fri
                "weekends" => day_mask |= 0b0100_0001, // Sat, Sun
                other => {
                    let idx = parse_day_name(other)
                        .ok_or_else(|| format!("unknown day name: {other:?}"))?;
                    day_mask |= 1 << idx;
                }
            }
        }
    }
    let (hour_start_min, hour_end_min, wraps_midnight) = if let Some(ref h) = cfg.hours {
        let (start_s, end_s) = h
            .split_once('-')
            .ok_or_else(|| format!("hours must be HH:MM-HH:MM, got: {h:?}"))?;
        let start =
            parse_hhmm(start_s.trim()).ok_or_else(|| format!("invalid start time: {start_s:?}"))?;
        let end = parse_hhmm(end_s.trim()).ok_or_else(|| format!("invalid end time: {end_s:?}"))?;
        (start, end, start > end)
    } else {
        (0, 1440, false) // 00:00–24:00 = all hours
    };
    Ok(CompiledSchedule {
        day_mask,
        hour_start_min,
        hour_end_min,
        wraps_midnight,
    })
}

// ---------------------------------------------------------------------------
// NAD group types and CIDR helpers
// ---------------------------------------------------------------------------

/// Configuration for one NAD group — defines which devices belong to it.
///
/// Devices are matched by their TCP source IP against the listed CIDR ranges.
///
/// # Example
///
/// ```json
/// "nad_groups": {
///   "core":   { "cidrs": ["10.0.0.0/8"] },
///   "access": { "cidrs": ["192.168.0.0/16", "172.16.0.0/12"] }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NadGroupConfig {
    /// CIDR ranges whose source IPs belong to this group.
    #[serde(default)]
    pub cidrs: Vec<String>,
}

/// A compiled CIDR entry: network address + prefix length.
#[derive(Debug, Clone)]
struct ParsedCidr {
    addr: IpAddr,
    prefix: u8,
}

impl ParsedCidr {
    /// Return true when `ip` falls within this CIDR range.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Routes NADs to policy group by source IP |
    fn contains(&self, ip: IpAddr) -> bool {
        assert!(self.prefix <= 128, "prefix must be at most 128");
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                if self.prefix == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(u32::from(self.prefix));
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(host) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                if self.prefix == 0 {
                    return true;
                }
                let shift = 128u32.saturating_sub(u32::from(self.prefix));
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(host) & mask)
            }
            _ => false, // IPv4/IPv6 family mismatch
        }
    }
}

/// Parse a CIDR string (e.g. `"10.0.0.0/8"`) into a `ParsedCidr`.
///
/// Returns an error string for invalid input.
fn parse_cidr(s: &str) -> Result<ParsedCidr, String> {
    assert!(!s.is_empty(), "CIDR string must not be empty");
    let (addr_s, prefix_s) = s
        .split_once('/')
        .ok_or_else(|| format!("CIDR missing '/': {s:?}"))?;
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|e| format!("invalid CIDR address {addr_s:?}: {e}"))?;
    let prefix: u8 = prefix_s
        .parse()
        .map_err(|e| format!("invalid prefix length {prefix_s:?}: {e}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("prefix {prefix} exceeds max {max} for {addr}"));
    }
    Ok(ParsedCidr { addr, prefix })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub priority: i32,
    pub effect: Effect,
    pub pattern: String,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    /// NAD group names this rule applies to.  Empty = all NADs.
    #[serde(default)]
    pub nad_groups: Vec<String>,
    /// Optional time-based restriction; `None` = always active.
    pub schedule: Option<ScheduleConfig>,
}

/// Vendor-service authorization attribute mapping (e.g. `service=PaloAlto`).
///
/// A non-shell NAS such as a Palo Alto firewall sends an authorization request
/// carrying `service=<vendor>` (and an optional vendor `protocol`) with no
/// `cmd`. It expects the server to return vendor AV-pairs (e.g.
/// `PaloAlto-Admin-Role=superuser`, `PaloAlto-Admin-Access-Domain=<name>`).
///
/// Resolution order mirrors `shell_start`/`shell_start_groups`: an exact
/// username match wins; otherwise the first matching IdP/LDAP group (in the
/// caller's group order) wins; otherwise `default` (if present) is returned.
///
/// # Example
///
/// ```json
/// "author_service_attributes": {
///   "paloalto": {
///     "groups": { "netops": ["PaloAlto-Admin-Role=superuser"] }
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorServiceConfig {
    /// Per-username AV-pair lists (case-insensitive key). Highest priority.
    #[serde(default)]
    pub users: HashMap<String, Vec<String>>,
    /// Per-group AV-pair lists (case-insensitive key). First match wins.
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
    /// Fallback AV-pairs when no user or group matches. `None` = deny.
    #[serde(default)]
    pub default: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub default_allow: bool,
    #[serde(default)]
    pub shell_start: HashMap<String, Vec<String>>,
    /// Shell start attributes keyed by group name (lowercased). Checked when
    /// the user has no entry in `shell_start`; first matching group wins.
    #[serde(default)]
    pub shell_start_groups: HashMap<String, Vec<String>>,
    /// Vendor-service authorization attributes keyed by service name
    /// (lowercased), e.g. `paloalto`. Drives non-shell attribute requests.
    #[serde(default)]
    pub author_service_attributes: HashMap<String, AuthorServiceConfig>,
    /// Usernames (or glob patterns with `*`) that bypass device flow and use
    /// password auth (ROPC/static). Case-insensitive. Use for service accounts
    /// that cannot complete browser authentication.
    #[serde(default)]
    pub device_flow_exclude_users: Vec<String>,
    /// NAD group definitions: maps a group name to its membership criteria.
    /// Groups are referenced from rule `nad_groups` fields.
    #[serde(default)]
    pub nad_groups: HashMap<String, NadGroupConfig>,
    /// Privilege-escalation gating: maps a requested privilege level (as a
    /// string, e.g. "15") to the ICAM/LDAP groups permitted to `enable` to it.
    /// When empty, enable is allowed for any authenticated user (legacy behavior).
    /// When non-empty but a level has no entry, enable to that level is denied.
    #[serde(default)]
    pub enable_groups: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub ascii_prompts: Option<AsciiPrompts>,
    #[serde(default)]
    pub ascii_user_prompts: HashMap<String, String>,
    #[serde(default)]
    pub ascii_password_prompts: HashMap<String, String>,
    #[serde(default)]
    pub ascii_port_prompts: HashMap<String, String>,
    #[serde(default)]
    pub ascii_remaddr_prompts: HashMap<String, String>,
    #[serde(default = "default_allow_raw_server_msg")]
    pub allow_raw_server_msg: bool,
    #[serde(default)]
    pub raw_server_msg_allow_prefixes: Vec<String>,
    #[serde(default)]
    pub raw_server_msg_deny_prefixes: Vec<String>,
    #[serde(default)]
    pub raw_server_msg_user_overrides: HashMap<String, RawServerMsgOverride>,
    #[serde(default)]
    pub ascii_messages: Option<AsciiMessages>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsciiPrompts {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsciiMessages {
    pub success: Option<String>,
    pub failure: Option<String>,
    pub abort: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawServerMsgOverride {
    pub allow: Option<bool>,
    #[serde(default)]
    pub allow_prefixes: Vec<String>,
    #[serde(default)]
    pub deny_prefixes: Vec<String>,
    #[serde(default)]
    pub allow_services: Vec<u8>,
    #[serde(default)]
    pub allow_actions: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub priority: i32,
    pub effect: Effect,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    /// NAD group names this rule applies to (lowercased). Empty = all NADs.
    pub nad_groups: Vec<String>,
    pub regex: Regex,
    pub order: usize,
    /// Pre-compiled schedule; `None` = rule is always active.
    pub schedule: Option<CompiledSchedule>,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    default_allow: bool,
    shell_start: HashMap<String, Vec<String>>,
    shell_start_groups: HashMap<String, Vec<String>>,
    /// Compiled vendor-service attribute map: service name (lowercased) →
    /// per-user/per-group/default AV-pair lists with lowercased lookup keys.
    author_service_attributes: HashMap<String, AuthorServiceConfig>,
    device_flow_exclude_users: Vec<String>,
    /// Compiled NAD groups: name → list of CIDR ranges.
    nad_groups: HashMap<String, Vec<ParsedCidr>>,
    /// Compiled enable gating: priv-lvl → groups permitted to escalate to it.
    enable_groups: HashMap<u8, Vec<String>>,
    ascii_prompts: Option<AsciiPrompts>,
    ascii_user_prompts: HashMap<String, String>,
    ascii_password_prompts: HashMap<String, String>,
    ascii_port_prompts: HashMap<String, String>,
    ascii_remaddr_prompts: HashMap<String, String>,
    allow_raw_server_msg: bool,
    raw_server_msg_allow_prefixes: Vec<String>,
    raw_server_msg_deny_prefixes: Vec<String>,
    raw_server_msg_user_overrides: HashMap<String, RawServerMsgOverride>,
    ascii_messages: Option<AsciiMessages>,
    rules: Vec<Rule>,
}

/// Case-insensitive glob match supporting a single `*` wildcard.
///
/// Both `pattern` and `text` are expected to be already lowercased by the caller.
fn glob_match(pattern: &str, text: &str) -> bool {
    assert!(!pattern.is_empty(), "glob pattern must not be empty");
    match pattern.find('*') {
        None => pattern == text,
        Some(star) => {
            let prefix = &pattern[..star];
            let suffix = &pattern[star + 1..];
            assert!(
                !suffix.contains('*'),
                "only one wildcard per pattern is supported"
            );
            text.starts_with(prefix)
                && text.ends_with(suffix)
                && text.len() >= prefix.len() + suffix.len()
        }
    }
}

/// Compile a list of `RuleConfig` entries into indexed `Rule` values.
/// Update the winning rule based on priority then declaration order.
fn update_selected<'a>(selected: &mut Option<&'a Rule>, rule: &'a Rule) {
    match selected {
        None => *selected = Some(rule),
        Some(cur) if rule.priority > cur.priority => *selected = Some(rule),
        Some(cur) if rule.priority == cur.priority && rule.order > cur.order => {
            *selected = Some(rule);
        }
        _ => {}
    }
}

fn compile_rules(configs: Vec<RuleConfig>) -> Result<Vec<Rule>> {
    let mut rules = Vec::with_capacity(configs.len());
    for (order, rule) in configs.into_iter().enumerate() {
        let regex = compile_pattern(&rule.pattern)
            .with_context(|| format!("compiling rule {} pattern {}", rule.id, rule.pattern))?;
        let schedule = rule
            .schedule
            .as_ref()
            .map(|s| {
                compile_schedule(s)
                    .map_err(|e| anyhow::anyhow!("rule {}: invalid schedule: {}", rule.id, e))
            })
            .transpose()?;
        rules.push(Rule {
            id: rule.id,
            priority: rule.priority,
            effect: rule.effect,
            users: rule.users.into_iter().map(|u| u.to_lowercase()).collect(),
            groups: rule.groups.into_iter().map(|g| g.to_lowercase()).collect(),
            nad_groups: rule
                .nad_groups
                .into_iter()
                .map(|g| g.to_lowercase())
                .collect(),
            regex,
            order,
            schedule,
        });
    }
    Ok(rules)
}

/// Compile the enable-gating map: parse string priv-lvl keys into u8 and
/// lowercase the group names for case-insensitive matching.
fn compile_enable_groups(groups: HashMap<String, Vec<String>>) -> Result<HashMap<u8, Vec<String>>> {
    let mut map = HashMap::new();
    for (lvl_s, allowed) in groups {
        let lvl: u8 = lvl_s.parse().map_err(|e| {
            anyhow::anyhow!("enable_groups key {lvl_s:?} is not a valid priv-lvl (0-15): {e}")
        })?;
        if lvl > 15 {
            return Err(anyhow::anyhow!(
                "enable_groups priv-lvl {lvl} exceeds max 15"
            ));
        }
        map.insert(lvl, allowed.into_iter().map(|g| g.to_lowercase()).collect());
    }
    Ok(map)
}

/// Compile the NAD group configuration map into parsed CIDR entries.
fn compile_nad_group_map(
    groups: HashMap<String, NadGroupConfig>,
) -> Result<HashMap<String, Vec<ParsedCidr>>> {
    let mut map = HashMap::new();
    for (name, cfg) in groups {
        let mut cidrs = Vec::new();
        for cidr_s in &cfg.cidrs {
            let parsed =
                parse_cidr(cidr_s).map_err(|e| anyhow::anyhow!("nad_group {name:?}: {e}"))?;
            cidrs.push(parsed);
        }
        map.insert(name.to_lowercase(), cidrs);
    }
    Ok(map)
}

/// Lowercase the service-name keys and the nested user/group lookup keys of a
/// vendor-service attribute map so resolution is case-insensitive. The AV-pair
/// values themselves are preserved verbatim (vendor role names are case-sensitive
/// on the device, e.g. `PaloAlto-Admin-Role=superuser`).
fn compile_author_service_attributes(
    map: HashMap<String, AuthorServiceConfig>,
) -> HashMap<String, AuthorServiceConfig> {
    let mut out = HashMap::with_capacity(map.len());
    for (service, cfg) in map {
        let lowered = AuthorServiceConfig {
            users: cfg
                .users
                .into_iter()
                .map(|(u, v)| (u.to_lowercase(), v))
                .collect(),
            groups: cfg
                .groups
                .into_iter()
                .map(|(g, v)| (g.to_lowercase(), v))
                .collect(),
            default: cfg.default,
        };
        out.insert(service.to_lowercase(), lowered);
    }
    out
}

fn default_allow_raw_server_msg() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub matched_rule: Option<String>,
}

impl PolicyEngine {
    pub fn from_path(policy: impl AsRef<Path>, schema: Option<impl AsRef<Path>>) -> Result<Self> {
        let policy_path = policy.as_ref();
        let policy_contents = fs::read_to_string(policy_path)
            .with_context(|| format!("reading policy {}", policy_path.display()))?;
        let value: Value = serde_json::from_str(&policy_contents)
            .with_context(|| format!("parsing JSON policy {}", policy_path.display()))?;

        if let Some(schema_path) = schema {
            validate_against_schema(&value, schema_path.as_ref())?;
        }

        let document: PolicyDocument = serde_json::from_value(value)
            .with_context(|| format!("deserializing policy {}", policy_path.display()))?;
        Self::from_document(document)
    }

    pub fn from_json_str(policy_json: &str, schema: Option<impl AsRef<Path>>) -> Result<Self> {
        let value: Value =
            serde_json::from_str(policy_json).context("parsing JSON policy from string")?;

        if let Some(schema_path) = schema {
            validate_against_schema(&value, schema_path.as_ref())?;
        }

        let document: PolicyDocument =
            serde_json::from_value(value).context("deserializing policy from JSON string")?;
        Self::from_document(document)
    }

    pub fn from_document(document: PolicyDocument) -> Result<Self> {
        let rules = compile_rules(document.rules)?;
        let nad_groups = compile_nad_group_map(document.nad_groups)?;
        let enable_groups = compile_enable_groups(document.enable_groups)?;
        let author_service_attributes =
            compile_author_service_attributes(document.author_service_attributes);
        Ok(Self {
            default_allow: document.default_allow,
            shell_start: document
                .shell_start
                .into_iter()
                .map(|(u, v)| (u.to_lowercase(), v))
                .collect(),
            shell_start_groups: document
                .shell_start_groups
                .into_iter()
                .map(|(g, v)| (g.to_lowercase(), v))
                .collect(),
            author_service_attributes,
            device_flow_exclude_users: document
                .device_flow_exclude_users
                .into_iter()
                .map(|u| u.to_lowercase())
                .collect(),
            nad_groups,
            enable_groups,
            ascii_prompts: document.ascii_prompts,
            ascii_user_prompts: document
                .ascii_user_prompts
                .into_iter()
                .map(|(u, p)| (u.to_lowercase(), p))
                .collect(),
            ascii_password_prompts: document
                .ascii_password_prompts
                .into_iter()
                .map(|(u, p)| (u.to_lowercase(), p))
                .collect(),
            ascii_port_prompts: document.ascii_port_prompts,
            ascii_remaddr_prompts: document.ascii_remaddr_prompts,
            allow_raw_server_msg: document.allow_raw_server_msg,
            raw_server_msg_allow_prefixes: document
                .raw_server_msg_allow_prefixes
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            raw_server_msg_deny_prefixes: document
                .raw_server_msg_deny_prefixes
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            raw_server_msg_user_overrides: document
                .raw_server_msg_user_overrides
                .into_iter()
                .map(|(u, o)| (u.to_lowercase(), o))
                .collect(),
            ascii_messages: document.ascii_messages,
            rules,
        })
    }

    #[tracing::instrument(skip(self))]
    pub fn authorize(&self, user: &str, command: &str) -> Decision {
        self.authorize_with_nad(user, &[], &[], command)
    }

    pub fn authorize_with_groups(&self, user: &str, groups: &[String], command: &str) -> Decision {
        self.authorize_with_nad(user, groups, &[], command)
    }

    /// Evaluate command authorization with user groups and NAD groups.
    ///
    /// `nad_groups` is the result of `resolve_nad_groups(peer)` and restricts
    /// which rules fire based on which device is making the request.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Rules filtered by NAD group membership |
    #[tracing::instrument(skip(self), fields(rule_count = self.rules.len()))]
    pub fn authorize_with_nad(
        &self,
        user: &str,
        groups: &[String],
        nad_groups: &[String],
        command: &str,
    ) -> Decision {
        let normalized_user = user.to_lowercase();
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();
        let normalized_nad: Vec<String> = nad_groups.iter().map(|g| g.to_lowercase()).collect();
        let normalized_cmd = normalize_command(command);

        let mut selected: Option<&Rule> = None;
        for rule in &self.rules {
            // Skip rules whose time-based schedule is not currently active (AC-3).
            if rule.schedule.as_ref().is_some_and(|s| !s.active_now()) {
                continue;
            }
            if !rule.users.is_empty() && !rule.users.iter().any(|u| u == &normalized_user) {
                continue;
            }
            if !rule.groups.is_empty()
                && !rule
                    .groups
                    .iter()
                    .any(|g| normalized_groups.iter().any(|ug| ug == g))
            {
                continue;
            }
            // Skip if rule targets specific NAD groups and this NAD is not in any of them.
            if !rule.nad_groups.is_empty()
                && !rule
                    .nad_groups
                    .iter()
                    .any(|g| normalized_nad.iter().any(|ng| ng == g))
            {
                continue;
            }
            if rule.regex.is_match(&normalized_cmd) {
                update_selected(&mut selected, rule);
            }
        }

        let allowed = selected
            .map(|r| r.effect == Effect::Allow)
            .unwrap_or(self.default_allow);

        let decision = Decision {
            allowed,
            matched_rule: selected.map(|r| r.id.clone()),
        };

        tracing::debug!(
            allowed = decision.allowed,
            matched_rule = ?decision.matched_rule,
            "authorization decision"
        );

        decision
    }

    /// Return shell-start attributes for a user by username (exact match, case-insensitive).
    pub fn shell_attributes_for(&self, user: &str) -> Option<Vec<String>> {
        self.shell_start.get(&user.to_lowercase()).cloned()
    }

    /// Return shell-start attributes, checking username first then groups.
    ///
    /// User-level entry takes priority; if absent, the first matching group
    /// (in iteration order) wins. Returns `None` if neither matches.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Group-based privilege attribute lookup |
    /// Resolve the NAD group names for a given peer address string.
    ///
    /// `peer` is in the format `"10.0.1.1:49"` or `"[2001:db8::1]:49"`.
    /// The IP is extracted, then checked against every group's CIDR list.
    /// Returns the names of all groups whose CIDRs contain the peer IP.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Maps NAD source IP to policy group |
    pub fn resolve_nad_groups(&self, peer: &str) -> Vec<String> {
        assert!(!peer.is_empty(), "peer address must not be empty");
        let ip_str = peer
            .rsplit_once(':')
            .map(|(host, _port)| host.trim_matches(['[', ']']))
            .unwrap_or(peer);
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            return Vec::new();
        };
        let mut result = Vec::new();
        for (name, cidrs) in &self.nad_groups {
            if cidrs.iter().any(|c| c.contains(ip)) {
                result.push(name.clone());
            }
        }
        result
    }

    /// Return true if a user with `groups` is permitted to `enable` to `priv_lvl`.
    ///
    /// Semantics:
    /// - No `enable_groups` configured at all → allow (legacy: any authed user).
    /// - A group is permitted for `priv_lvl` if it appears in the entry for that
    ///   level, OR in the entry for any higher level (privilege is hierarchical:
    ///   a user cleared for level 15 may also enable to level 7).
    /// - Configured but no matching group at or above `priv_lvl` → deny.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-6 | Least Privilege | Gates privilege escalation by group membership |
    /// | AC-3 | Access Enforcement | Enforces enable authorization at the policy layer |
    pub fn can_enable(&self, priv_lvl: u8, groups: &[String]) -> bool {
        if self.enable_groups.is_empty() {
            return true;
        }
        let user_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();
        for (lvl, allowed) in &self.enable_groups {
            if *lvl >= priv_lvl && allowed.iter().any(|a| user_groups.iter().any(|ug| ug == a)) {
                return true;
            }
        }
        false
    }

    /// Return true if `service` is a configured vendor authorization service
    /// (e.g. `PaloAlto`). Matching is case-insensitive.
    ///
    /// Used by the server to (a) accept the service through RFC validation and
    /// (b) route the request to the vendor-attribute authorization path.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Identifies vendor services eligible for attribute return |
    pub fn is_custom_author_service(&self, service: &str) -> bool {
        assert!(!service.is_empty(), "service must not be empty");
        self.author_service_attributes
            .contains_key(&service.to_lowercase())
    }

    /// Return the configured vendor service names (lowercased). Used to extend
    /// the RFC service allowlist so vendor authorization requests are accepted.
    pub fn custom_author_services(&self) -> Vec<String> {
        let names: Vec<String> = self.author_service_attributes.keys().cloned().collect();
        assert!(
            names.len() == self.author_service_attributes.len(),
            "service name count must match map size"
        );
        names
    }

    /// Resolve the vendor AV-pairs to return for a `service` authorization
    /// request, by `user` then `groups` then the service `default`.
    ///
    /// Returns `None` when the service is unknown or no user/group/default
    /// entry matches — the caller treats that as a denial.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Returns vendor role/scope AV-pairs per identity |
    /// | AC-6 | Least Privilege | Role granted is bounded by IdP group membership |
    pub fn service_attributes_for_with_groups(
        &self,
        service: &str,
        user: &str,
        groups: &[String],
    ) -> Option<Vec<String>> {
        assert!(!service.is_empty(), "service must not be empty");
        assert!(!user.is_empty(), "user must not be empty");
        let cfg = self.author_service_attributes.get(&service.to_lowercase())?;
        if let Some(attrs) = cfg.users.get(&user.to_lowercase()) {
            return Some(attrs.clone());
        }
        for group in groups {
            if let Some(attrs) = cfg.groups.get(&group.to_lowercase()) {
                return Some(attrs.clone());
            }
        }
        cfg.default.clone()
    }

    /// Return true if the username matches an entry in `device_flow_exclude_users`.
    ///
    /// Matching is case-insensitive. Entries may contain a single `*` wildcard
    /// that matches any sequence of characters (glob-style: `svc-*`, `*-scanner`).
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | IA-2 | Identification and Authentication | Routes service accounts to password auth |
    pub fn is_device_flow_excluded(&self, username: &str) -> bool {
        assert!(!username.is_empty(), "username must not be empty");
        let lower = username.to_lowercase();
        for pattern in &self.device_flow_exclude_users {
            if glob_match(pattern, &lower) {
                return true;
            }
        }
        false
    }

    pub fn shell_attributes_for_with_groups(
        &self,
        user: &str,
        groups: &[String],
    ) -> Option<Vec<String>> {
        assert!(!user.is_empty(), "user must not be empty");
        if let Some(attrs) = self.shell_start.get(&user.to_lowercase()) {
            return Some(attrs.clone());
        }
        for group in groups {
            if let Some(attrs) = self.shell_start_groups.get(&group.to_lowercase()) {
                return Some(attrs.clone());
            }
        }
        None
    }

    /// Returns the number of authorization rules in the policy.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn prompt_username(
        &self,
        user: Option<&str>,
        port: Option<&str>,
        rem_addr: Option<&str>,
    ) -> Option<&str> {
        if let Some(user) = user
            && let Some(custom) = self.ascii_user_prompts.get(&user.to_lowercase())
        {
            return Some(custom.as_str());
        }
        if let Some(port) = port
            && let Some(custom) = self.ascii_port_prompts.get(port)
        {
            return Some(custom.as_str());
        }
        if let Some(rem) = rem_addr
            && let Some(custom) = self.ascii_remaddr_prompts.get(rem)
        {
            return Some(custom.as_str());
        }
        self.ascii_prompts
            .as_ref()
            .and_then(|p| p.username.as_deref())
    }

    pub fn prompt_password(&self, user: Option<&str>) -> Option<&str> {
        if let Some(user) = user
            && let Some(custom) = self.ascii_password_prompts.get(&user.to_lowercase())
        {
            return Some(custom.as_str());
        }
        self.ascii_prompts
            .as_ref()
            .and_then(|p| p.password.as_deref())
    }

    /// Hook for observing/enforcing raw server messages from auth replies.
    /// Check user-specific override policy for raw server messages.
    fn check_user_override(
        override_policy: &RawServerMsgOverride,
        service: Option<u8>,
        action: Option<u8>,
        hex: &str,
    ) -> bool {
        if let Some(allow) = override_policy.allow
            && !allow
        {
            return false;
        }
        if !override_policy.allow_services.is_empty() {
            if let Some(svc) = service {
                if !override_policy.allow_services.contains(&svc) {
                    return false;
                }
            } else {
                return false;
            }
        }
        if !override_policy.allow_actions.is_empty() {
            if let Some(act) = action {
                if !override_policy.allow_actions.contains(&act) {
                    return false;
                }
            } else {
                return false;
            }
        }
        if override_policy
            .deny_prefixes
            .iter()
            .any(|p: &String| hex.starts_with(&p.to_lowercase()))
        {
            return false;
        }
        if !override_policy.allow_prefixes.is_empty()
            && !override_policy
                .allow_prefixes
                .iter()
                .any(|p: &String| hex.starts_with(&p.to_lowercase()))
        {
            return false;
        }
        true
    }

    pub fn observe_server_msg(
        &self,
        user: Option<&str>,
        port: Option<&str>,
        rem_addr: Option<&str>,
        service: Option<u8>,
        action: Option<u8>,
        raw: &[u8],
    ) -> bool {
        if !self.allow_raw_server_msg && !raw.is_empty() {
            return false;
        }
        if raw.is_empty() {
            return true;
        }
        let hex = hex::encode(raw).to_lowercase();
        if let Some(user) = user
            && let Some(override_policy) =
                self.raw_server_msg_user_overrides.get(&user.to_lowercase())
            && !Self::check_user_override(override_policy, service, action, &hex)
        {
            return false;
        }
        if self
            .raw_server_msg_deny_prefixes
            .iter()
            .any(|p| hex.starts_with(p))
        {
            return false;
        }
        if !self.raw_server_msg_allow_prefixes.is_empty()
            && !self
                .raw_server_msg_allow_prefixes
                .iter()
                .any(|p| hex.starts_with(p))
        {
            return false;
        }
        let _ = (user, port, rem_addr); // reserved for future rule-based decisions
        true
    }

    pub fn message_success(&self) -> Option<&str> {
        self.ascii_messages
            .as_ref()
            .and_then(|m| m.success.as_deref())
    }

    pub fn message_failure(&self) -> Option<&str> {
        self.ascii_messages
            .as_ref()
            .and_then(|m| m.failure.as_deref())
    }

    pub fn message_abort(&self) -> Option<&str> {
        self.ascii_messages
            .as_ref()
            .and_then(|m| m.abort.as_deref())
    }
}

pub fn validate_policy_file(
    policy: impl AsRef<Path>,
    schema: impl AsRef<Path>,
) -> Result<PolicyDocument> {
    let path = policy.as_ref();
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading policy {}", path.display()))?;
    let value: Value = serde_json::from_str(&contents)
        .with_context(|| format!("parsing JSON policy {}", path.display()))?;
    validate_against_schema(&value, schema.as_ref())?;
    let document: PolicyDocument = serde_json::from_value(value)
        .with_context(|| format!("deserializing policy {}", path.display()))?;
    Ok(document)
}

pub fn validate_policy_document(document: &PolicyDocument, schema: impl AsRef<Path>) -> Result<()> {
    let value =
        serde_json::to_value(document).context("serializing policy document for validation")?;
    validate_against_schema(&value, schema.as_ref())
}

pub fn normalize_command(cmd: &str) -> String {
    let lowered = cmd.trim().to_lowercase();
    let mut result = String::with_capacity(lowered.len());
    let mut last_was_space = false;
    for ch in lowered.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                result.push(' ');
                last_was_space = true;
            }
        } else {
            result.push(ch);
            last_was_space = false;
        }
    }
    result
}

/// Compile a policy pattern into a regex with security limits.
///
/// # NIST Controls
/// - **SI-10 (Information Input Validation)**: Applies size and complexity limits
///   to prevent ReDoS attacks (CWE-1333). Patterns are anchored for full-match
///   semantics.
///
/// # Security
/// The regex is compiled with:
/// - Size limit of 1MB to prevent memory exhaustion
/// - Nesting limit of 100 to prevent stack overflow
/// - Full-string anchoring to enforce exact command matching
fn compile_pattern(raw: &str) -> Result<Regex> {
    let anchored = format!("^(?:{})$", raw);
    RegexBuilder::new(&anchored)
        .size_limit(MAX_REGEX_SIZE)
        .nest_limit(MAX_REGEX_NEST_LEVEL)
        .build()
        .context("invalid regex (pattern may be too complex)")
}

fn validate_against_schema(value: &Value, schema_path: &Path) -> Result<()> {
    let schema_contents = fs::read_to_string(schema_path)
        .with_context(|| format!("reading schema {}", schema_path.display()))?;
    let schema_json: Value = serde_json::from_str(&schema_contents)
        .with_context(|| format!("parsing JSON schema {}", schema_path.display()))?;
    let compiled = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .build(&schema_json)
        .map_err(|err| anyhow!("compiling schema {}: {err}", schema_path.display()))?;

    compiled
        .validate(value)
        .map_err(|err| anyhow!("policy failed schema validation: {}", err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy_doc(rules: Vec<RuleConfig>) -> PolicyDocument {
        PolicyDocument {
            default_allow: false,
            shell_start: HashMap::new(),
            shell_start_groups: HashMap::new(),
            author_service_attributes: HashMap::new(),
            device_flow_exclude_users: Vec::new(),
            nad_groups: HashMap::new(),
            enable_groups: HashMap::new(),
            ascii_prompts: None,
            ascii_user_prompts: HashMap::new(),
            ascii_password_prompts: HashMap::new(),
            ascii_port_prompts: HashMap::new(),
            ascii_remaddr_prompts: HashMap::new(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: Vec::new(),
            raw_server_msg_deny_prefixes: Vec::new(),
            raw_server_msg_user_overrides: HashMap::new(),
            ascii_messages: None,
            rules,
        }
    }

    fn make_rule(id: &str, priority: i32, effect: Effect, pattern: &str) -> RuleConfig {
        RuleConfig {
            id: id.into(),
            priority,
            effect,
            pattern: pattern.into(),
            users: vec![],
            groups: vec![],
            nad_groups: vec![],
            schedule: None,
        }
    }

    // ==================== normalize_command Tests ====================

    #[test]
    fn normalizes_whitespace_and_case() {
        assert_eq!(normalize_command(" Show  Run "), "show run");
        assert_eq!(normalize_command("show\tint  Gi0/1"), "show int gi0/1");
    }

    #[test]
    fn normalize_command_preserves_single_spaces() {
        assert_eq!(normalize_command("show run"), "show run");
    }

    #[test]
    fn normalize_command_handles_empty() {
        assert_eq!(normalize_command(""), "");
        assert_eq!(normalize_command("   "), "");
    }

    #[test]
    fn normalize_command_handles_newlines() {
        assert_eq!(normalize_command("show\n\nrun"), "show run");
    }

    // ==================== authorize Tests ====================

    #[test]
    fn authorize_default_deny_when_no_match() {
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "show.*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "configure terminal");
        assert!(!decision.allowed);
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn authorize_default_allow_when_configured() {
        let mut doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Deny, "show.*")]);
        doc.default_allow = true;
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "configure terminal");
        assert!(decision.allowed);
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn authorize_matches_rule() {
        let doc = make_policy_doc(vec![make_rule("allow-show", 10, Effect::Allow, "show.*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show running-config");
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule.unwrap(), "allow-show");
    }

    #[test]
    fn authorize_case_insensitive_command() {
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "show run")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "SHOW RUN");
        assert!(decision.allowed);
    }

    #[test]
    fn authorize_case_insensitive_user() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "show.*");
        rule.users = vec!["ALICE".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
    }

    #[test]
    fn last_match_wins_with_priority() {
        let doc = make_policy_doc(vec![
            make_rule("allow1", 10, Effect::Allow, "show.*"),
            make_rule("deny1", 10, Effect::Deny, "show.*"),
            make_rule("allow2", 20, Effect::Allow, "show.*"),
        ]);

        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule.unwrap(), "allow2");
    }

    #[test]
    fn same_priority_last_rule_wins() {
        let doc = make_policy_doc(vec![
            make_rule("allow1", 10, Effect::Allow, "show.*"),
            make_rule("deny1", 10, Effect::Deny, "show.*"),
        ]);

        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed); // deny1 is last with same priority
        assert_eq!(decision.matched_rule.unwrap(), "deny1");
    }

    #[test]
    fn higher_priority_wins_regardless_of_order() {
        let doc = make_policy_doc(vec![
            make_rule("high-priority-deny", 100, Effect::Deny, "show.*"),
            make_rule("low-priority-allow", 10, Effect::Allow, "show.*"),
        ]);

        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed);
        assert_eq!(decision.matched_rule.unwrap(), "high-priority-deny");
    }

    // ==================== User Filtering Tests ====================

    #[test]
    fn authorize_user_filter_matches() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "show.*");
        rule.users = vec!["alice".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
    }

    #[test]
    fn authorize_user_filter_no_match() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "show.*");
        rule.users = vec!["bob".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed); // Falls through to default_allow=false
    }

    #[test]
    fn authorize_empty_users_matches_all() {
        let rule = make_rule("r1", 10, Effect::Allow, "show.*");
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "show run").allowed);
        assert!(engine.authorize("bob", "show run").allowed);
        assert!(engine.authorize("charlie", "show run").allowed);
    }

    // ==================== Group Filtering Tests ====================

    #[test]
    fn authorize_with_groups_matches() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "configure.*");
        rule.groups = vec!["admins".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let groups = vec!["admins".to_string(), "users".to_string()];
        let decision = engine.authorize_with_groups("alice", &groups, "configure terminal");
        assert!(decision.allowed);
    }

    #[test]
    fn authorize_with_groups_no_match() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "configure.*");
        rule.groups = vec!["admins".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let groups = vec!["users".to_string()];
        let decision = engine.authorize_with_groups("alice", &groups, "configure terminal");
        assert!(!decision.allowed);
    }

    #[test]
    fn authorize_with_groups_case_insensitive() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "configure.*");
        rule.groups = vec!["ADMINS".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let groups = vec!["admins".to_string()];
        let decision = engine.authorize_with_groups("alice", &groups, "configure terminal");
        assert!(decision.allowed);
    }

    // ==================== Shell Attributes Tests ====================

    #[test]
    fn shell_attributes_for_existing_user() {
        let mut doc = make_policy_doc(vec![]);
        doc.shell_start.insert(
            "alice".into(),
            vec!["priv-lvl=15".into(), "timeout=300".into()],
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        let attrs = engine.shell_attributes_for("alice");
        assert!(attrs.is_some());
        let attrs = attrs.unwrap();
        assert!(attrs.contains(&"priv-lvl=15".to_string()));
        assert!(attrs.contains(&"timeout=300".to_string()));
    }

    #[test]
    fn shell_attributes_for_case_insensitive() {
        let mut doc = make_policy_doc(vec![]);
        doc.shell_start
            .insert("ALICE".into(), vec!["priv-lvl=15".into()]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let attrs = engine.shell_attributes_for("alice");
        assert!(attrs.is_some());
    }

    #[test]
    fn shell_attributes_for_nonexistent_user() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let attrs = engine.shell_attributes_for("unknown");
        assert!(attrs.is_none());
    }

    // ============== Vendor Service Attribute Tests ==============

    fn make_paloalto_doc() -> PolicyDocument {
        let mut groups = HashMap::new();
        groups.insert(
            "netops".to_string(),
            vec!["PaloAlto-Admin-Role=superuser".to_string()],
        );
        let mut users = HashMap::new();
        users.insert(
            "svc-pan".to_string(),
            vec!["PaloAlto-Admin-Role=deviceadmin".to_string()],
        );
        let mut svc = HashMap::new();
        svc.insert(
            "paloalto".to_string(),
            AuthorServiceConfig {
                users,
                groups,
                default: None,
            },
        );
        let mut doc = make_policy_doc(vec![]);
        doc.author_service_attributes = svc;
        doc
    }

    #[test]
    fn vendor_service_is_recognized_case_insensitive() {
        let engine = PolicyEngine::from_document(make_paloalto_doc()).unwrap();
        assert!(engine.is_custom_author_service("paloalto"));
        assert!(engine.is_custom_author_service("PaloAlto"));
        assert!(!engine.is_custom_author_service("shell"));
        assert_eq!(engine.custom_author_services(), vec!["paloalto".to_string()]);
    }

    #[test]
    fn vendor_service_group_match_returns_role() {
        let engine = PolicyEngine::from_document(make_paloalto_doc()).unwrap();
        let groups = vec!["NetOps".to_string()];
        let attrs = engine.service_attributes_for_with_groups("PaloAlto", "alice", &groups);
        assert_eq!(
            attrs,
            Some(vec!["PaloAlto-Admin-Role=superuser".to_string()])
        );
    }

    #[test]
    fn vendor_service_user_overrides_group() {
        let engine = PolicyEngine::from_document(make_paloalto_doc()).unwrap();
        let groups = vec!["netops".to_string()];
        let attrs = engine.service_attributes_for_with_groups("paloalto", "SVC-PAN", &groups);
        assert_eq!(
            attrs,
            Some(vec!["PaloAlto-Admin-Role=deviceadmin".to_string()])
        );
    }

    #[test]
    fn vendor_service_no_match_returns_none() {
        let engine = PolicyEngine::from_document(make_paloalto_doc()).unwrap();
        let groups = vec!["helpdesk".to_string()];
        let attrs = engine.service_attributes_for_with_groups("paloalto", "bob", &groups);
        assert!(attrs.is_none());
    }

    #[test]
    fn vendor_service_default_used_when_no_user_or_group() {
        let mut doc = make_paloalto_doc();
        if let Some(cfg) = doc.author_service_attributes.get_mut("paloalto") {
            cfg.default = Some(vec!["PaloAlto-Admin-Role=superreader".to_string()]);
        }
        let engine = PolicyEngine::from_document(doc).unwrap();
        let attrs = engine.service_attributes_for_with_groups("paloalto", "bob", &[]);
        assert_eq!(
            attrs,
            Some(vec!["PaloAlto-Admin-Role=superreader".to_string()])
        );
    }

    #[test]
    fn unknown_vendor_service_returns_none() {
        let engine = PolicyEngine::from_document(make_paloalto_doc()).unwrap();
        let attrs = engine.service_attributes_for_with_groups("ciscoasa", "alice", &["netops".into()]);
        assert!(attrs.is_none());
        assert!(!engine.is_custom_author_service("ciscoasa"));
    }

    // ==================== Prompt Tests ====================

    #[test]
    fn prompt_username_user_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_user_prompts
            .insert("alice".into(), "Alice's Username: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(Some("alice"), None, None);
        assert_eq!(prompt, Some("Alice's Username: "));
    }

    #[test]
    fn prompt_username_port_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_port_prompts
            .insert("console".into(), "Console Login: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(None, Some("console"), None);
        assert_eq!(prompt, Some("Console Login: "));
    }

    #[test]
    fn prompt_username_remaddr_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_remaddr_prompts
            .insert("192.168.1.1".into(), "Remote Login: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(None, None, Some("192.168.1.1"));
        assert_eq!(prompt, Some("Remote Login: "));
    }

    #[test]
    fn prompt_username_global_fallback() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_prompts = Some(AsciiPrompts {
            username: Some("Global Username: ".into()),
            password: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_username(None, None, None);
        assert_eq!(prompt, Some("Global Username: "));
    }

    #[test]
    fn prompt_username_user_takes_priority() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_user_prompts
            .insert("alice".into(), "User Prompt".into());
        doc.ascii_port_prompts
            .insert("console".into(), "Port Prompt".into());
        doc.ascii_prompts = Some(AsciiPrompts {
            username: Some("Global Prompt".into()),
            password: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        // User prompt should win
        let prompt = engine.prompt_username(Some("alice"), Some("console"), None);
        assert_eq!(prompt, Some("User Prompt"));
    }

    #[test]
    fn prompt_password_user_override() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_password_prompts
            .insert("alice".into(), "Alice's Password: ".into());
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_password(Some("alice"));
        assert_eq!(prompt, Some("Alice's Password: "));
    }

    #[test]
    fn prompt_password_global_fallback() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_prompts = Some(AsciiPrompts {
            username: None,
            password: Some("Enter Password: ".into()),
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        let prompt = engine.prompt_password(None);
        assert_eq!(prompt, Some("Enter Password: "));
    }

    // ==================== Message Tests ====================

    #[test]
    fn message_success() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_messages = Some(AsciiMessages {
            success: Some("Welcome!".into()),
            failure: None,
            abort: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(engine.message_success(), Some("Welcome!"));
    }

    #[test]
    fn message_failure() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_messages = Some(AsciiMessages {
            success: None,
            failure: Some("Access Denied".into()),
            abort: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(engine.message_failure(), Some("Access Denied"));
    }

    #[test]
    fn message_abort() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_messages = Some(AsciiMessages {
            success: None,
            failure: None,
            abort: Some("Session Aborted".into()),
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(engine.message_abort(), Some("Session Aborted"));
    }

    // ==================== Raw Server Message Tests ====================

    #[test]
    fn observe_server_msg_allowed_by_default() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.observe_server_msg(None, None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_empty_allowed() {
        let mut doc = make_policy_doc(vec![]);
        doc.allow_raw_server_msg = false;
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Empty messages are always allowed
        assert!(engine.observe_server_msg(None, None, None, None, None, b""));
    }

    #[test]
    fn observe_server_msg_denied_when_disabled() {
        let mut doc = make_policy_doc(vec![]);
        doc.allow_raw_server_msg = false;
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(!engine.observe_server_msg(None, None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_deny_prefix() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_deny_prefixes = vec!["48656c".into()]; // "Hel" in hex
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(!engine.observe_server_msg(None, None, None, None, None, b"Hello"));
        assert!(engine.observe_server_msg(None, None, None, None, None, b"World"));
    }

    #[test]
    fn observe_server_msg_allow_prefix_required() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_allow_prefixes = vec!["48656c".into()]; // "Hel" in hex
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.observe_server_msg(None, None, None, None, None, b"Hello"));
        assert!(!engine.observe_server_msg(None, None, None, None, None, b"World"));
    }

    // ==================== Regex Pattern Tests ====================

    #[test]
    fn authorize_regex_pattern() {
        let doc = make_policy_doc(vec![make_rule(
            "r1",
            10,
            Effect::Allow,
            "show (run|start|version)",
        )]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "show run").allowed);
        assert!(engine.authorize("alice", "show start").allowed);
        assert!(engine.authorize("alice", "show version").allowed);
        assert!(!engine.authorize("alice", "show interface").allowed);
    }

    #[test]
    fn authorize_wildcard_pattern() {
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, ".*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "any command").allowed);
        assert!(engine.authorize("alice", "show run").allowed);
        assert!(engine.authorize("alice", "configure terminal").allowed);
    }

    #[test]
    fn authorize_anchored_pattern() {
        // Patterns should be anchored (full match required)
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "show")]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "show").allowed);
        assert!(!engine.authorize("alice", "show run").allowed); // Not a full match
    }

    // ==================== observe_server_msg User Override Tests ====================

    #[test]
    fn observe_server_msg_user_override_allow_false() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_user_overrides.insert(
            "alice".into(),
            RawServerMsgOverride {
                allow: Some(false),
                allow_prefixes: vec![],
                deny_prefixes: vec![],
                allow_services: vec![],
                allow_actions: vec![],
            },
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(!engine.observe_server_msg(Some("alice"), None, None, None, None, b"hello"));
        // Other users not affected
        assert!(engine.observe_server_msg(Some("bob"), None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_user_override_case_insensitive() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_user_overrides.insert(
            "ALICE".into(),
            RawServerMsgOverride {
                allow: Some(false),
                allow_prefixes: vec![],
                deny_prefixes: vec![],
                allow_services: vec![],
                allow_actions: vec![],
            },
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Should match regardless of case
        assert!(!engine.observe_server_msg(Some("alice"), None, None, None, None, b"hello"));
        assert!(!engine.observe_server_msg(Some("ALICE"), None, None, None, None, b"hello"));
        assert!(!engine.observe_server_msg(Some("Alice"), None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_user_override_allow_services() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_user_overrides.insert(
            "alice".into(),
            RawServerMsgOverride {
                allow: None,
                allow_prefixes: vec![],
                deny_prefixes: vec![],
                allow_services: vec![1, 2], // Only allow services 1 and 2
                allow_actions: vec![],
            },
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Service 1 allowed
        assert!(engine.observe_server_msg(Some("alice"), None, None, Some(1), None, b"hello"));
        // Service 2 allowed
        assert!(engine.observe_server_msg(Some("alice"), None, None, Some(2), None, b"hello"));
        // Service 3 not allowed
        assert!(!engine.observe_server_msg(Some("alice"), None, None, Some(3), None, b"hello"));
        // No service specified - denied when allow_services is set
        assert!(!engine.observe_server_msg(Some("alice"), None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_user_override_allow_actions() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_user_overrides.insert(
            "alice".into(),
            RawServerMsgOverride {
                allow: None,
                allow_prefixes: vec![],
                deny_prefixes: vec![],
                allow_services: vec![],
                allow_actions: vec![1, 2], // Only allow actions 1 and 2
            },
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Action 1 allowed
        assert!(engine.observe_server_msg(Some("alice"), None, None, None, Some(1), b"hello"));
        // Action 2 allowed
        assert!(engine.observe_server_msg(Some("alice"), None, None, None, Some(2), b"hello"));
        // Action 3 not allowed
        assert!(!engine.observe_server_msg(Some("alice"), None, None, None, Some(3), b"hello"));
        // No action specified - denied when allow_actions is set
        assert!(!engine.observe_server_msg(Some("alice"), None, None, None, None, b"hello"));
    }

    #[test]
    fn observe_server_msg_user_override_deny_prefix() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_user_overrides.insert(
            "alice".into(),
            RawServerMsgOverride {
                allow: None,
                allow_prefixes: vec![],
                deny_prefixes: vec!["48656c".into()], // "Hel" in hex (lowercase)
                allow_services: vec![],
                allow_actions: vec![],
            },
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(!engine.observe_server_msg(Some("alice"), None, None, None, None, b"Hello"));
        assert!(engine.observe_server_msg(Some("alice"), None, None, None, None, b"World"));
    }

    #[test]
    fn observe_server_msg_user_override_allow_prefix_required() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_user_overrides.insert(
            "alice".into(),
            RawServerMsgOverride {
                allow: None,
                allow_prefixes: vec!["48656c".into()], // "Hel" in hex
                deny_prefixes: vec![],
                allow_services: vec![],
                allow_actions: vec![],
            },
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.observe_server_msg(Some("alice"), None, None, None, None, b"Hello"));
        assert!(!engine.observe_server_msg(Some("alice"), None, None, None, None, b"World"));
    }

    #[test]
    fn observe_server_msg_user_override_combined() {
        let mut doc = make_policy_doc(vec![]);
        doc.raw_server_msg_user_overrides.insert(
            "alice".into(),
            RawServerMsgOverride {
                allow: None,
                allow_prefixes: vec![],
                deny_prefixes: vec![],
                allow_services: vec![1],
                allow_actions: vec![1],
            },
        );
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Both service and action must match
        assert!(engine.observe_server_msg(Some("alice"), None, None, Some(1), Some(1), b"hello"));
        assert!(!engine.observe_server_msg(Some("alice"), None, None, Some(1), Some(2), b"hello"));
        assert!(!engine.observe_server_msg(Some("alice"), None, None, Some(2), Some(1), b"hello"));
    }

    // ==================== rule_count Tests ====================

    #[test]
    fn rule_count_empty() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn rule_count_multiple() {
        let doc = make_policy_doc(vec![
            make_rule("r1", 10, Effect::Allow, "show.*"),
            make_rule("r2", 10, Effect::Deny, "configure.*"),
            make_rule("r3", 20, Effect::Allow, ".*"),
        ]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert_eq!(engine.rule_count(), 3);
    }

    // ==================== compile_pattern Tests ====================

    #[test]
    fn compile_pattern_invalid_regex() {
        // Invalid regex should fail
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "[invalid")]);
        let result = PolicyEngine::from_document(doc);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // Error message should mention the rule or pattern
        assert!(
            err_msg.contains("r1") || err_msg.contains("[invalid") || err_msg.contains("pattern")
        );
    }

    #[test]
    fn compile_pattern_empty_pattern() {
        // Empty pattern should match empty command
        let doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "")]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.authorize("alice", "").allowed);
        assert!(!engine.authorize("alice", "show").allowed);
    }

    #[test]
    fn compile_pattern_complex_regex() {
        let doc = make_policy_doc(vec![make_rule(
            "r1",
            10,
            Effect::Allow,
            r"show\s+interface\s+gi\d+/\d+",
        )]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert!(engine.authorize("alice", "show interface gi0/1").allowed);
        assert!(engine.authorize("alice", "show interface gi12/34").allowed);
        assert!(!engine.authorize("alice", "show interface eth0").allowed);
    }

    // ==================== from_document Edge Cases ====================

    #[test]
    fn from_document_lowercase_users() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "show.*");
        rule.users = vec!["ALICE".into(), "Bob".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        // All users should match regardless of case
        assert!(engine.authorize("alice", "show run").allowed);
        assert!(engine.authorize("ALICE", "show run").allowed);
        assert!(engine.authorize("bob", "show run").allowed);
        assert!(engine.authorize("BOB", "show run").allowed);
    }

    #[test]
    fn from_document_lowercase_groups() {
        let mut rule = make_rule("r1", 10, Effect::Allow, "configure.*");
        rule.groups = vec!["ADMINS".into(), "NetOps".into()];
        let doc = make_policy_doc(vec![rule]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let groups = vec!["admins".to_string()];
        assert!(
            engine
                .authorize_with_groups("alice", &groups, "configure terminal")
                .allowed
        );

        let groups = vec!["ADMINS".to_string()];
        assert!(
            engine
                .authorize_with_groups("alice", &groups, "configure terminal")
                .allowed
        );
    }

    #[test]
    fn from_document_shell_start_lowercase() {
        let mut doc = make_policy_doc(vec![]);
        doc.shell_start
            .insert("ALICE".into(), vec!["priv-lvl=15".into()]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Should find regardless of case
        assert!(engine.shell_attributes_for("alice").is_some());
        assert!(engine.shell_attributes_for("ALICE").is_some());
    }

    // ==================== Messages None Tests ====================

    #[test]
    fn message_success_none() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.message_success().is_none());
    }

    #[test]
    fn message_failure_none() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.message_failure().is_none());
    }

    #[test]
    fn message_abort_none() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.message_abort().is_none());
    }

    // ==================== Prompt None Tests ====================

    #[test]
    fn prompt_username_none() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.prompt_username(None, None, None).is_none());
    }

    #[test]
    fn prompt_password_none() {
        let doc = make_policy_doc(vec![]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.prompt_password(None).is_none());
    }

    #[test]
    fn prompt_username_no_match() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_user_prompts
            .insert("bob".into(), "Bob's prompt".into());
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.prompt_username(Some("alice"), None, None).is_none());
    }

    #[test]
    fn prompt_password_no_match() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_password_prompts
            .insert("bob".into(), "Bob's password".into());
        let engine = PolicyEngine::from_document(doc).unwrap();
        assert!(engine.prompt_password(Some("alice")).is_none());
    }

    // ==================== Decision Struct Tests ====================

    #[test]
    fn decision_allowed_with_rule() {
        let doc = make_policy_doc(vec![make_rule("allow-all", 10, Effect::Allow, ".*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule, Some("allow-all".to_string()));
    }

    #[test]
    fn decision_denied_with_rule() {
        let doc = make_policy_doc(vec![make_rule("deny-all", 10, Effect::Deny, ".*")]);
        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed);
        assert_eq!(decision.matched_rule, Some("deny-all".to_string()));
    }

    #[test]
    fn decision_default_no_rule() {
        let mut doc = make_policy_doc(vec![]);
        doc.default_allow = true;
        let engine = PolicyEngine::from_document(doc).unwrap();
        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
        assert!(decision.matched_rule.is_none());
    }

    // ==================== normalize_command Edge Cases ====================

    #[test]
    fn normalize_command_unicode() {
        // Unicode should be preserved but lowercased
        assert_eq!(normalize_command("SHOW ËCHO"), "show ëcho");
    }

    #[test]
    fn normalize_command_mixed_whitespace() {
        assert_eq!(normalize_command("show\t \n\r  run"), "show run");
    }

    #[test]
    fn normalize_command_only_whitespace() {
        assert_eq!(normalize_command("\t\n  \r"), "");
    }

    // ==================== Effect Enum Tests ====================

    #[test]
    fn effect_allow_equality() {
        assert_eq!(Effect::Allow, Effect::Allow);
        assert_ne!(Effect::Allow, Effect::Deny);
    }

    #[test]
    fn effect_deny_equality() {
        assert_eq!(Effect::Deny, Effect::Deny);
        assert_ne!(Effect::Deny, Effect::Allow);
    }

    // ==================== RawServerMsgOverride Tests ====================

    #[test]
    fn raw_server_msg_override_clone() {
        let override_cfg = RawServerMsgOverride {
            allow: Some(true),
            allow_prefixes: vec!["abc".into()],
            deny_prefixes: vec!["def".into()],
            allow_services: vec![1, 2],
            allow_actions: vec![3, 4],
        };
        let cloned = override_cfg.clone();
        assert_eq!(cloned.allow, Some(true));
        assert_eq!(cloned.allow_prefixes, vec!["abc".to_string()]);
        assert_eq!(cloned.deny_prefixes, vec!["def".to_string()]);
        assert_eq!(cloned.allow_services, vec![1, 2]);
        assert_eq!(cloned.allow_actions, vec![3, 4]);
    }

    // ==================== AsciiPrompts Tests ====================

    #[test]
    fn ascii_prompts_both_set() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_prompts = Some(AsciiPrompts {
            username: Some("Enter user: ".into()),
            password: Some("Enter pass: ".into()),
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(
            engine.prompt_username(None, None, None),
            Some("Enter user: ")
        );
        assert_eq!(engine.prompt_password(None), Some("Enter pass: "));
    }

    #[test]
    fn ascii_prompts_only_username() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_prompts = Some(AsciiPrompts {
            username: Some("Enter user: ".into()),
            password: None,
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(
            engine.prompt_username(None, None, None),
            Some("Enter user: ")
        );
        assert!(engine.prompt_password(None).is_none());
    }

    // ==================== AsciiMessages Tests ====================

    #[test]
    fn ascii_messages_all_set() {
        let mut doc = make_policy_doc(vec![]);
        doc.ascii_messages = Some(AsciiMessages {
            success: Some("Welcome!".into()),
            failure: Some("Denied!".into()),
            abort: Some("Aborted!".into()),
        });
        let engine = PolicyEngine::from_document(doc).unwrap();

        assert_eq!(engine.message_success(), Some("Welcome!"));
        assert_eq!(engine.message_failure(), Some("Denied!"));
        assert_eq!(engine.message_abort(), Some("Aborted!"));
    }

    // ==================== default_allow_raw_server_msg Tests ====================

    #[test]
    fn default_allow_raw_server_msg_default_true() {
        // Test the default function
        assert!(default_allow_raw_server_msg());
    }

    // ==================== PolicyDocument Clone/Debug Tests ====================

    #[test]
    fn policy_document_clone() {
        let mut doc = make_policy_doc(vec![make_rule("r1", 10, Effect::Allow, "show.*")]);
        doc.default_allow = true;
        let cloned = doc.clone();
        assert!(cloned.default_allow);
        assert_eq!(cloned.rules.len(), 1);
        assert_eq!(cloned.rules[0].id, "r1");
    }

    #[test]
    fn rule_config_clone() {
        let rule = make_rule("r1", 10, Effect::Allow, "show.*");
        let cloned = rule.clone();
        assert_eq!(cloned.id, "r1");
        assert_eq!(cloned.priority, 10);
        assert_eq!(cloned.effect, Effect::Allow);
        assert_eq!(cloned.pattern, "show.*");
    }

    // ==================== Rule Priority Edge Cases ====================

    #[test]
    fn rule_negative_priority() {
        let doc = make_policy_doc(vec![
            make_rule("low", -100, Effect::Deny, "show.*"),
            make_rule("high", 100, Effect::Allow, "show.*"),
        ]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        let decision = engine.authorize("alice", "show run");
        assert!(decision.allowed);
        assert_eq!(decision.matched_rule, Some("high".to_string()));
    }

    #[test]
    fn rule_zero_priority() {
        let doc = make_policy_doc(vec![
            make_rule("first", 0, Effect::Allow, "show.*"),
            make_rule("second", 0, Effect::Deny, "show.*"),
        ]);
        let engine = PolicyEngine::from_document(doc).unwrap();

        // Same priority, last one wins
        let decision = engine.authorize("alice", "show run");
        assert!(!decision.allowed);
        assert_eq!(decision.matched_rule, Some("second".to_string()));
    }

    // ==================== ReDoS Protection Tests ====================

    #[test]
    fn compile_pattern_deeply_nested_rejected() {
        // Very deeply nested pattern should be rejected due to nest_limit
        let deep_pattern = "(".repeat(200) + "a" + &")".repeat(200);
        let result = compile_pattern(&deep_pattern);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("regex") || err_msg.contains("complex"));
    }

    #[test]
    fn compile_pattern_moderate_nesting_allowed() {
        // Moderate nesting should be allowed
        let pattern = "((show|configure)\\s+(run|start))";
        let result = compile_pattern(pattern);
        assert!(result.is_ok());
    }

    #[test]
    fn compile_pattern_normal_patterns_work() {
        // Normal authorization patterns should compile fine
        let patterns = vec![
            "show.*",
            "configure terminal",
            "show (run|start|version)",
            r"show\s+interface\s+.*",
            "clear (counters|log|arp)",
            "ping [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+",
        ];

        for pattern in patterns {
            let result = compile_pattern(pattern);
            assert!(result.is_ok(), "Pattern '{}' should compile", pattern);
        }
    }

    // ==================== Schedule Tests ====================

    fn make_schedule(days: &[&str], hours: Option<&str>) -> CompiledSchedule {
        let cfg = ScheduleConfig {
            days: days.iter().map(|s| s.to_string()).collect(),
            hours: hours.map(|s| s.to_string()),
        };
        compile_schedule(&cfg).expect("valid schedule config")
    }

    #[test]
    fn compile_schedule_all_days_no_hours() {
        let s = make_schedule(&[], None);
        assert_eq!(s.day_mask, 0x7F);
        assert_eq!(s.hour_start_min, 0);
        assert_eq!(s.hour_end_min, 1440);
    }

    #[test]
    fn compile_schedule_weekdays_shorthand() {
        let s = make_schedule(&["weekdays"], None);
        // Mon(1)..Fri(5) → bits 1-5 set
        assert_eq!(s.day_mask & 0b0111_1110, 0b0111_1110);
        assert_eq!(s.day_mask & 0b1000_0001, 0); // Sat/Sun not set
    }

    #[test]
    fn compile_schedule_weekends_shorthand() {
        let s = make_schedule(&["weekends"], None);
        assert_eq!(s.day_mask & 0b0100_0001, 0b0100_0001); // Sat(6)+Sun(0)
    }

    #[test]
    fn compile_schedule_explicit_days() {
        let s = make_schedule(&["mon", "wed", "fri"], None);
        assert!((s.day_mask >> 1) & 1 == 1, "Monday");
        assert!((s.day_mask >> 3) & 1 == 1, "Wednesday");
        assert!((s.day_mask >> 5) & 1 == 1, "Friday");
        assert!(s.day_mask & 1 == 0, "Sunday not set");
    }

    #[test]
    fn compile_schedule_business_hours() {
        let s = make_schedule(&[], Some("08:00-18:00"));
        assert_eq!(s.hour_start_min, 480);
        assert_eq!(s.hour_end_min, 1080);
        assert!(!s.wraps_midnight);
    }

    #[test]
    fn compile_schedule_overnight_window() {
        let s = make_schedule(&[], Some("22:00-06:00"));
        assert_eq!(s.hour_start_min, 1320);
        assert_eq!(s.hour_end_min, 360);
        assert!(s.wraps_midnight);
    }

    #[test]
    fn compile_schedule_invalid_day_errors() {
        let cfg = ScheduleConfig {
            days: vec!["not-a-day".into()],
            hours: None,
        };
        assert!(compile_schedule(&cfg).is_err());
    }

    #[test]
    fn compile_schedule_invalid_hours_errors() {
        let cfg = ScheduleConfig {
            days: vec![],
            hours: Some("25:00-26:00".into()),
        };
        assert!(compile_schedule(&cfg).is_err());
    }

    #[test]
    fn parse_hhmm_valid() {
        assert_eq!(parse_hhmm("08:30"), Some(510));
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
    }

    #[test]
    fn parse_hhmm_invalid() {
        assert!(parse_hhmm("24:00").is_none());
        assert!(parse_hhmm("08:60").is_none());
        assert!(parse_hhmm("bad").is_none());
    }

    #[test]
    fn rule_with_always_active_schedule_fires() {
        let mut rule = make_rule("r", 10, Effect::Allow, "show.*");
        rule.schedule = Some(ScheduleConfig {
            days: vec![],
            hours: None,
        });
        let doc = PolicyDocument {
            default_allow: false,
            shell_start: HashMap::new(),
            shell_start_groups: HashMap::new(),
            author_service_attributes: HashMap::new(),
            device_flow_exclude_users: vec![],
            nad_groups: HashMap::new(),
            enable_groups: HashMap::new(),
            ascii_prompts: None,
            ascii_user_prompts: HashMap::new(),
            ascii_password_prompts: HashMap::new(),
            ascii_port_prompts: HashMap::new(),
            ascii_remaddr_prompts: HashMap::new(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: vec![],
            raw_server_msg_deny_prefixes: vec![],
            raw_server_msg_user_overrides: HashMap::new(),
            ascii_messages: None,
            rules: vec![rule],
        };
        let engine = PolicyEngine::from_document(doc).unwrap();
        let d = engine.authorize_with_groups("alice", &[], "show version");
        assert!(d.allowed, "rule with all-day schedule should fire now");
    }

    // ==================== NAD Group Tests ====================

    fn make_engine_with_nad(
        nad_groups: HashMap<String, NadGroupConfig>,
        rules: Vec<RuleConfig>,
    ) -> PolicyEngine {
        let doc = PolicyDocument {
            default_allow: false,
            shell_start: HashMap::new(),
            shell_start_groups: HashMap::new(),
            author_service_attributes: HashMap::new(),
            device_flow_exclude_users: vec![],
            nad_groups,
            enable_groups: HashMap::new(),
            ascii_prompts: None,
            ascii_user_prompts: HashMap::new(),
            ascii_password_prompts: HashMap::new(),
            ascii_port_prompts: HashMap::new(),
            ascii_remaddr_prompts: HashMap::new(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: vec![],
            raw_server_msg_deny_prefixes: vec![],
            raw_server_msg_user_overrides: HashMap::new(),
            ascii_messages: None,
            rules,
        };
        PolicyEngine::from_document(doc).unwrap()
    }

    #[test]
    fn cidr_ipv4_contains_host() {
        let c = parse_cidr("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn cidr_ipv4_slash32_exact() {
        let c = parse_cidr("10.0.0.1/32").unwrap();
        assert!(c.contains("10.0.0.1".parse().unwrap()));
        assert!(!c.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn cidr_ipv4_slash0_matches_all() {
        let c = parse_cidr("0.0.0.0/0").unwrap();
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(c.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn cidr_invalid_prefix_errors() {
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("not-an-ip/8").is_err());
        assert!(parse_cidr("10.0.0.0").is_err());
    }

    #[test]
    fn resolve_nad_groups_matches_cidr() {
        let mut nads = HashMap::new();
        nads.insert(
            "core".into(),
            NadGroupConfig {
                cidrs: vec!["10.0.0.0/8".into()],
            },
        );
        nads.insert(
            "access".into(),
            NadGroupConfig {
                cidrs: vec!["192.168.0.0/16".into()],
            },
        );
        let engine = make_engine_with_nad(nads, vec![]);
        let groups = engine.resolve_nad_groups("10.0.1.1:49");
        assert_eq!(groups, vec!["core"]);
        let groups = engine.resolve_nad_groups("192.168.5.10:49");
        assert_eq!(groups, vec!["access"]);
        let groups = engine.resolve_nad_groups("172.16.0.1:49");
        assert!(groups.is_empty());
    }

    #[test]
    fn nad_group_rule_fires_for_matching_nad() {
        let mut nads = HashMap::new();
        nads.insert(
            "core".into(),
            NadGroupConfig {
                cidrs: vec!["10.0.0.0/8".into()],
            },
        );
        let mut rule = make_rule("deny-config-access", 50, Effect::Deny, "(configure|conf).*");
        rule.nad_groups = vec!["core".into()];
        let engine = make_engine_with_nad(nads, vec![rule]);

        // Core NAD → rule fires → configure is denied
        let core_nads = engine.resolve_nad_groups("10.0.1.1:49");
        let d = engine.authorize_with_nad("alice", &[], &core_nads, "configure terminal");
        assert!(!d.allowed, "configure should be denied for core NAD");
    }

    #[test]
    fn nad_group_rule_skipped_for_nonmatching_nad() {
        let mut nads = HashMap::new();
        nads.insert(
            "core".into(),
            NadGroupConfig {
                cidrs: vec!["10.0.0.0/8".into()],
            },
        );
        let mut rule = make_rule(
            "deny-config-core-only",
            50,
            Effect::Deny,
            "(configure|conf).*",
        );
        rule.nad_groups = vec!["core".into()];
        let mut allow_all = make_rule("allow-all", 10, Effect::Allow, ".*");
        allow_all.nad_groups = vec![];
        let engine = make_engine_with_nad(nads, vec![rule, allow_all]);

        // Access NAD (not core) → rule skipped → allow-all fires
        let access_nads = engine.resolve_nad_groups("192.168.1.1:49");
        let d = engine.authorize_with_nad("alice", &[], &access_nads, "configure terminal");
        assert!(d.allowed, "configure should be allowed for non-core NAD");
    }

    // ==================== device_flow_exclude_users Tests ====================

    fn make_engine_with_excludes(patterns: Vec<&str>) -> PolicyEngine {
        let doc = PolicyDocument {
            default_allow: false,
            shell_start: HashMap::new(),
            shell_start_groups: HashMap::new(),
            author_service_attributes: HashMap::new(),
            device_flow_exclude_users: patterns.iter().map(|s| s.to_string()).collect(),
            nad_groups: HashMap::new(),
            enable_groups: HashMap::new(),
            ascii_prompts: None,
            ascii_user_prompts: HashMap::new(),
            ascii_password_prompts: HashMap::new(),
            ascii_port_prompts: HashMap::new(),
            ascii_remaddr_prompts: HashMap::new(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: Vec::new(),
            raw_server_msg_deny_prefixes: Vec::new(),
            raw_server_msg_user_overrides: HashMap::new(),
            ascii_messages: None,
            rules: vec![],
        };
        PolicyEngine::from_document(doc).unwrap()
    }

    #[test]
    fn exclude_exact_match() {
        let e = make_engine_with_excludes(vec!["svc-tenable"]);
        assert!(e.is_device_flow_excluded("svc-tenable"));
        assert!(!e.is_device_flow_excluded("operator"));
    }

    #[test]
    fn exclude_case_insensitive() {
        let e = make_engine_with_excludes(vec!["SVC-TENABLE"]);
        assert!(e.is_device_flow_excluded("svc-tenable"));
        assert!(e.is_device_flow_excluded("SVC-TENABLE"));
    }

    #[test]
    fn exclude_prefix_glob() {
        let e = make_engine_with_excludes(vec!["svc-*"]);
        assert!(e.is_device_flow_excluded("svc-tenable"));
        assert!(e.is_device_flow_excluded("svc-monitoring"));
        assert!(!e.is_device_flow_excluded("operator"));
        assert!(!e.is_device_flow_excluded("svc"));
    }

    #[test]
    fn exclude_suffix_glob() {
        let e = make_engine_with_excludes(vec!["*-scanner"]);
        assert!(e.is_device_flow_excluded("tenable-scanner"));
        assert!(!e.is_device_flow_excluded("operator"));
    }

    #[test]
    fn exclude_wildcard_only_matches_anything() {
        let e = make_engine_with_excludes(vec!["*"]);
        assert!(e.is_device_flow_excluded("operator"));
        assert!(e.is_device_flow_excluded("svc-tenable"));
    }

    #[test]
    fn exclude_empty_list_never_excludes() {
        let e = make_engine_with_excludes(vec![]);
        assert!(!e.is_device_flow_excluded("svc-tenable"));
        assert!(!e.is_device_flow_excluded("operator"));
    }

    #[test]
    fn glob_match_no_wildcard() {
        assert!(glob_match("alice", "alice"));
        assert!(!glob_match("alice", "bob"));
    }

    #[test]
    fn glob_match_prefix_wildcard() {
        assert!(glob_match("svc-*", "svc-tenable"));
        assert!(glob_match("svc-*", "svc-"));
        assert!(!glob_match("svc-*", "svc"));
        assert!(!glob_match("svc-*", "notasvc-thing"));
    }

    #[test]
    fn glob_match_suffix_wildcard() {
        assert!(glob_match("*-svc", "tenable-svc"));
        assert!(!glob_match("*-svc", "tenable"));
    }

    #[test]
    fn glob_match_star_alone_matches_all() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    // ==================== Enable Gating Tests ====================

    fn make_engine_with_enable(enable: HashMap<String, Vec<String>>) -> PolicyEngine {
        let doc = PolicyDocument {
            default_allow: false,
            shell_start: HashMap::new(),
            shell_start_groups: HashMap::new(),
            author_service_attributes: HashMap::new(),
            device_flow_exclude_users: vec![],
            nad_groups: HashMap::new(),
            enable_groups: enable,
            ascii_prompts: None,
            ascii_user_prompts: HashMap::new(),
            ascii_password_prompts: HashMap::new(),
            ascii_port_prompts: HashMap::new(),
            ascii_remaddr_prompts: HashMap::new(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: vec![],
            raw_server_msg_deny_prefixes: vec![],
            raw_server_msg_user_overrides: HashMap::new(),
            ascii_messages: None,
            rules: vec![],
        };
        PolicyEngine::from_document(doc).unwrap()
    }

    #[test]
    fn can_enable_empty_config_allows_any() {
        let e = make_engine_with_enable(HashMap::new());
        assert!(e.can_enable(15, &[]));
        assert!(e.can_enable(15, &["whatever".into()]));
    }

    #[test]
    fn can_enable_matching_group_at_level() {
        let mut cfg = HashMap::new();
        cfg.insert("15".into(), vec!["netops-admin".into()]);
        let e = make_engine_with_enable(cfg);
        assert!(e.can_enable(15, &["netops-admin".into()]));
        assert!(!e.can_enable(15, &["netops".into()]));
    }

    #[test]
    fn can_enable_configured_but_no_entry_denies() {
        let mut cfg = HashMap::new();
        cfg.insert("15".into(), vec!["admin".into()]);
        let e = make_engine_with_enable(cfg);
        // requesting level 7, no entry for 7, and level-15 entry doesn't apply
        // downward to a user lacking the admin group
        assert!(!e.can_enable(7, &["netops".into()]));
    }

    #[test]
    fn can_enable_hierarchical_higher_level_covers_lower() {
        let mut cfg = HashMap::new();
        cfg.insert("15".into(), vec!["admin".into()]);
        let e = make_engine_with_enable(cfg);
        // admin is cleared for 15, so may also enable to 7
        assert!(e.can_enable(7, &["admin".into()]));
        assert!(e.can_enable(15, &["admin".into()]));
    }

    #[test]
    fn can_enable_case_insensitive() {
        let mut cfg = HashMap::new();
        cfg.insert("15".into(), vec!["NetOps-Admin".into()]);
        let e = make_engine_with_enable(cfg);
        assert!(e.can_enable(15, &["netops-admin".into()]));
        assert!(e.can_enable(15, &["NETOPS-ADMIN".into()]));
    }

    #[test]
    fn compile_enable_groups_rejects_bad_level() {
        let mut cfg = HashMap::new();
        cfg.insert("99".into(), vec!["admin".into()]);
        assert!(compile_enable_groups(cfg).is_err());
        let mut cfg2 = HashMap::new();
        cfg2.insert("notanum".into(), vec!["admin".into()]);
        assert!(compile_enable_groups(cfg2).is_err());
    }
}
