// SPDX-License-Identifier: Apache-2.0
//! Typed declarative YAML server configuration and semantic validation.

use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

pub const API_VERSION: &str = "tacacs.usg.mil/v1alpha1";
pub const KIND: &str = "TacacsServer";
pub const MAX_JIT_TTL_SECONDS: u64 = 900;

/// Stable, service-scoped authorization actions for the HTTP APIs.
/// Permissions are an exact allow-list so new endpoints require explicit grants.
pub mod management_actions {
    pub const LIST_NAD_AUDIT_EVENTS: &str = "tacacs:ListNadAuditEvents";
    pub const VERIFY_NAD_AUDIT_EVENTS: &str = "tacacs:VerifyNadAuditEvents";
    pub const LIST_NADS: &str = "tacacs:ListNads";
    pub const CREATE_NAD: &str = "tacacs:CreateNad";
    pub const LIST_NAD_INVENTORY: &str = "tacacs:ListNadInventory";
    pub const GET_NAD_RECONCILIATION: &str = "tacacs:GetNadReconciliation";
    pub const GET_NAD: &str = "tacacs:GetNad";
    pub const UPDATE_NAD: &str = "tacacs:UpdateNad";
    pub const DELETE_NAD: &str = "tacacs:DeleteNad";
    pub const GET_STATUS: &str = "tacacs:GetStatus";
    pub const LIST_SESSIONS: &str = "tacacs:ListSessions";
    pub const DELETE_SESSION: &str = "tacacs:DeleteSession";
    pub const GET_POLICY: &str = "tacacs:GetPolicy";
    pub const REPLACE_POLICY: &str = "tacacs:ReplacePolicy";
    pub const RELOAD_POLICY: &str = "tacacs:ReloadPolicy";
    pub const GET_OPERATION: &str = "tacacs:GetOperation";
    pub const GET_RUNTIME_CONFIG: &str = "tacacs:GetRuntimeConfig";
    pub const GET_EFFECTIVE_CONFIG: &str = "tacacs:GetEffectiveConfig";
    pub const GET_CONFIG_SCHEMA: &str = "tacacs:GetConfigSchema";
    pub const VALIDATE_CONFIG: &str = "tacacs:ValidateConfig";
    pub const GET_METRICS: &str = "tacacs:GetMetrics";
    pub const CREATE_JIT_LEASE: &str = "tacacs:CreateJitLease";
    pub const GET_JIT_LEASE: &str = "tacacs:GetJitLease";
    pub const REVOKE_JIT_LEASE: &str = "tacacs:RevokeJitLease";
    pub const GET_MANAGEMENT_OPEN_API: &str = "tacacs:GetManagementOpenApi";
    pub const GET_JIT_OPEN_API: &str = "tacacs:GetJitOpenApi";

    pub const ALL: &[&str] = &[
        LIST_NAD_AUDIT_EVENTS,
        VERIFY_NAD_AUDIT_EVENTS,
        LIST_NADS,
        CREATE_NAD,
        LIST_NAD_INVENTORY,
        GET_NAD_RECONCILIATION,
        GET_NAD,
        UPDATE_NAD,
        DELETE_NAD,
        GET_STATUS,
        LIST_SESSIONS,
        DELETE_SESSION,
        GET_POLICY,
        REPLACE_POLICY,
        RELOAD_POLICY,
        GET_OPERATION,
        GET_RUNTIME_CONFIG,
        GET_EFFECTIVE_CONFIG,
        GET_CONFIG_SCHEMA,
        VALIDATE_CONFIG,
        GET_METRICS,
        CREATE_JIT_LEASE,
        GET_JIT_LEASE,
        REVOKE_JIT_LEASE,
        GET_MANAGEMENT_OPEN_API,
        GET_JIT_OPEN_API,
    ];

    pub fn is_supported(value: &str) -> bool {
        ALL.contains(&value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerConfiguration {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: ServerSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerSpec {
    pub role: ServerRole,
    pub listeners: Listeners,
    #[serde(default)]
    pub nads: Vec<Nad>,
    pub authorization: Authorization,
    #[serde(default)]
    pub management: Option<Management>,
    pub audit: Audit,
    #[serde(default)]
    pub jit: Option<Jit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ServerRole {
    Management,
    Legacy,
    Tls,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Listeners {
    #[serde(default)]
    pub legacy: Option<SocketAddr>,
    #[serde(default)]
    pub tls: Option<TlsListener>,
    pub health: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsListener {
    pub address: SocketAddr,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub client_ca_file: PathBuf,
    #[serde(default = "tls_1_3")]
    pub minimum_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
// `flatten` cannot be combined with `deny_unknown_fields`; the tagged
// authentication enum performs strict validation of its own fields.
#[serde(rename_all = "camelCase")]
pub struct Nad {
    pub name: String,
    pub source_address: IpAddr,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(flatten)]
    pub authentication: NadAuthentication,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum NadAuthentication {
    Legacy {
        #[serde(rename = "secretFile")]
        secret_file: PathBuf,
    },
    Tls {
        #[serde(rename = "certificateIdentities")]
        certificate_identities: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorization {
    #[serde(default)]
    pub default_allow: bool,
    #[serde(default)]
    pub rules: Vec<AuthorizationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationRule {
    pub id: String,
    pub priority: i32,
    pub effect: RuleEffect,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub nad_groups: Vec<String>,
    #[serde(default)]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Management {
    pub listener: TlsListener,
    pub rbac: Rbac,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rbac {
    pub roles: BTreeMap<String, Role>,
    pub subjects: Vec<SubjectBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Role {
    pub permissions: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectBinding {
    pub certificate_identity: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Audit {
    pub hmac_key_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Jit {
    pub store_url: String,
    pub store_password_file: PathBuf,
    pub store_ca_file: PathBuf,
    pub verifier_key_file: PathBuf,
    #[serde(default = "max_jit_ttl")]
    pub maximum_ttl_seconds: u64,
}

fn tls_1_3() -> String {
    "1.3".to_string()
}

const fn max_jit_ttl() -> u64 {
    MAX_JIT_TTL_SECONDS
}

impl ServerConfiguration {
    pub fn from_path(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        yaml_serde::from_str(&contents)
            .with_context(|| format!("failed to parse typed YAML from {}", path.display()))
    }

    pub fn validate(&self, check_files: bool) -> Result<()> {
        if self.api_version != API_VERSION {
            bail!("apiVersion must be {API_VERSION}");
        }
        if self.kind != KIND {
            bail!("kind must be {KIND}");
        }
        if self.metadata.name.trim().is_empty() {
            bail!("metadata.name must not be empty");
        }
        validate_role(&self.spec)?;
        if let Some(management) = &self.spec.management {
            validate_tls("spec.management.listener", &management.listener)?;
            validate_rbac(&management.rbac)?;
        }
        if let Some(tls) = &self.spec.listeners.tls {
            validate_tls("spec.listeners.tls", tls)?;
        }
        validate_nads(&self.spec.nads)?;
        validate_unique_rule_ids(&self.spec.authorization.rules)?;
        if let Some(jit) = &self.spec.jit
            && !(1..=MAX_JIT_TTL_SECONDS).contains(&jit.maximum_ttl_seconds)
        {
            bail!("spec.jit.maximumTtlSeconds must be between 1 and 900");
        }
        for (field, path) in self.secret_paths() {
            if !is_config_absolute(path) {
                bail!("{field} must be an absolute path");
            }
            if check_files && !path.is_file() {
                bail!(
                    "{field} does not exist or is not a file: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    fn secret_paths(&self) -> Vec<(&'static str, &Path)> {
        let mut paths = vec![(
            "spec.audit.hmacKeyFile",
            self.spec.audit.hmac_key_file.as_path(),
        )];
        for nad in &self.spec.nads {
            if let NadAuthentication::Legacy { secret_file } = &nad.authentication {
                paths.push(("spec.nads[].secretFile", secret_file.as_path()));
            }
        }
        if let Some(jit) = &self.spec.jit {
            paths.extend([
                (
                    "spec.jit.storePasswordFile",
                    jit.store_password_file.as_path(),
                ),
                ("spec.jit.storeCaFile", jit.store_ca_file.as_path()),
                ("spec.jit.verifierKeyFile", jit.verifier_key_file.as_path()),
            ]);
        }
        paths
    }
}

fn validate_role(spec: &ServerSpec) -> Result<()> {
    let legacy = spec.listeners.legacy.is_some();
    let tls = spec.listeners.tls.is_some();
    let management = spec.management.is_some();
    let valid = match spec.role {
        ServerRole::Management => management && !legacy && !tls,
        ServerRole::Legacy => legacy && !tls && !management,
        ServerRole::Tls => tls && !legacy && !management,
    };
    if !valid {
        bail!("spec.role must exclusively match its listener: management, legacy, or tls");
    }
    Ok(())
}

fn validate_tls(field: &str, listener: &TlsListener) -> Result<()> {
    if listener.minimum_version != "1.3" {
        bail!("{field}.minimumVersion must be \"1.3\"");
    }
    for (name, path) in [
        ("certificateFile", &listener.certificate_file),
        ("privateKeyFile", &listener.private_key_file),
        ("clientCaFile", &listener.client_ca_file),
    ] {
        if !is_config_absolute(path) {
            bail!("{field}.{name} must be an absolute path");
        }
    }
    Ok(())
}

fn is_config_absolute(path: &Path) -> bool {
    path.is_absolute() || path.to_string_lossy().starts_with('/')
}

fn validate_nads(nads: &[Nad]) -> Result<()> {
    let mut names = HashSet::new();
    let mut addresses = HashSet::new();
    for nad in nads {
        if !names.insert(&nad.name) {
            bail!("duplicate NAD name: {}", nad.name);
        }
        if !addresses.insert(nad.source_address) {
            bail!("duplicate NAD sourceAddress: {}", nad.source_address);
        }
        if let NadAuthentication::Tls {
            certificate_identities,
        } = &nad.authentication
            && certificate_identities.is_empty()
        {
            bail!(
                "TLS NAD {} requires at least one certificateIdentity",
                nad.name
            );
        }
    }
    Ok(())
}

fn validate_rbac(rbac: &Rbac) -> Result<()> {
    let mut identities = HashSet::new();
    for subject in &rbac.subjects {
        validate_certificate_identity(&subject.certificate_identity)?;
        if !rbac.roles.contains_key(&subject.role) {
            bail!(
                "RBAC subject {} references undefined role {}",
                subject.certificate_identity,
                subject.role
            );
        }
        if !identities.insert(&subject.certificate_identity) {
            bail!(
                "duplicate RBAC certificateIdentity: {}",
                subject.certificate_identity
            );
        }
    }
    for (name, role) in &rbac.roles {
        if role.permissions.is_empty() {
            bail!("RBAC role {name} must contain at least one permission");
        }
        let mut permissions = HashSet::new();
        for permission in &role.permissions {
            if !management_actions::is_supported(permission) {
                bail!("RBAC role {name} contains unsupported permission: {permission}");
            }
            if !permissions.insert(permission) {
                bail!("RBAC role {name} contains duplicate permission: {permission}");
            }
        }
    }
    Ok(())
}

fn validate_certificate_identity(identity: &str) -> Result<()> {
    let valid = if let Some(value) = identity.strip_prefix("cn:") {
        valid_identity_value(value, 512)
    } else if let Some(value) = identity.strip_prefix("dns:") {
        valid_dns_identity(value)
    } else if let Some(value) = identity.strip_prefix("email:") {
        value == value.to_ascii_lowercase()
            && value.contains('@')
            && valid_identity_value(value, 512)
    } else if let Some(value) = identity.strip_prefix("uri:") {
        value.contains(':') && valid_identity_value(value, 1024)
    } else {
        false
    };
    if !valid {
        bail!("RBAC certificateIdentity must be a valid typed cn:, dns:, email:, or uri: identity");
    }
    Ok(())
}

fn valid_identity_value(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn valid_dns_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
}

fn validate_unique_rule_ids(rules: &[AuthorizationRule]) -> Result<()> {
    let mut ids = HashSet::new();
    for rule in rules {
        if !ids.insert(&rule.id) {
            bail!("duplicate authorization rule id: {}", rule.id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_yaml_fields() {
        let result = yaml_serde::from_str::<ServerConfiguration>(
            "apiVersion: tacacs.usg.mil/v1alpha1\nkind: TacacsServer\nunknown: true\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn rbac_certificate_identities_are_typed_and_canonical() {
        assert!(validate_certificate_identity("cn:tacacs-admin.example.mil").is_ok());
        assert!(validate_certificate_identity("dns:tacacs-admin.example.mil").is_ok());
        assert!(validate_certificate_identity("uri:spiffe://example.mil/tacacs/admin").is_ok());
        assert!(validate_certificate_identity("tacacs-admin.example.mil").is_err());
        assert!(validate_certificate_identity("dns:TACACS-ADMIN.example.mil").is_err());
    }

    fn management_example() -> ServerConfiguration {
        yaml_serde::from_str(include_str!("../../../docs/config/server.example.yaml")).unwrap()
    }

    #[test]
    fn runtime_roles_require_exclusive_listeners() {
        let management = management_example();
        assert!(management.validate(false).is_ok());

        let mut legacy = management.clone();
        legacy.spec.role = ServerRole::Legacy;
        legacy.spec.listeners.legacy = Some("0.0.0.0:49".parse().unwrap());
        legacy.spec.management = None;
        assert!(legacy.validate(false).is_ok());

        let mut tls = management.clone();
        tls.spec.role = ServerRole::Tls;
        tls.spec.listeners.tls = Some(management.spec.management.unwrap().listener);
        tls.spec.management = None;
        assert!(tls.validate(false).is_ok());
    }

    #[test]
    fn runtime_roles_reject_combined_data_planes() {
        let mut config = management_example();
        config.spec.role = ServerRole::Legacy;
        config.spec.listeners.legacy = Some("0.0.0.0:49".parse().unwrap());
        config.spec.listeners.tls = Some(config.spec.management.take().unwrap().listener);
        assert!(config.validate(false).is_err());
    }

    #[test]
    fn rbac_rejects_wildcard_and_unknown_actions() {
        for permission in ["tacacs:*", "tacacs:GteNad", "read:nads"] {
            let mut config = management_example();
            config
                .spec
                .management
                .as_mut()
                .unwrap()
                .rbac
                .roles
                .get_mut("viewer")
                .unwrap()
                .permissions = vec![permission.to_owned()];
            assert!(config.validate(false).is_err(), "accepted {permission}");
        }
    }

    #[test]
    fn rbac_rejects_duplicate_actions() {
        let mut config = management_example();
        let viewer = config
            .spec
            .management
            .as_mut()
            .unwrap()
            .rbac
            .roles
            .get_mut("viewer")
            .unwrap();
        viewer.permissions = vec![
            management_actions::GET_STATUS.to_owned(),
            management_actions::GET_STATUS.to_owned(),
        ];
        assert!(config.validate(false).is_err());
    }
}
