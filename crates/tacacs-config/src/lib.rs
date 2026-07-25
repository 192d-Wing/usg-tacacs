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
    pub listeners: Listeners,
    #[serde(default)]
    pub nads: Vec<Nad>,
    pub authorization: Authorization,
    pub management: Management,
    pub audit: Audit,
    #[serde(default)]
    pub jit: Option<Jit>,
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
        if self.spec.listeners.legacy.is_none() && self.spec.listeners.tls.is_none() {
            bail!("at least one TACACS listener must be configured");
        }
        validate_tls("spec.management.listener", &self.spec.management.listener)?;
        if let Some(tls) = &self.spec.listeners.tls {
            validate_tls("spec.listeners.tls", tls)?;
        }
        validate_nads(&self.spec.nads)?;
        validate_rbac(&self.spec.management.rbac)?;
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
    }
    Ok(())
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
}
