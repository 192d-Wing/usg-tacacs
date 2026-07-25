// SPDX-License-Identifier: Apache-2.0
//! Fail-closed reconciliation of YAML-owned and API-owned NAD desired state.

use crate::jit_lease::NadIdentity;
use crate::nad_store::{NadAuthentication as ApiAuthentication, NadRecord};
use crate::server::normalize_ip;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use usg_tacacs_config::{Nad, NadAuthentication as YamlAuthentication};
use usg_tacacs_proto::MIN_SECRET_LEN;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReconciliationState {
    Active,
    Conflict,
    SecretUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NadReconciliationStatus {
    pub nad_id: Uuid,
    pub resource_version: i64,
    pub state: ReconciliationState,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeNadSnapshot {
    pub legacy_secrets: Arc<HashMap<IpAddr, Arc<Vec<u8>>>>,
    pub legacy_identities: Arc<HashMap<IpAddr, NadIdentity>>,
    pub tls_identities: Arc<HashMap<String, NadIdentity>>,
    pub statuses: Arc<HashMap<Uuid, NadReconciliationStatus>>,
}

#[derive(Debug, Clone)]
pub struct NadReconciler {
    secret_root: PathBuf,
}

#[derive(Default)]
struct SnapshotBuilder {
    names: HashSet<String>,
    addresses: HashSet<IpAddr>,
    certificate_identities: HashSet<String>,
    legacy_secrets: HashMap<IpAddr, Arc<Vec<u8>>>,
    legacy_identities: HashMap<IpAddr, NadIdentity>,
    tls_identities: HashMap<String, NadIdentity>,
    statuses: HashMap<Uuid, NadReconciliationStatus>,
}

impl NadReconciler {
    pub fn new(secret_root: PathBuf) -> Self {
        Self { secret_root }
    }

    pub fn reconcile(&self, yaml: &[Nad], api: &[NadRecord]) -> RuntimeNadSnapshot {
        let mut builder = SnapshotBuilder::default();
        for nad in yaml {
            builder.add_yaml(nad);
        }
        for nad in api {
            builder.add_api(nad, &self.secret_root);
        }
        builder.finish()
    }
}

impl SnapshotBuilder {
    fn add_yaml(&mut self, nad: &Nad) {
        let address = normalize_ip(nad.source_address);
        self.names.insert(nad.name.clone());
        self.addresses.insert(address);
        let Ok(identity) = NadIdentity::parse(&nad.name) else {
            return;
        };
        match &nad.authentication {
            YamlAuthentication::Legacy { secret_file } => {
                if let Ok(secret) = read_secret(secret_file) {
                    self.legacy_secrets.insert(address, Arc::new(secret));
                    self.legacy_identities.insert(address, identity);
                }
            }
            YamlAuthentication::Tls {
                certificate_identities,
            } => self.add_tls_identities(identity, certificate_identities),
        }
    }

    fn add_api(&mut self, nad: &NadRecord, secret_root: &Path) {
        let address = normalize_ip(nad.source_address);
        if self.names.contains(&nad.name) || self.addresses.contains(&address) {
            self.record_status(nad, ReconciliationState::Conflict, "yaml_or_api_conflict");
            return;
        }
        let Ok(identity) = NadIdentity::parse(&nad.name) else {
            self.record_status(nad, ReconciliationState::Conflict, "invalid_nad_identity");
            return;
        };
        if self.authentication_conflicts(&nad.authentication) {
            self.record_status(
                nad,
                ReconciliationState::Conflict,
                "certificate_identity_conflict",
            );
            return;
        }
        if !self.activate_api(nad, identity, address, secret_root) {
            return;
        }
        self.names.insert(nad.name.clone());
        self.addresses.insert(address);
        self.record_status(nad, ReconciliationState::Active, None);
    }

    fn authentication_conflicts(&self, authentication: &ApiAuthentication) -> bool {
        let ApiAuthentication::Tls {
            certificate_identities,
        } = authentication
        else {
            return false;
        };
        certificate_identities
            .iter()
            .any(|value| self.certificate_identities.contains(value))
    }

    fn activate_api(
        &mut self,
        nad: &NadRecord,
        identity: NadIdentity,
        address: IpAddr,
        secret_root: &Path,
    ) -> bool {
        match &nad.authentication {
            ApiAuthentication::Legacy { secret_ref } => {
                let Some(secret) = resolve_api_secret(secret_root, secret_ref) else {
                    self.record_status(
                        nad,
                        ReconciliationState::SecretUnavailable,
                        "secret_unavailable",
                    );
                    return false;
                };
                self.legacy_secrets.insert(address, Arc::new(secret));
                self.legacy_identities.insert(address, identity);
            }
            ApiAuthentication::Tls {
                certificate_identities,
            } => self.add_tls_identities(identity, certificate_identities),
        }
        true
    }

    fn add_tls_identities(&mut self, identity: NadIdentity, certificates: &[String]) {
        for certificate in certificates {
            self.certificate_identities.insert(certificate.clone());
            self.tls_identities
                .insert(certificate.clone(), identity.clone());
        }
    }

    fn record_status(
        &mut self,
        nad: &NadRecord,
        state: ReconciliationState,
        reason: impl Into<Option<&'static str>>,
    ) {
        self.statuses.insert(
            nad.nad_id,
            NadReconciliationStatus {
                nad_id: nad.nad_id,
                resource_version: nad.resource_version,
                state,
                reason: reason.into(),
            },
        );
    }

    fn finish(self) -> RuntimeNadSnapshot {
        RuntimeNadSnapshot {
            legacy_secrets: Arc::new(self.legacy_secrets),
            legacy_identities: Arc::new(self.legacy_identities),
            tls_identities: Arc::new(self.tls_identities),
            statuses: Arc::new(self.statuses),
        }
    }
}

fn resolve_api_secret(root: &Path, secret_ref: &str) -> Option<Vec<u8>> {
    let path = Path::new(secret_ref);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || !path.starts_with(root)
    {
        return None;
    }
    let canonical_root = root.canonicalize().ok()?;
    let canonical_path = path.canonicalize().ok()?;
    if !canonical_path.starts_with(canonical_root) {
        return None;
    }
    read_secret(&canonical_path).ok()
}

fn read_secret(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut secret = std::fs::read(path)?;
    while secret.last().is_some_and(u8::is_ascii_whitespace) {
        secret.pop();
    }
    if secret.len() < MIN_SECRET_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TACACS secret is too short",
        ));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use time::OffsetDateTime;

    fn api_nad(name: &str, address: &str, authentication: ApiAuthentication) -> NadRecord {
        NadRecord {
            nad_id: Uuid::new_v4(),
            name: name.to_owned(),
            description: None,
            source_address: address.parse().unwrap(),
            authentication,
            ownership: "api".to_owned(),
            resource_version: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            created_by: "test".to_owned(),
            updated_at: OffsetDateTime::UNIX_EPOCH,
            updated_by: "test".to_owned(),
            deleted_at: None,
            deleted_by: None,
        }
    }

    fn yaml_tls(name: &str, address: &str, certificate: &str) -> Nad {
        Nad {
            name: name.to_owned(),
            source_address: address.parse().unwrap(),
            description: None,
            authentication: YamlAuthentication::Tls {
                certificate_identities: vec![certificate.to_owned()],
            },
        }
    }

    #[test]
    fn yaml_baseline_wins_cross_source_conflicts() {
        let yaml = yaml_tls("oopl-an-001", "192.0.2.10", "yaml.example.mil");
        let api = api_nad(
            "oopl-an-001",
            "192.0.2.11",
            ApiAuthentication::Tls {
                certificate_identities: vec!["api.example.mil".to_owned()],
            },
        );
        let snapshot = NadReconciler::new(PathBuf::from("/run/secrets/nads"))
            .reconcile(&[yaml], std::slice::from_ref(&api));
        assert_eq!(
            snapshot.statuses[&api.nad_id].state,
            ReconciliationState::Conflict
        );
        assert!(snapshot.tls_identities.contains_key("yaml.example.mil"));
        assert!(!snapshot.tls_identities.contains_key("api.example.mil"));
    }

    #[test]
    fn unresolved_and_escaping_secret_references_fail_closed() {
        let directory = TempDir::new().unwrap();
        let outside = directory.path().parent().unwrap().join("outside-secret");
        fs::write(&outside, "long-enough-secret").unwrap();
        let api = api_nad(
            "oopl-an-001",
            "192.0.2.10",
            ApiAuthentication::Legacy {
                secret_ref: outside.display().to_string(),
            },
        );
        let snapshot = NadReconciler::new(directory.path().to_path_buf())
            .reconcile(&[], std::slice::from_ref(&api));
        assert_eq!(
            snapshot.statuses[&api.nad_id].state,
            ReconciliationState::SecretUnavailable
        );
        assert!(snapshot.legacy_secrets.is_empty());
        fs::remove_file(outside).unwrap();
    }

    #[test]
    fn valid_api_secret_activates_legacy_nad() {
        let directory = TempDir::new().unwrap();
        let secret_path = directory.path().join("oopl-an-001");
        fs::write(&secret_path, "unique-shared-secret\n").unwrap();
        let api = api_nad(
            "oopl-an-001",
            "192.0.2.10",
            ApiAuthentication::Legacy {
                secret_ref: secret_path.display().to_string(),
            },
        );
        let snapshot = NadReconciler::new(directory.path().to_path_buf())
            .reconcile(&[], std::slice::from_ref(&api));
        assert_eq!(
            snapshot.statuses[&api.nad_id].state,
            ReconciliationState::Active
        );
        assert_eq!(
            snapshot.legacy_secrets[&api.source_address].as_slice(),
            b"unique-shared-secret"
        );
        assert_eq!(
            snapshot.legacy_identities[&api.source_address].as_str(),
            api.name
        );
    }

    #[test]
    fn certificate_identity_conflicts_fail_closed() {
        let yaml = yaml_tls("oopl-an-001", "192.0.2.10", "router.example.mil");
        let api = api_nad(
            "oopl-an-002",
            "192.0.2.11",
            ApiAuthentication::Tls {
                certificate_identities: vec!["router.example.mil".to_owned()],
            },
        );
        let snapshot = NadReconciler::new(PathBuf::from("/run/secrets/nads"))
            .reconcile(&[yaml], std::slice::from_ref(&api));
        assert_eq!(
            snapshot.statuses[&api.nad_id].state,
            ReconciliationState::Conflict
        );
    }
}
