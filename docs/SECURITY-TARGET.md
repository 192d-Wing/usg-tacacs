# Security Target for usg-tacacs TACACS+ Server

<!-- NIST SP 800-53 Rev. 5 Security Controls
     Control Implementation Matrix

     | Control | Family | Status | Validated | Primary Functions |
     |---------|--------|--------|-----------|-------------------|
     | SA-4    | System and Services Acquisition | Documented | 2026-01-31 | Security requirements |
     | SA-5    | System Documentation | Documented | 2026-01-31 | Security target |
     | SA-11   | Developer Testing | Documented | 2026-01-31 | Security testing |
-->

**Security Target Version:** 1.0
**Product:** usg-tacacs TACACS+ Server v0.77.1
**Protection Profile:** NDcPP v4.0 + PP-Module for Authentication Servers v1.0
**Certification:** NIAP Common Criteria EAL2+ (NDcPP v4.0)
**Date:** 2026-01-31

---

## Table of Contents

1. [ST Introduction](#st-introduction)
2. [Conformance Claims](#conformance-claims)
3. [Security Problem Definition](#security-problem-definition)
4. [Security Objectives](#security-objectives)
5. [Extended Components Definition](#extended-components-definition)
6. [Security Requirements](#security-requirements)
7. [TOE Summary Specification](#toe-summary-specification)

---

## 1. ST Introduction

### 1.1 ST Reference

| Field | Value |
|-------|-------|
| ST Title | Security Target for usg-tacacs TACACS+ Server |
| ST Version | 1.0 |
| ST Date | 2026-01-31 |
| ST Author | usg-tacacs Development Team |
| TOE Reference | usg-tacacs v0.77.1 |

### 1.2 TOE Reference

**TOE Identification:**
- Product Name: usg-tacacs TACACS+ Server
- Version: 0.77.1
- Developer: usg-tacacs Project
- Type: Network Device Authentication Server

**TOE Overview:**

The Target of Evaluation (TOE) is a TACACS+ authentication, authorization, and accounting (AAA) server that provides centralized access control for network infrastructure devices. The TOE implements the TACACS+ protocol (RFC 8907) with TLS 1.3 encryption for secure communication between network access devices (NADs) and the authentication server.

### 1.3 TOE Description

#### 1.3.1 TOE Type

The TOE is a software application that functions as:
- Network Device (NDcPP v4.0)
- Authentication Server (PP-Module for Authentication Servers v1.0)

#### 1.3.2 Major Security Features

1. **Cryptographic Protection**
   - TLS 1.3 exclusive (no fallback to older versions)
   - Mutual TLS (mTLS) for device authentication
   - Argon2id password hashing
   - MD5 body obfuscation (legacy protocol compatibility)

2. **Authentication Services**
   - PAP (Password Authentication Protocol)
   - CHAP (Challenge-Handshake Authentication Protocol)
   - ASCII interactive authentication
   - LDAPS integration for enterprise directory services

3. **Authorization Services**
   - Role-based access control (RBAC)
   - Command authorization via policy engine
   - Privilege level enforcement
   - Server message filtering

4. **Accounting Services**
   - Session start/stop/update records
   - Task ID tracking per RFC 8907
   - Comprehensive audit logging

5. **Security Management**
   - RESTful management API with mTLS
   - Policy hot-reload
   - Session monitoring and termination
   - Prometheus metrics

### 1.4 TOE Usage

#### 1.4.1 Intended Use

The TOE is intended for deployment in enterprise and government networks to:
- Centralize authentication for routers, switches, and firewalls
- Enforce command authorization policies
- Provide detailed accounting records for compliance
- Replace legacy TACACS+ servers with modern security controls

#### 1.4.2 Deployment Architecture

```
┌─────────────────┐
│  Network Admin  │
└────────┬────────┘
         │ HTTPS (mTLS)
         ▼
┌─────────────────────────┐
│   Management API        │
│  (Session Control)      │
└─────────────────────────┘
         │
         ▼
┌─────────────────────────┐       ┌──────────────┐
│   usg-tacacs Server     │◄─────►│ LDAP Server  │
│   (TOE)                 │ LDAPS │              │
└─────────────────────────┘       └──────────────┘
         ▲
         │ TACACS+/TLS 1.3
         │
    ┌────┴────┬──────────┬──────────┐
    │         │          │          │
┌───▼───┐ ┌──▼───┐  ┌───▼───┐  ┌──▼───┐
│Router │ │Switch│  │Firewall│  │...   │
└───────┘ └──────┘  └───────┘  └──────┘
  Network Access Devices (NADs)
```

### 1.5 TOE Scope

#### 1.5.1 Physical Boundary

The TOE consists of:
- Compiled Rust binary (`tacacs-server`)
- Configuration files (policy, RBAC, secrets)
- TLS certificates and keys

**Excluded from TOE:**
- Operating system (Linux/Unix)
- Hardware platform
- Network infrastructure
- LDAP directory services
- Syslog/audit storage systems

#### 1.5.2 Logical Boundary

**Included:**
- TACACS+ protocol implementation (RFC 8907)
- TLS 1.3 cryptographic channel
- Authentication engine (PAP, CHAP, ASCII, LDAP)
- Authorization policy engine
- Accounting record generation
- Session management
- Audit logging
- Management API

**Excluded:**
- Network packet routing
- File system encryption
- Database management
- Web browser interface

---

## 2. Conformance Claims

### 2.1 CC Conformance Claim

This Security Target claims conformance to:

- **Common Criteria for Information Technology Security Evaluation**
  - Version: 3.1 Revision 5 (CC:2022)
  - Conformance: Part 2 extended, Part 3 conformant

### 2.2 PP Claim

This Security Target claims exact conformance to:

- **collaborative Protection Profile for Network Devices (NDcPP)**
  - Version: 4.0
  - Date: November 25, 2025
  - Claimed with all base requirements

- **PP-Module for Authentication Servers**
  - Version: 1.0
  - Date: January 25, 2023
  - Claimed in conjunction with NDcPP v4.0

### 2.3 Package Claim

- **Assurance Package:** EAL2 augmented with:
  - ALC_FLR.1 (Basic flaw remediation)

### 2.4 Conformance Rationale

The TOE functions as both:
1. **Network Device** - Provides AAA services over network connections with cryptographic protection
2. **Authentication Server** - Authenticates claimants (network administrators) and provides identity assertions to relying parties (network devices)

The TACACS+ protocol serves as a "direct federation protocol" analogous to RADIUS/DIAMETER specified in the PP-Module for Authentication Servers.

---

## 3. Security Problem Definition

### 3.1 Threats

The TOE addresses the following threats defined in NDcPP v4.0:

#### T.NETWORK_ATTACK

**Threat:** An attacker is positioned on a communications channel or elsewhere on the network infrastructure and attempts to compromise the TOE through network-based attack vectors.

**TOE Assets Threatened:**
- User credentials
- Session data
- Authorization policies
- Accounting records

**Addressed by:** FCS (cryptography), FIA (authentication), FTP (trusted paths)

#### T.NETWORK_EAVESDROP

**Threat:** An attacker is positioned on a communications channel and attempts to read data exchanged between the TOE and endpoints.

**TOE Assets Threatened:**
- TACACS+ packets (authentication credentials, commands)
- LDAP bind credentials
- Session identifiers

**Addressed by:** FCS_TLSC_EXT.1, SC-8 (TLS 1.3 encryption)

#### T.LOCAL_ATTACK

**Threat:** An attacker on a locally connected endpoint attempts to compromise the TOE.

**TOE Assets Threatened:**
- Configuration files
- Secret keys
- Audit logs

**Addressed by:** FPT_APW_EXT.1, FCS_STG_EXT.1 (key protection)

#### T.LIMITED_PHYSICAL_ACCESS

**Threat:** An attacker with physical access to the TOE attempts to extract sensitive data from non-volatile storage.

**TOE Assets Threatened:**
- Persistent private keys
- Shared secrets
- Password hashes

**Addressed by:** FCS_STG_EXT.1 (encrypted key storage), FPT_SKP_EXT.1

#### T.UNAUTHORIZED_ADMINISTRATOR_ACCESS

**Threat:** An unauthorized user attempts to gain administrator access to the TOE.

**TOE Assets Threatened:**
- Management API
- Configuration modification
- Session control

**Addressed by:** FIA (authentication), FMT_SMR.2 (roles), FTP_TRP.1 (mTLS)

#### T.WEAK_CRYPTOGRAPHY

**Threat:** An attacker exploits weak cryptographic algorithms or implementations to compromise confidentiality or integrity.

**TOE Assets Threatened:**
- TLS sessions
- Password hashes
- Key material

**Addressed by:** FCS_COP.1, FCS_CKM (modern algorithms only)

### 3.2 Organizational Security Policies

#### P.STRONG_CRYPTO

**Policy:** The TOE shall use strong cryptographic algorithms for all security functions.

**Rationale:** Government and enterprise policies mandate FIPS-validated cryptography.

**Addressed by:** FCS (Cryptographic Support family)

#### P.AUDIT_RECORDS

**Policy:** The TOE shall generate comprehensive audit records for security-relevant events.

**Rationale:** Compliance requirements (e.g., PCI-DSS, NIST SP 800-53) mandate audit trails.

**Addressed by:** FAU (Audit family)

#### P.MANAGE_ACCESS

**Policy:** The TOE shall provide mechanisms to manage and control access to security functions.

**Rationale:** Administrative access must be restricted to authorized personnel.

**Addressed by:** FMT (Security Management family)

### 3.3 Assumptions

#### A.PLATFORM

**Assumption:** The TOE is deployed on a trusted operating system platform that is properly configured and maintained.

**Rationale:** The TOE relies on OS-provided services (filesystem, network stack, process isolation).

#### A.PHYSICAL

**Assumption:** The TOE is physically protected from unauthorized access.

**Rationale:** Physical security controls are outside the TOE boundary.

#### A.TRUSTED_ADMIN

**Assumption:** Authorized administrators are trusted to follow security procedures and not intentionally compromise the TOE.

**Rationale:** Insider threat is addressed through organizational controls.

#### A.NETWORK

**Assumption:** The network infrastructure provides basic connectivity and is protected by perimeter security controls (firewalls, IDS).

**Rationale:** Network-level DDoS protection is outside TOE scope.

#### A.TIME

**Assumption:** A reliable time source (NTP) is available to the TOE for timestamp generation.

**Rationale:** Required for FPT_STM_EXT.1 (reliable timestamps).

---

## 4. Security Objectives

### 4.1 Security Objectives for the TOE

#### O.PROTECTED_COMMUNICATIONS

**Objective:** The TOE protects network traffic from disclosure and modification using cryptographic mechanisms.

**Rationale:** Addresses T.NETWORK_EAVESDROP and T.NETWORK_ATTACK.

**Satisfied by:**
- FCS_TLSC_EXT.1 (TLS client)
- FCS_TLSS_EXT.1 (TLS server)
- FTP_ITC.1 (trusted channels)

#### O.STRONG_CRYPTO

**Objective:** The TOE uses FIPS-validated cryptographic algorithms and strong key sizes.

**Rationale:** Addresses T.WEAK_CRYPTOGRAPHY and P.STRONG_CRYPTO.

**Satisfied by:**
- FCS_CKM.1/2/4 (key management)
- FCS_COP.1 (cryptographic operations)
- FCS_RBG_EXT.1 (random bit generation)

#### O.AUTHENTICATION

**Objective:** The TOE authenticates users and devices before granting access.

**Rationale:** Addresses T.UNAUTHORIZED_ADMINISTRATOR_ACCESS.

**Satisfied by:**
- FIA_UAU_EXT.2 (password authentication)
- FIA_AFL.1 (authentication failure handling)
- FIA_X509_EXT.1 (certificate validation)

#### O.AUTHORIZATION

**Objective:** The TOE enforces access control policies for command authorization.

**Rationale:** Addresses P.MANAGE_ACCESS.

**Satisfied by:**
- FMT_SMF.1 (management functions)
- FMT_SMR.2 (security roles)
- Policy engine implementation

#### O.ACCOUNTABILITY

**Objective:** The TOE generates comprehensive audit records for security-relevant events.

**Rationale:** Addresses P.AUDIT_RECORDS.

**Satisfied by:**
- FAU_GEN.1 (audit generation)
- FAU_GEN.2 (user identity association)
- FAU_STG_EXT.1 (protected audit storage)

#### O.MANAGEMENT

**Objective:** The TOE provides secure management interfaces with role-based access control.

**Rationale:** Addresses P.MANAGE_ACCESS.

**Satisfied by:**
- FMT_MOF.1 (management of security functions)
- FMT_MTD.1 (TSF data management)
- FTP_TRP.1 (trusted path for administrators)

#### O.INTEGRITY

**Objective:** The TOE maintains the integrity of its security functions and data.

**Rationale:** Addresses T.LOCAL_ATTACK.

**Satisfied by:**
- FPT_TST_EXT.1 (TSF testing)
- FPT_TUD_EXT.1 (trusted update)
- FPT_STM_EXT.1 (reliable timestamps)

#### O.PROTECTED_STORAGE

**Objective:** The TOE protects sensitive data at rest.

**Rationale:** Addresses T.LIMITED_PHYSICAL_ACCESS.

**Satisfied by:**
- FCS_STG_EXT.1 (cryptographic key storage)
- FPT_SKP_EXT.1 (protection of TSF data)
- FPT_APW_EXT.1 (administrator password protection)

### 4.2 Security Objectives for the Operational Environment

#### OE.PLATFORM

**Objective:** The TOE execution platform provides process isolation, filesystem access controls, and network stack services.

**Rationale:** Supports A.PLATFORM assumption.

#### OE.PHYSICAL

**Objective:** Physical security controls prevent unauthorized access to the TOE hardware.

**Rationale:** Supports A.PHYSICAL assumption.

#### OE.ADMIN

**Objective:** Administrators are properly trained and follow secure operational procedures.

**Rationale:** Supports A.TRUSTED_ADMIN assumption.

#### OE.TIME

**Objective:** A reliable time source (NTP server) is available and configured.

**Rationale:** Supports A.TIME assumption for FPT_STM_EXT.1.

#### OE.UPDATES

**Objective:** Security updates are applied promptly when available.

**Rationale:** Supports vulnerability remediation.

---

## 5. Extended Components Definition

This Security Target claims extended components from NDcPP v4.0 and the PP-Module for Authentication Servers. All extended components are defined in those Protection Profiles and are not further extended in this ST.

**Extended SFRs from NDcPP v4.0:**
- FCS_CKM_EXT.4 (Cryptographic Key Zeroization)
- FCS_RBG_EXT.1 (Random Bit Generation)
- FCS_STG_EXT.1 (Cryptographic Key Storage)
- FIA_AFL.1 (Authentication Failure Management)
- FIA_PMG_EXT.1 (Password Management)
- FIA_UIA_EXT.1 (User Identification and Authentication)
- FIA_UAU_EXT.2 (User Authentication Before Any Action)
- FPT_APW_EXT.1 (Protection of Administrator Passwords)
- FPT_SKP_EXT.1 (Protection of TSF Data)
- FPT_STM_EXT.1 (Reliable Time Stamps)
- FPT_TST_EXT.1 (TSF Testing)
- FPT_TUD_EXT.1 (Trusted Update)
- FTA_SSL_EXT.1 (TSF-initiated Session Locking)

**Extended SFRs from PP-Module for Authentication Servers:**
- FCS_EAPTLS_EXT.1 (EAP-TLS Protocol)
- FCS_RADIUS_EXT.1 (RADIUS/DIAMETER Protocol)
- FIA_AFL.1/AuthSvr (Authentication Failure Handling for Claimants)
- FIA_X509_EXT.1/AuthSvr (X.509 Certificate Validation for Claimants)
- FAU_GEN.1/AuthSvr (Audit Data Generation for Authentication Events)
- FCO_NRO.1 (Selective Proof of Origin)
- FCO_NRR.1 (Selective Proof of Receipt)

---

## 6. Security Requirements

### 6.1 Security Functional Requirements

The TOE satisfies all SFRs from:
- NDcPP v4.0 (base requirements)
- PP-Module for Authentication Servers v1.0

**Complete SFR list:** See [NIAP-NDCPP-MAPPING.md](NIAP-NDCPP-MAPPING.md) for detailed implementation mapping.

#### 6.1.1 Audit (FAU)

- FAU_GEN.1 - Audit data generation
- FAU_GEN.2 - User identity association
- FAU_STG_EXT.1 - Protected audit event storage
- FAU_GEN.1/AuthSvr - Authentication server audit events

#### 6.1.2 Cryptographic Support (FCS)

- FCS_CKM.1 - Cryptographic key generation (refined)
- FCS_CKM.2 - Cryptographic key establishment (refined)
- FCS_CKM.4 - Cryptographic key destruction
- FCS_COP.1/DataEncryption - Encryption/decryption operations
- FCS_COP.1/SigGen - Signature generation
- FCS_COP.1/Hash - Cryptographic hashing
- FCS_COP.1/KeyedHash - Keyed-hash (HMAC)
- FCS_RBG_EXT.1 - Random bit generation
- FCS_STG_EXT.1 - Cryptographic key storage
- FCS_EAPTLS_EXT.1 - EAP-TLS (mapped to TACACS+ over TLS)
- FCS_RADIUS_EXT.1 - RADIUS/DIAMETER (mapped to TACACS+)

#### 6.1.3 User Data Protection (FDP)

*(None from base PP; TOE does not manage user data)*

#### 6.1.4 Identification and Authentication (FIA)

- FIA_AFL.1 - Authentication failure handling (refined)
- FIA_PMG_EXT.1 - Password management
- FIA_UIA_EXT.1 - User identification and authentication
- FIA_UAU_EXT.2 - User authentication before any action
- FIA_UAU.7 - Protected authentication feedback
- FIA_AFL.1/AuthSvr - Authentication failure for claimants
- FIA_UAU.6 - Re-authenticating
- FIA_X509_EXT.1/AuthSvr - X.509 certificate validation

#### 6.1.5 Security Management (FMT)

- FMT_MOF.1/ManualUpdate - Management of security functions behavior
- FMT_MTD.1/CoreData - Management of TSF data
- FMT_SMF.1 - Specification of Management Functions
- FMT_SMR.2 - Restrictions on security roles

#### 6.1.6 Protection of the TSF (FPT)

- FPT_APW_EXT.1 - Protection of administrator passwords
- FPT_SKP_EXT.1 - Protection of TSF data (keys)
- FPT_STM_EXT.1 - Reliable time stamps
- FPT_TST_EXT.1 - TSF testing
- FPT_TUD_EXT.1 - Trusted update

#### 6.1.7 Resource Utilization (FRU)

*(None from base PP)*

#### 6.1.8 TOE Access (FTA)

- FTA_SSL_EXT.1 - TSF-initiated session locking
- FTA_SSL.3 - TSF-initiated termination (refined)
- FTA_SSL.4 - User-initiated termination (refined)
- FTA_TAB.1 - Default TOE access banners (refined)

#### 6.1.9 Trusted Path/Channels (FTP)

- FTP_ITC.1 - Inter-TSF trusted channel (refined)
- FTP_TRP.1/Admin - Trusted path for administrators (refined)

#### 6.1.10 Communications (FCO)

- FCO_NRO.1 - Selective proof of origin
- FCO_NRR.1 - Selective proof of receipt

### 6.2 Security Assurance Requirements

The TOE satisfies all SARs from NDcPP v4.0:

| SAR Class | SAR Component |
|-----------|---------------|
| **ASE** (Security Target) | ASE_INT.1, ASE_CCL.1, ASE_SPD.1, ASE_OBJ.1, ASE_ECD.1, ASE_REQ.1, ASE_TSS.1 |
| **ADV** (Development) | ADV_FSP.1 |
| **AGD** (Guidance) | AGD_OPE.1, AGD_PRE.1 |
| **ALC** (Life-cycle) | ALC_CMC.1, ALC_CMS.1, ALC_TSU_EXT.1 |
| **ATE** (Testing) | ATE_IND.1 |
| **AVA** (Vulnerability) | AVA_VAN.1 |

---

## 7. TOE Summary Specification

### 7.1 TOE Security Functions

#### TSF.1 - Cryptographic Services

**Description:** Provides cryptographic operations for confidentiality, integrity, and authentication.

**SFRs Satisfied:**
- FCS_CKM.1/2/4 (key management)
- FCS_COP.1 (encryption, signatures, hashing)
- FCS_RBG_EXT.1 (random generation)

**Implementation:**
- TLS 1.3 via Rustls library with AWS-LC cryptographic provider
- Argon2id password hashing
- SHA-256 for integrity
- AES-GCM for symmetric encryption (key storage)
- OpenSSL for CSPRNG

#### TSF.2 - Authentication Services

**Description:** Authenticates network administrators (claimants) via multiple mechanisms.

**SFRs Satisfied:**
- FIA_UAU_EXT.2 (authentication mechanisms)
- FIA_AFL.1 (failure handling)
- FIA_PMG_EXT.1 (password management)
- FIA_UAU.7 (protected feedback)

**Implementation:**
- PAP: Username/password validation against static file or LDAP
- CHAP: MD5 challenge-response per RFC 1994
- ASCII: Interactive username/password prompts
- LDAP: Enterprise directory integration via LDAPS
- Brute-force protection with exponential backoff and jitter
- Constant-time comparisons to prevent timing attacks

#### TSF.3 - Device Authentication

**Description:** Authenticates network access devices (NADs) via mutual TLS.

**SFRs Satisfied:**
- FIA_X509_EXT.1/AuthSvr (certificate validation)
- FTP_TRP.1 (trusted path)

**Implementation:**
- mTLS with client certificate validation
- CN/SAN allowlisting
- Certificate chain validation
- OCSP/CRL revocation checking

#### TSF.4 - Authorization Services

**Description:** Enforces command authorization policies for network administrators.

**SFRs Satisfied:**
- FMT_SMR.2 (security roles)
- Policy engine per TOE design

**Implementation:**
- Policy engine with regex-based rules
- User/group matching
- Command pattern matching
- Privilege level enforcement

#### TSF.5 - Accounting Services

**Description:** Generates accounting records for administrator sessions and commands.

**SFRs Satisfied:**
- FAU_GEN.1 (audit generation)
- FAU_GEN.2 (user association)

**Implementation:**
- Start/stop/watchdog accounting packets
- Task ID tracking per RFC 8907
- Session correlation

#### TSF.6 - Audit Logging

**Description:** Generates comprehensive audit records for security-relevant events.

**SFRs Satisfied:**
- FAU_GEN.1 (audit generation)
- FAU_GEN.2 (user identity)
- FAU_STG_EXT.1 (protected storage)

**Implementation:**
- Structured audit events with rich metadata
- Timestamps in ISO 8601 UTC format
- External forwarding to syslog (TCP/TLS) or Elasticsearch (HTTPS)
- Event types: authentication, authorization, session, config changes

#### TSF.7 - Session Management

**Description:** Manages administrator sessions with timeouts and termination.

**SFRs Satisfied:**
- FTA_SSL_EXT.1 (session locking)
- FTA_SSL.3/4 (termination)
- FTA_TAB.1 (access banners)

**Implementation:**
- Session registry with idle timeout tracking
- Administrative session termination via API
- Configurable idle timeout (default 300s)
- Background idle session sweeper
- Login banners displayed before authentication

#### TSF.8 - Security Management

**Description:** Provides management interfaces with role-based access control.

**SFRs Satisfied:**
- FMT_SMF.1 (management functions)
- FMT_MOF.1 (management behavior)
- FMT_MTD.1 (TSF data management)

**Implementation:**
- RESTful API over HTTPS with mTLS
- RBAC with admin/operator/viewer roles
- Policy hot-reload (SIGHUP, API endpoint)
- Session enumeration and control
- Prometheus metrics endpoint

#### TSF.9 - TSF Protection

**Description:** Protects the integrity and availability of security functions.

**SFRs Satisfied:**
- FPT_TST_EXT.1 (self-testing)
- FPT_TUD_EXT.1 (trusted update)
- FPT_STM_EXT.1 (reliable timestamps)
- FPT_SKP_EXT.1 (key protection)
- FPT_APW_EXT.1 (password protection)

**Implementation:**
- Startup self-tests (crypto KATs, integrity checks)
- Signature verification for updates
- NTP time synchronization
- Encrypted key storage at rest
- Restrictive file permissions for secrets

#### TSF.10 - Trusted Channels

**Description:** Establishes encrypted channels to external services.

**SFRs Satisfied:**
- FTP_ITC.1 (inter-TSF channels)
- FTP_TRP.1 (trusted path)

**Implementation:**
- TLS 1.3 for all TACACS+ connections
- LDAPS (not plain LDAP) for directory queries
- HTTPS for management API
- TLS for syslog forwarding

#### TSF.11 - Federation Protocol

**Description:** Provides proof of origin and receipt for authentication assertions.

**SFRs Satisfied:**
- FCO_NRO.1 (proof of origin)
- FCO_NRR.1 (proof of receipt)
- FCS_RADIUS_EXT.1 (TACACS+ as direct federation protocol)

**Implementation:**
- SHA-256 hash of TACACS+ request packets
- Client certificate fingerprint binding
- Session ID correlation
- Audit logging of origin/receipt proofs

### 7.2 SFR Rationale

All SFRs from NDcPP v4.0 and PP-Module for Authentication Servers v1.0 are satisfied by the TOE. For detailed code-level implementation mapping, see [NIAP-NDCPP-MAPPING.md](NIAP-NDCPP-MAPPING.md).

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-31 | usg-tacacs Team | Initial Security Target |
