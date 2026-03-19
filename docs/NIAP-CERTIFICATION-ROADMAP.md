# NIAP NDcPP v4.0 Certification Roadmap

<!-- NIST SP 800-53 Rev. 5 Security Controls
     Control Implementation Matrix

     | Control | Family | Status | Validated | Primary Functions |
     |---------|--------|--------|-----------|-------------------|
     | SA-4    | System and Services Acquisition | Documented | 2026-01-31 | Acquisition process |
     | SA-11   | Developer Testing and Evaluation | Documented | 2026-01-31 | Security testing |
     | SA-15   | Development Process | Documented | 2026-01-31 | Development standards |
-->

**Project:** usg-tacacs TACACS+ Server
**Target Profile:** NDcPP v4.0 (November 25, 2025) + PP-Module for Authentication Servers v1.0
**Document Version:** 1.0
**Last Updated:** 2026-01-31

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Certification Overview](#certification-overview)
3. [Timeline and Milestones](#timeline-and-milestones)
4. [Evaluation Lab Selection](#evaluation-lab-selection)
5. [Budget and Resources](#budget-and-resources)
6. [Risk Assessment](#risk-assessment)
7. [Gap Analysis Summary](#gap-analysis-summary)
8. [Deliverables Checklist](#deliverables-checklist)

---

## Executive Summary

This roadmap outlines the path to achieving NIAP (National Information Assurance Partnership) Common Criteria certification for the usg-tacacs TACACS+ server against:

- **collaborative Protection Profile for Network Devices (NDcPP) v4.0**
- **PP-Module for Authentication Servers v1.0**

The usg-tacacs server provides centralized authentication, authorization, and accounting (AAA) services for network infrastructure devices. Achieving NDcPP certification will enable deployment in U.S. Government National Security Systems (NSS) and other environments requiring Common Criteria certified products.

### Current State

The codebase has strong security foundations:

- TLS 1.3 exclusive (no fallback)
- Mutual TLS (mTLS) for device authentication
- Argon2id password hashing
- Comprehensive RBAC
- Full audit logging with syslog/Elasticsearch forwarding
- NIST SP 800-53 Rev. 5 compliance (38 controls documented)
- NASA Power of 10 Rule #4 compliance (99.1%)

### Certification Goal

Achieve NIAP Product Compliant List (PCL) certification within 9-12 months, enabling:

- Deployment in DoD and IC environments
- Compliance with CNSSP-11 requirements
- International recognition via CCRA (Common Criteria Recognition Arrangement)

---

## Certification Overview

### What is NIAP Certification?

NIAP is the U.S. Government initiative for evaluating IT products against the Common Criteria for Information Technology Security Evaluation (ISO/IEC 15408). Products evaluated under NIAP are listed on the Product Compliant List (PCL) and recognized internationally.

### Why NDcPP v4.0?

NDcPP v4.0 is the latest collaborative Protection Profile for network devices, released November 25, 2025. Key reasons for targeting v4.0:

1. **Mandatory after December 31, 2025** - New evaluations against v3.0e are no longer accepted
2. **CC:2022 Alignment** - Modern evaluation framework with improved assurance
3. **Protocol Modularization** - TLS and X.509 in functional packages for flexibility
4. **Future-Proof** - Longer certification validity period

### Why PP-Module for Authentication Servers?

The PP-Module extends NDcPP with requirements specific to authentication servers:

- RADIUS/DIAMETER protocol requirements (TACACS+ as equivalent)
- EAP-TLS/EAP-TTLS support
- Proof of origin/receipt for identity assertions
- Enhanced certificate validation

---

## Timeline and Milestones

### Phase 1: Preparation (Weeks 1-9)

| Week | Milestone | Deliverables |
|------|-----------|--------------|
| 1-2 | Documentation | Security Target, NDcPP Mapping, Threat Model |
| 3-6 | Code Development | 7 gap closure modules implemented |
| 7-8 | Testing | SFR test suite, fuzz testing, vulnerability scans |
| 9 | Evidence Package | Complete certification package assembled |

### Phase 2: Lab Selection and Kickoff (Weeks 10-12)

| Week | Milestone | Activities |
|------|-----------|------------|
| 10 | Lab Selection | Evaluate and select NIAP-approved CCTL |
| 11 | Contract Negotiation | Finalize SOW, timeline, and costs |
| 12 | Kickoff Meeting | Submit initial evidence package |

### Phase 3: Evaluation (Weeks 13-36)

| Week | Milestone | Activities |
|------|-----------|------------|
| 13-16 | ST Review | Security Target review and feedback |
| 17-24 | Evidence Review | ADV, AGD, ALC, ATE evidence evaluation |
| 25-32 | Testing | Independent functional and vulnerability testing |
| 33-36 | Certification | Final report, NIAP review, PCL listing |

### Critical Dates

| Date | Event |
|------|-------|
| 2025-12-31 | NDcPP v3.0e sunset (v4.0 mandatory) |
| Q1 2026 | Complete preparation phase |
| Q2 2026 | Begin lab evaluation |
| Q4 2026 | Target certification date |

---

## Evaluation Lab Selection

### NIAP-Approved CCTLs (Common Criteria Testing Laboratories)

The following labs are accredited to perform NIAP evaluations:

| Laboratory | Location | Specialization |
|------------|----------|----------------|
| Acumen Security | Columbia, MD | Network devices, cryptographic modules |
| Booz Allen Hamilton | McLean, VA | Enterprise IT, network security |
| Gossamer Security Solutions | Columbia, MD | Network devices, mobile |
| Leidos | Reston, VA | Government IT, network infrastructure |
| UL Solutions | Research Triangle Park, NC | IoT, network devices |
| EWA-Canada | Ottawa, Canada | Network devices (CCRA) |

### Selection Criteria

1. **NDcPP v4.0 Experience** - Prior evaluations against NDcPP v4.0
2. **Authentication Server Experience** - Familiarity with PP-Module for Auth Servers
3. **Timeline** - Availability to meet target certification date
4. **Cost** - Competitive evaluation fees
5. **Geographic Location** - Accessibility for kickoff and testing
6. **Communication** - Responsiveness and technical expertise

### Recommended Approach

1. Issue RFI to 3-4 labs with project summary
2. Conduct technical discussions to assess fit
3. Request formal proposals with fixed-price quotes
4. Select lab based on weighted criteria scoring

---

## Budget and Resources

### Estimated Costs

| Category | Low Estimate | High Estimate | Notes |
|----------|--------------|---------------|-------|
| **Lab Evaluation Fees** | $150,000 | $250,000 | Depends on lab and complexity |
| **NIAP Scheme Fees** | $5,000 | $10,000 | Administrative fees |
| **Internal Development** | $80,000 | $120,000 | 2-3 FTE for 3 months |
| **Consulting Support** | $20,000 | $50,000 | Optional CC expertise |
| **Penetration Testing** | $15,000 | $30,000 | Independent assessment |
| **Documentation** | $10,000 | $20,000 | Technical writing support |
| **Contingency (15%)** | $42,000 | $72,000 | Unexpected issues |
| **Total** | **$322,000** | **$552,000** | |

### Resource Requirements

**Internal Team:**

| Role | Allocation | Duration | Responsibilities |
|------|------------|----------|------------------|
| Project Lead | 50% | 9 months | Coordination, lab liaison |
| Security Engineer | 100% | 3 months | Gap closure development |
| QA Engineer | 50% | 2 months | Test suite development |
| Technical Writer | 25% | 3 months | Documentation |
| DevOps Engineer | 25% | 1 month | CI/CD, evidence automation |

**External Support:**

- Common Criteria consultant (optional): 40-80 hours
- Penetration testing firm: 1-2 week engagement
- Technical writer (if needed): 80-160 hours

---

## Risk Assessment

### High-Impact Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Gap closure delays** | Medium | High | Start development immediately; parallel workstreams |
| **Lab backlog** | Medium | High | Engage labs early; flexible timeline |
| **NDcPP v4.0 interpretation issues** | Low | High | Engage lab for early ST review |
| **Cryptographic module compliance** | Medium | Medium | Validate FIPS 140-3 requirements early |
| **Resource availability** | Medium | Medium | Secure commitments; identify backups |

### Medium-Impact Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Test failures during evaluation** | Medium | Medium | Comprehensive pre-certification testing |
| **Documentation deficiencies** | Medium | Medium | Template-based approach; early review |
| **Scope creep** | Low | Medium | Fixed scope in SOW; change control |
| **Dependency vulnerabilities** | Low | Medium | Continuous cargo audit; SBOM tracking |

### Risk Monitoring

- Weekly risk review during preparation phase
- Bi-weekly during evaluation phase
- Escalation path to project sponsor defined

---

## Gap Analysis Summary

### Implemented Requirements (No Action Needed)

| SFR | Description | Implementation |
|-----|-------------|----------------|
| FAU_GEN.1 | Audit generation | `tacacs-audit/src/event.rs` |
| FAU_GEN.2 | User identity association | Audit records include username, session_id |
| FAU_STG_EXT.1 | Protected audit storage | TLS to syslog/Elasticsearch |
| FCS_CKM.1/2 | Key generation/establishment | TLS 1.3 via Rustls |
| FCS_CKM.4 | Key destruction | Zeroization on connection close |
| FCS_COP.1 | Cryptographic operations | AES-GCM, SHA-256, Argon2id |
| FCS_RBG_EXT.1 | Random bit generation | OpenSSL CSPRNG |
| FIA_AFL.1 | Auth failure handling | Exponential backoff, lockout |
| FIA_PMG_EXT.1 | Password management | Argon2id, configurable policies |
| FIA_UIA_EXT.1 | User identification | PAP, CHAP, ASCII, LDAP |
| FIA_UAU_EXT.2 | Password authentication | Multiple methods supported |
| FIA_UAU.7 | Protected feedback | Constant-time comparisons |
| FMT_MOF.1 | Management functions | API endpoints, SIGHUP reload |
| FMT_MTD.1 | TSF data management | Policy hot-reload |
| FMT_SMF.1 | Management functions | Comprehensive API |
| FMT_SMR.2 | Security roles | Admin, operator, viewer |
| FPT_SKP_EXT.1 | Key protection | File permissions, no CLI exposure |
| FPT_APW_EXT.1 | Admin password protection | Argon2id hashing |
| FTA_SSL_EXT.1 | Session locking | Idle timeout |
| FTA_SSL.3/4 | Session termination | Administrative and automatic |
| FTP_ITC.1 | Trusted channel | TLS 1.3 to all external services |
| FTP_TRP.1 | Trusted path | mTLS for management API |

### Gaps Requiring Implementation

| SFR | Description | Priority | Effort |
|-----|-------------|----------|--------|
| FPT_TST_EXT.1 | Self-testing | High | 1 week |
| FPT_TUD_EXT.1 | Trusted update | High | 1 week |
| FPT_STM_EXT.1 | Reliable timestamps | Medium | 3 days |
| FTA_TAB.1 | Access banners | Low | 1 day |
| FIA_X509_EXT.1 | OCSP/CRL checking | High | 1 week |
| FCS_STG_EXT.1 | Encrypted key storage | Medium | 1 week |
| FCO_NRO.1/NRR.1 | Proof of origin/receipt | Medium | 3 days |

**Total Development Effort:** ~5-6 weeks

---

## Deliverables Checklist

### Documentation Deliverables

- [ ] **Security Target (ST)** - Formal CC document describing TOE
- [ ] **NDcPP Requirements Mapping** - SFR-to-code traceability
- [ ] **Threat Model** - Security problem definition
- [ ] **Assurance Evidence Index** - SAR evidence inventory
- [ ] **Operational Guidance (AGD_OPE)** - Administrator documentation
- [ ] **Preparative Procedures (AGD_PRE)** - Installation guide
- [ ] **Functional Specification (ADV_FSP)** - TSFI description
- [ ] **Life-cycle Documentation (ALC)** - CM, delivery, development

### Code Deliverables

- [ ] Self-testing module (`selftest.rs`)
- [ ] Trusted update module (`update.rs`)
- [ ] Time synchronization (`timesync.rs`)
- [ ] Access banners (ASCII auth modification)
- [ ] Certificate validation (`cert_validation.rs`)
- [ ] Encrypted key storage (`encrypted_key.rs`)
- [ ] Federation protocol (`federation.rs`)

### Test Deliverables

- [ ] SFR test suite (~78 test cases)
- [ ] Fuzz testing expansion (5 new targets)
- [ ] Vulnerability scan automation
- [ ] CI/CD workflow (`.github/workflows/niap-compliance.yml`)
- [ ] Test coverage report (>80% target)
- [ ] Traceability matrix (test-to-SFR)

### Evidence Package

- [ ] Test results (JSON format)
- [ ] Coverage reports (LCOV)
- [ ] Vulnerability scan results
- [ ] Fuzz testing artifacts
- [ ] Penetration test report
- [ ] Source code snapshot (with Cargo.lock)

---

## Next Steps

1. **Immediate:** Begin Phase 1 documentation (Security Target, NDcPP Mapping)
2. **Week 1:** Start high-priority gap closure (self-testing, OCSP/CRL)
3. **Week 2:** Issue RFI to evaluation labs
4. **Week 4:** Complete code development, begin testing
5. **Week 8:** Assemble evidence package
6. **Week 10:** Select lab and initiate evaluation

---

## References

- [NIAP Product Compliant List](https://www.niap-ccevs.org/Product/index.cfm)
- [NDcPP v4.0](https://nd-itc.github.io/cPP/NDcPP_v4_0.pdf)
- [NDcPP v4.0 Supporting Document](https://nd-itc.github.io/SD/ND_Supporting_Document_4_0.pdf)
- [PP-Module for Authentication Servers v1.0](https://www.niap-ccevs.org/Profile/Info.cfm?PPID=470)
- [Common Criteria Portal](https://www.commoncriteriaportal.org/)
- [NIAP Policy Letters](https://www.niap-ccevs.org/Documents_and_Guidance/policy.cfm)

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-31 | usg-tacacs Team | Initial release |
