// SPDX-License-Identifier: Apache-2.0
//! TACACS+ shared-secret body obfuscation (MD5 pad).
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
//! | SC-12 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-13 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-8 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
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
//!     "SC"
//!   ],
//!   "total_controls": 3,
//!   "file_path": "crates/tacacs-proto/src/crypto.rs"
//! }
//! ```
//!
//! </details>
//!
//! # Security Notice: MD5 Usage (CWE-327)
//!
//! This module uses MD5 for TACACS+ body obfuscation as required by RFC 8907.
//! **MD5 is cryptographically broken and provides only obfuscation, not encryption.**
//!
//! ## Important:
//! - **TLS 1.3 is mandatory** for production deployments to provide actual encryption
//! - The `--forbid-unencrypted` flag should be enabled to reject unobfuscated packets
//! - MD5 obfuscation is applied as defense-in-depth even when TLS is enabled
//! - Legacy plaintext listeners should only be used for migration scenarios
//!
//! ## Mitigation:
//! 1. Always use TLS 1.3 for all TACACS+ connections (enforced by default)
//! 2. Use `--forbid-unencrypted` to reject packets without obfuscation
//! 3. Migrate legacy NADs to TLS-capable versions when possible
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **SC-8 (Transmission Confidentiality)**: Implements TACACS+ body
//!   obfuscation using MD5-based pad generation and XOR. Note: This is
//!   legacy obfuscation, not encryption. TLS 1.3 provides actual encryption.
//!
//! - **SC-13 (Cryptographic Protection)**: Uses MD5 for legacy protocol
//!   compatibility per RFC 8907. The obfuscation is applied as defense-in-depth
//!   even when TLS is enabled.
//!
//! - **SC-12 (Cryptographic Key Establishment)**: Enforces minimum secret
//!   length (8 bytes) for obfuscation keys.

use crate::FLAG_UNENCRYPTED;
use crate::header::Header;
#[cfg(not(feature = "legacy-md5"))]
use anyhow::bail;
use anyhow::{Result, anyhow, bail};
#[cfg(feature = "legacy-md5")]
use md5::{Digest, Md5};
use zeroize::Zeroizing;

/// Apply TACACS+ body obfuscation (encrypt or decrypt).
///
/// # NIST Controls
/// - **SC-8 (Transmission Confidentiality)**: Obfuscates packet body using
///   MD5-based pad generation and XOR operation.
/// - **SC-12 (Cryptographic Key Establishment)**: Enforces minimum secret
///   length requirement.
/// - **SC-13 (Cryptographic Protection)**: Uses MD5 for legacy compatibility;
///   actual encryption is provided by TLS 1.3.
pub fn apply_body_crypto(header: &Header, body: &mut [u8], secret: Option<&[u8]>) -> Result<()> {
    if header.flags & FLAG_UNENCRYPTED != 0 {
        return Ok(());
    }

    let secret = secret.ok_or_else(|| anyhow!("encrypted TACACS+ body but no secret provided"))?;
    // NIST SC-12: Enforce minimum secret length
    if secret.len() < crate::MIN_SECRET_LEN {
        bail!(
            "shared secret too short; minimum {} bytes required",
            crate::MIN_SECRET_LEN
        );
    }

    #[cfg(not(feature = "legacy-md5"))]
    {
        bail!("legacy TACACS+ obfuscation is disabled (legacy-md5 feature off)");
    }

    #[cfg(feature = "legacy-md5")]
    {
        // NIST SC-12: Zeroize seed material when dropped.
        // Reuse a single seed buffer across iterations to avoid per-block
        // heap allocation.  XOR each MD5 block directly into the body to
        // eliminate the separate pad accumulation vector.
        let mut seed = Zeroizing::new(Vec::with_capacity(4 + secret.len() + 2 + 16));
        let mut prev: Option<Zeroizing<[u8; 16]>> = None;
        let mut offset = 0;

        while offset < body.len() {
            seed.clear();
            seed.extend_from_slice(&header.session_id.to_be_bytes());
            seed.extend_from_slice(secret);
            seed.push(header.version);
            seed.push(header.seq_no);
            if let Some(ref prev_block) = prev {
                seed.extend_from_slice(&**prev_block);
            }
            let block = Zeroizing::new(<[u8; 16]>::from(Md5::digest(&*seed)));
            let remaining = body.len() - offset;
            let chunk = remaining.min(16);
            for i in 0..chunk {
                body[offset + i] ^= block[i];
            }
            offset += chunk;
            prev = Some(block);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(session_id: u32, version: u8, seq_no: u8, flags: u8) -> Header {
        Header {
            version,
            packet_type: crate::TYPE_AUTHEN,
            seq_no,
            flags,
            session_id,
            length: 0,
        }
    }

    #[test]
    fn crypto_skips_unencrypted_flag() {
        let header = make_header(12345, crate::VERSION, 1, FLAG_UNENCRYPTED);
        let mut body = vec![0x01, 0x02, 0x03, 0x04];
        let original = body.clone();

        let result = apply_body_crypto(&header, &mut body, Some(b"testsecret"));
        assert!(result.is_ok());
        // Body should be unchanged when UNENCRYPTED flag is set
        assert_eq!(body, original);
    }

    #[test]
    fn crypto_requires_secret_when_encrypted() {
        let header = make_header(12345, crate::VERSION, 1, 0);
        let mut body = vec![0x01, 0x02, 0x03, 0x04];

        let result = apply_body_crypto(&header, &mut body, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no secret"));
    }

    #[test]
    fn crypto_rejects_short_secret() {
        let header = make_header(12345, crate::VERSION, 1, 0);
        let mut body = vec![0x01, 0x02, 0x03, 0x04];

        // Secret less than MIN_SECRET_LEN (8 bytes)
        let result = apply_body_crypto(&header, &mut body, Some(b"short"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[cfg(feature = "legacy-md5")]
    #[test]
    fn crypto_roundtrip_encryption() {
        let header = make_header(0xDEADBEEF, crate::VERSION, 1, 0);
        let secret = b"mysecretkey123";
        let original = b"Hello, TACACS+ world!".to_vec();
        let mut encrypted = original.clone();

        // Encrypt
        apply_body_crypto(&header, &mut encrypted, Some(secret)).unwrap();

        // Encrypted should differ from original
        assert_ne!(encrypted, original);

        // Decrypt (XOR is symmetric)
        apply_body_crypto(&header, &mut encrypted, Some(secret)).unwrap();

        // Should match original
        assert_eq!(encrypted, original);
    }

    #[cfg(feature = "legacy-md5")]
    #[test]
    fn crypto_empty_body() {
        let header = make_header(12345, crate::VERSION, 1, 0);
        let secret = b"testsecret";
        let mut body: Vec<u8> = vec![];

        // Empty body should work without error
        let result = apply_body_crypto(&header, &mut body, Some(secret));
        assert!(result.is_ok());
        assert!(body.is_empty());
    }

    #[cfg(feature = "legacy-md5")]
    #[test]
    fn crypto_single_byte_body() {
        let header = make_header(12345, crate::VERSION, 1, 0);
        let secret = b"testsecret";
        let original = vec![0x42];
        let mut body = original.clone();

        apply_body_crypto(&header, &mut body, Some(secret)).unwrap();
        assert_ne!(body, original);

        // Roundtrip
        apply_body_crypto(&header, &mut body, Some(secret)).unwrap();
        assert_eq!(body, original);
    }

    #[cfg(feature = "legacy-md5")]
    #[test]
    fn crypto_multi_block_body() {
        // Body larger than 16 bytes (MD5 block size) to test pad chaining
        let header = make_header(0x12345678, crate::VERSION, 3, 0);
        let secret = b"longsecretkey";
        let original: Vec<u8> = (0..64).collect(); // 64 bytes = 4 MD5 blocks
        let mut body = original.clone();

        apply_body_crypto(&header, &mut body, Some(secret)).unwrap();
        assert_ne!(body, original);

        // Roundtrip
        apply_body_crypto(&header, &mut body, Some(secret)).unwrap();
        assert_eq!(body, original);
    }

    #[cfg(feature = "legacy-md5")]
    #[test]
    fn crypto_different_session_ids_produce_different_ciphertext() {
        let secret = b"testsecret";
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let header1 = make_header(0x11111111, crate::VERSION, 1, 0);
        let header2 = make_header(0x22222222, crate::VERSION, 1, 0);

        let mut body1 = original.clone();
        let mut body2 = original.clone();

        apply_body_crypto(&header1, &mut body1, Some(secret)).unwrap();
        apply_body_crypto(&header2, &mut body2, Some(secret)).unwrap();

        // Different session IDs should produce different ciphertext
        assert_ne!(body1, body2);
    }

    #[cfg(feature = "legacy-md5")]
    #[test]
    fn crypto_different_seq_nos_produce_different_ciphertext() {
        let secret = b"testsecret";
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let header1 = make_header(0x12345678, crate::VERSION, 1, 0);
        let header2 = make_header(0x12345678, crate::VERSION, 3, 0);

        let mut body1 = original.clone();
        let mut body2 = original.clone();

        apply_body_crypto(&header1, &mut body1, Some(secret)).unwrap();
        apply_body_crypto(&header2, &mut body2, Some(secret)).unwrap();

        // Different sequence numbers should produce different ciphertext
        assert_ne!(body1, body2);
    }
}
