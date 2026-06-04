// SPDX-License-Identifier: Apache-2.0
//! Shared parsing utilities for TACACS+ packet bodies.

use anyhow::{Context, Result, anyhow};

pub fn read_bytes(body: &[u8], offset: usize, len: usize, label: &str) -> Result<(Vec<u8>, usize)> {
    let next = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("overflow parsing {label}"))?;
    let slice = body
        .get(offset..next)
        .ok_or_else(|| anyhow!("{label} truncated"))?;
    Ok((slice.to_vec(), next))
}

pub fn read_string(body: &[u8], offset: usize, len: usize, label: &str) -> Result<(String, usize)> {
    let (raw, next) = read_bytes(body, offset, len, label)?;
    let value = String::from_utf8(raw).with_context(|| format!("decoding {label} as UTF-8"))?;
    Ok((value, next))
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
}

pub fn parse_attributes(args: &[String]) -> Vec<Attribute> {
    // RFC 8907 §8.2: an AV pair is delimited by the first '=' (mandatory) or
    // '*' (optional). Both separators are ASCII, so the byte index is a valid
    // char boundary. The value may be empty.
    args.iter()
        .map(|s| {
            if let Some(idx) = s.find(['=', '*']) {
                Attribute {
                    name: s[..idx].to_string(),
                    value: Some(s[idx + 1..].to_string()),
                }
            } else {
                Attribute {
                    name: s.clone(),
                    value: None,
                }
            }
        })
        .collect()
}

pub fn validate_attributes(args: &[String], allowed_prefixes: &[&str]) -> Result<()> {
    for (idx, arg) in args.iter().enumerate() {
        if arg.is_empty() {
            return Err(anyhow!("attr[{idx}] is empty"));
        }
        if arg.len() > 255 {
            return Err(anyhow!("attr[{idx}] exceeds 255 bytes"));
        }
        // RFC 8907 §8.2: name=value (mandatory) or name*value (optional),
        // delimited by the first '=' or '*'. The value MAY be empty, e.g. the
        // "cmd=" a NAS sends for shell-login (exec) authorization.
        let Some(sep) = arg.find(['=', '*']) else {
            return Err(anyhow!("attr[{idx}] must be name=value or name*value"));
        };
        let name = &arg[..sep];
        if name.is_empty() {
            return Err(anyhow!("attr[{idx}] has an empty name"));
        }
        if !allowed_prefixes
            .iter()
            .any(|p| name.eq_ignore_ascii_case(p))
        {
            return Err(anyhow!("attr[{idx}] uses unsupported name '{}'", name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== read_bytes Tests ====================

    #[test]
    fn read_bytes_valid() {
        let body = b"hello world";
        let (bytes, next) = read_bytes(body, 0, 5, "test").unwrap();

        assert_eq!(bytes, b"hello");
        assert_eq!(next, 5);
    }

    #[test]
    fn read_bytes_with_offset() {
        let body = b"hello world";
        let (bytes, next) = read_bytes(body, 6, 5, "test").unwrap();

        assert_eq!(bytes, b"world");
        assert_eq!(next, 11);
    }

    #[test]
    fn read_bytes_empty() {
        let body = b"hello";
        let (bytes, next) = read_bytes(body, 0, 0, "test").unwrap();

        assert!(bytes.is_empty());
        assert_eq!(next, 0);
    }

    #[test]
    fn read_bytes_truncated() {
        let body = b"hello";
        let result = read_bytes(body, 0, 10, "test");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn read_bytes_offset_overflow() {
        let body = b"hello";
        let result = read_bytes(body, usize::MAX, 1, "test");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overflow"));
    }

    #[test]
    fn read_bytes_exact_length() {
        let body = b"hello";
        let (bytes, next) = read_bytes(body, 0, 5, "test").unwrap();

        assert_eq!(bytes, b"hello");
        assert_eq!(next, 5);
    }

    // ==================== read_string Tests ====================

    #[test]
    fn read_string_valid_utf8() {
        let body = b"hello world";
        let (string, next) = read_string(body, 0, 5, "test").unwrap();

        assert_eq!(string, "hello");
        assert_eq!(next, 5);
    }

    #[test]
    fn read_string_with_offset() {
        let body = b"hello world";
        let (string, next) = read_string(body, 6, 5, "test").unwrap();

        assert_eq!(string, "world");
        assert_eq!(next, 11);
    }

    #[test]
    fn read_string_empty() {
        let body = b"hello";
        let (string, next) = read_string(body, 0, 0, "test").unwrap();

        assert!(string.is_empty());
        assert_eq!(next, 0);
    }

    #[test]
    fn read_string_invalid_utf8() {
        let body = &[0xFF, 0xFE, 0x00];
        let result = read_string(body, 0, 3, "test");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("UTF-8"));
    }

    #[test]
    fn read_string_truncated() {
        let body = b"hello";
        let result = read_string(body, 0, 10, "test");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    // ==================== parse_attributes Tests ====================

    #[test]
    fn parse_attributes_with_equals() {
        let args = vec!["service=shell".to_string(), "protocol=exec".to_string()];
        let attrs = parse_attributes(&args);

        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].name, "service");
        assert_eq!(attrs[0].value, Some("shell".to_string()));
        assert_eq!(attrs[1].name, "protocol");
        assert_eq!(attrs[1].value, Some("exec".to_string()));
    }

    #[test]
    fn parse_attributes_without_equals() {
        let args = vec!["flag".to_string()];
        let attrs = parse_attributes(&args);

        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, "flag");
        assert!(attrs[0].value.is_none());
    }

    #[test]
    fn parse_attributes_empty_value() {
        let args = vec!["key=".to_string()];
        let attrs = parse_attributes(&args);

        assert_eq!(attrs[0].name, "key");
        assert_eq!(attrs[0].value, Some(String::new()));
    }

    #[test]
    fn parse_attributes_optional_separator() {
        // Optional AV pairs use '*' as the delimiter (RFC 8907 §8.2).
        let args = vec!["cmd*show".to_string(), "cmd-arg*".to_string()];
        let attrs = parse_attributes(&args);

        assert_eq!(attrs[0].name, "cmd");
        assert_eq!(attrs[0].value, Some("show".to_string()));
        assert_eq!(attrs[1].name, "cmd-arg");
        assert_eq!(attrs[1].value, Some(String::new()));
    }

    #[test]
    fn parse_attributes_value_with_equals() {
        let args = vec!["cmd=show interface=eth0".to_string()];
        let attrs = parse_attributes(&args);

        assert_eq!(attrs[0].name, "cmd");
        assert_eq!(attrs[0].value, Some("show interface=eth0".to_string()));
    }

    #[test]
    fn parse_attributes_empty_input() {
        let args: Vec<String> = vec![];
        let attrs = parse_attributes(&args);

        assert!(attrs.is_empty());
    }

    // ==================== validate_attributes Tests ====================

    #[test]
    fn validate_attributes_valid() {
        let args = vec!["service=shell".to_string(), "cmd=show".to_string()];
        let allowed = ["service", "cmd"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_ok());
    }

    #[test]
    fn validate_attributes_case_insensitive() {
        let args = vec!["SERVICE=shell".to_string(), "CMD=show".to_string()];
        let allowed = ["service", "cmd"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_ok());
    }

    #[test]
    fn validate_attributes_empty_arg() {
        let args = vec!["".to_string()];
        let allowed = ["service"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn validate_attributes_missing_equals() {
        let args = vec!["service".to_string()];
        let allowed = ["service"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("name=value"));
    }

    #[test]
    fn validate_attributes_empty_value_is_allowed() {
        // RFC 8907 §8.2: an empty value is valid (e.g. "cmd=" for shell login).
        let args = vec!["service=".to_string(), "cmd=".to_string()];
        let allowed = ["service", "cmd"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_ok());
    }

    #[test]
    fn validate_attributes_optional_separator_is_allowed() {
        // Optional attributes use '*'; value may be present or empty.
        let args = vec!["service=shell".to_string(), "cmd*".to_string()];
        let allowed = ["service", "cmd"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_ok());
    }

    #[test]
    fn validate_attributes_empty_name() {
        let args = vec!["=value".to_string()];
        let allowed = ["service"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty name"));
    }

    #[test]
    fn validate_attributes_unknown_name() {
        let args = vec!["unknown=value".to_string()];
        let allowed = ["service", "cmd"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }

    #[test]
    fn validate_attributes_too_long() {
        let long_value = "a".repeat(256);
        let args = vec![format!("cmd={}", long_value)];
        let allowed = ["cmd"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("255"));
    }

    #[test]
    fn validate_attributes_exactly_255_bytes() {
        let value = "a".repeat(251); // "cmd=" is 4 bytes, + 251 = 255
        let args = vec![format!("cmd={}", value)];
        let allowed = ["cmd"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_ok());
    }

    #[test]
    fn validate_attributes_multiple_errors_reports_first() {
        let args = vec![
            "".to_string(),        // empty
            "invalid".to_string(), // no equals
        ];
        let allowed = ["service"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("attr[0]"));
    }

    #[test]
    fn validate_attributes_empty_input() {
        let args: Vec<String> = vec![];
        let allowed = ["service"];

        let result = validate_attributes(&args, &allowed);

        assert!(result.is_ok());
    }
}
