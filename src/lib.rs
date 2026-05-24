//! # llm-pii-redact
//!
//! Regex-based PII redaction for LLM prompts and tool outputs.
//!
//! Scans text for common PII (emails, phone numbers, SSNs, credit cards
//! with Luhn validation, IPv4, IPv6, IBANs, URLs) and replaces each match
//! with a stable placeholder like `<EMAIL_0>`. A mapping from placeholder
//! to original value is returned so callers can [`reveal`] the original
//! text after the LLM has responded.
//!
//! [`reveal`]: Redactor::reveal
//!
//! ## Quick example
//!
//! ```
//! use llm_pii_redact::Redactor;
//!
//! let r = Redactor::default();
//! let out = r.redact("Email me at ops@example.invalid or call 555-123-4567");
//! assert!(!out.text.contains("ops@example.invalid"));
//! assert!(!out.text.contains("555-123-4567"));
//!
//! let original = r.reveal(&out.text, &out.mapping);
//! assert_eq!(original, "Email me at ops@example.invalid or call 555-123-4567");
//! ```
//!
//! ## Custom patterns
//!
//! Start from an empty [`Redactor`] and add your own:
//!
//! ```
//! use llm_pii_redact::Redactor;
//!
//! let r = Redactor::new()
//!     .with_pattern("AWS_KEY", r"AKIA[0-9A-Z]{16}")
//!     .unwrap();
//! let out = r.redact("key=AKIAABCDEFGHIJKLMNOP ok");
//! assert!(out.text.contains("<AWS_KEY_0>"));
//! assert_eq!(out.mapping["<AWS_KEY_0>"], "AKIAABCDEFGHIJKLMNOP");
//! ```
//!
//! Or take a built-in detector by itself:
//!
//! ```
//! use llm_pii_redact::Redactor;
//!
//! let r = Redactor::email();
//! let out = r.redact("ping ops@example.invalid and call 555-123-4567");
//! assert!(out.text.contains("<EMAIL_0>"));
//! assert!(out.text.contains("555-123-4567"));
//! ```
//!
//! ## Companion crates
//!
//! - [`tool-secret-scrubber`](https://crates.io/crates/tool-secret-scrubber):
//!   API keys, JWTs, bearer tokens, AWS keys. PII detectors live here.

#![deny(missing_docs)]

use std::collections::HashMap;

use regex::Regex;

/// Built-in PII type label `"EMAIL"`.
pub const EMAIL: &str = "EMAIL";
/// Built-in PII type label `"PHONE_US"`.
pub const PHONE_US: &str = "PHONE_US";
/// Built-in PII type label `"SSN"`.
pub const SSN: &str = "SSN";
/// Built-in PII type label `"CREDIT_CARD"`.
pub const CREDIT_CARD: &str = "CREDIT_CARD";
/// Built-in PII type label `"IP_V4"`.
pub const IP_V4: &str = "IP_V4";
/// Built-in PII type label `"IP_V6"`.
pub const IP_V6: &str = "IP_V6";
/// Built-in PII type label `"IBAN"`.
pub const IBAN: &str = "IBAN";
/// Built-in PII type label `"URL"`.
pub const URL: &str = "URL";

const EMAIL_RE: &str = r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b";
// `regex` crate has no lookaround, so we surround with a (?:\D|^)/(?:\D|$) frame
// and capture the actual number. The Redactor walks Captures to get group 1.
const PHONE_US_RE: &str =
    r"(?:^|\D)((?:\+?1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4})(?:\D|$)";
const SSN_RE: &str = r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b";
const CREDIT_CARD_RE: &str = r"(?:^|\D)((?:\d[ \-]?){12,18}\d)(?:\D|$)";
const IP_V4_RE: &str = concat!(
    r"\b",
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}",
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)",
    r"\b"
);
const IP_V6_RE: &str = concat!(
    r"(?:^|[^\w:])",
    r"(",
    r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}",
    r"|",
    r"(?:[A-Fa-f0-9]{1,4}:){1,7}:",
    r"|",
    r":(?::[A-Fa-f0-9]{1,4}){1,7}",
    r"|",
    r"(?:[A-Fa-f0-9]{1,4}:){1,6}(?::[A-Fa-f0-9]{1,4}){1,6}",
    r")",
    r"(?:[^\w:]|$)"
);
const IBAN_RE: &str = r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b";
const URL_RE: &str = r#"\bhttps?://[^\s<>"')]+"#;

/// One detected PII span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Detector name (e.g. `"EMAIL"`) that produced the match.
    pub kind: String,
    /// Matched substring.
    pub value: String,
    /// Inclusive byte offset where the match starts in the input.
    pub start: usize,
    /// Exclusive byte offset where the match ends in the input.
    pub end: usize,
}

/// Result of [`Redactor::redact`].
///
/// `text` is the redacted output. `mapping` sends each placeholder
/// (e.g. `"<EMAIL_0>"`) back to its original value so [`Redactor::reveal`]
/// can restore the input. Repeated values share a single placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Redacted {
    /// Redacted text with placeholders substituted in.
    pub text: String,
    /// Placeholder to original value.
    pub mapping: HashMap<String, String>,
}

/// One named detector: a label and its compiled regex.
///
/// For credit cards the matcher also runs a Luhn check; for phone numbers
/// and credit cards the regex contains a capture group around the actual
/// value because the `regex` crate has no lookaround.
#[derive(Debug, Clone)]
struct Detector {
    name: String,
    regex: Regex,
    // Some patterns need to look at framing characters; group 1 holds the
    // real match in that case. None means use the whole match.
    capture_group: Option<usize>,
    needs_luhn: bool,
}

impl Detector {
    fn new(name: &str, pat: &str) -> Self {
        Self {
            name: name.to_string(),
            regex: Regex::new(pat).expect("built-in pattern compiles"),
            capture_group: None,
            needs_luhn: false,
        }
    }
}

/// Configurable PII redactor.
///
/// Use [`Redactor::default`] for all built-in detectors, or [`Redactor::new`]
/// for an empty redactor you build up with [`Redactor::with_pattern`].
///
/// Single-detector helpers ([`Redactor::email`], [`Redactor::phone`],
/// [`Redactor::ssn`], [`Redactor::cc`], [`Redactor::ip`]) return a redactor
/// configured for just that type.
#[derive(Debug, Clone)]
pub struct Redactor {
    detectors: Vec<Detector>,
}

impl Default for Redactor {
    /// All built-in detectors, registered in the order `EMAIL`, `PHONE_US`,
    /// `SSN`, `CREDIT_CARD`, `IP_V4`, `IP_V6`, `IBAN`, `URL`. Registration
    /// order matters on overlaps: the earlier detector wins.
    fn default() -> Self {
        Self {
            detectors: default_detectors(),
        }
    }
}

fn default_detectors() -> Vec<Detector> {
    vec![
        Detector::new(EMAIL, EMAIL_RE),
        Detector {
            name: PHONE_US.to_string(),
            regex: Regex::new(PHONE_US_RE).expect("phone pattern compiles"),
            capture_group: Some(1),
            needs_luhn: false,
        },
        Detector::new(SSN, SSN_RE),
        Detector {
            name: CREDIT_CARD.to_string(),
            regex: Regex::new(CREDIT_CARD_RE).expect("cc pattern compiles"),
            capture_group: Some(1),
            needs_luhn: true,
        },
        Detector::new(IP_V4, IP_V4_RE),
        Detector {
            name: IP_V6.to_string(),
            regex: Regex::new(IP_V6_RE).expect("ipv6 pattern compiles"),
            capture_group: Some(1),
            needs_luhn: false,
        },
        Detector::new(IBAN, IBAN_RE),
        Detector::new(URL, URL_RE),
    ]
}

impl Redactor {
    /// Empty redactor with no detectors. Build it up with
    /// [`Redactor::with_pattern`].
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Register an additional named detector.
    ///
    /// `name` becomes the placeholder prefix (`<NAME_0>`, `<NAME_1>`, ...).
    /// `pattern` is a `regex` crate-compatible regex source string.
    ///
    /// Returns the modified redactor on success. Returns
    /// [`regex::Error`] if the pattern fails to compile.
    ///
    /// ```
    /// use llm_pii_redact::Redactor;
    ///
    /// let r = Redactor::new()
    ///     .with_pattern("AWS_KEY", r"AKIA[0-9A-Z]{16}")
    ///     .unwrap();
    /// let out = r.redact("AKIAABCDEFGHIJKLMNOP");
    /// assert_eq!(out.mapping["<AWS_KEY_0>"], "AKIAABCDEFGHIJKLMNOP");
    /// ```
    pub fn with_pattern(mut self, name: &str, pattern: &str) -> Result<Self, regex::Error> {
        if name.is_empty() {
            return Err(regex::Error::Syntax("name must be non-empty".into()));
        }
        let regex = Regex::new(pattern)?;
        self.detectors.push(Detector {
            name: name.to_string(),
            regex,
            capture_group: None,
            needs_luhn: false,
        });
        Ok(self)
    }

    /// Redactor with only the EMAIL detector.
    pub fn email() -> Self {
        Self {
            detectors: vec![Detector::new(EMAIL, EMAIL_RE)],
        }
    }

    /// Redactor with only the PHONE_US detector.
    pub fn phone() -> Self {
        Self {
            detectors: vec![Detector {
                name: PHONE_US.to_string(),
                regex: Regex::new(PHONE_US_RE).expect("phone pattern compiles"),
                capture_group: Some(1),
                needs_luhn: false,
            }],
        }
    }

    /// Redactor with only the SSN detector.
    pub fn ssn() -> Self {
        Self {
            detectors: vec![Detector::new(SSN, SSN_RE)],
        }
    }

    /// Redactor with only the CREDIT_CARD detector. Matches pass the Luhn
    /// checksum.
    pub fn cc() -> Self {
        Self {
            detectors: vec![Detector {
                name: CREDIT_CARD.to_string(),
                regex: Regex::new(CREDIT_CARD_RE).expect("cc pattern compiles"),
                capture_group: Some(1),
                needs_luhn: true,
            }],
        }
    }

    /// Redactor with both IPv4 and IPv6 detectors.
    pub fn ip() -> Self {
        Self {
            detectors: vec![
                Detector::new(IP_V4, IP_V4_RE),
                Detector {
                    name: IP_V6.to_string(),
                    regex: Regex::new(IP_V6_RE).expect("ipv6 pattern compiles"),
                    capture_group: Some(1),
                    needs_luhn: false,
                },
            ],
        }
    }

    /// Names of the registered detectors, in registration order.
    pub fn detector_names(&self) -> Vec<&str> {
        self.detectors.iter().map(|d| d.name.as_str()).collect()
    }

    /// Return every PII match in `text` without modifying it.
    ///
    /// Matches are returned in document order. When two enabled detectors
    /// overlap on the same span, the detector registered first wins so the
    /// result is unambiguous.
    pub fn detect(&self, text: &str) -> Vec<Detection> {
        if text.is_empty() {
            return Vec::new();
        }
        let mut raw: Vec<Detection> = Vec::new();
        for det in &self.detectors {
            for caps in det.regex.captures_iter(text) {
                let m = match det.capture_group {
                    Some(idx) => match caps.get(idx) {
                        Some(m) => m,
                        None => continue,
                    },
                    None => caps.get(0).expect("group 0 always present"),
                };
                let value = m.as_str();
                if det.needs_luhn && !luhn_ok(value) {
                    continue;
                }
                raw.push(Detection {
                    kind: det.name.clone(),
                    value: value.to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
        raw.sort_by_key(|d| (d.start, d.end));

        // Earlier match wins on overlap. With equal start, the shorter range
        // would come first in the sort; that is fine because the Python lib
        // accepts a candidate when `start >= last_end`.
        let mut accepted: Vec<Detection> = Vec::new();
        let mut last_end: usize = 0;
        let mut have_one = false;
        for d in raw {
            if !have_one || d.start >= last_end {
                last_end = d.end;
                have_one = true;
                accepted.push(d);
            }
        }
        accepted
    }

    /// Replace each detected PII span with a stable placeholder.
    ///
    /// Repeated values share a placeholder so the output is deterministic.
    /// The returned [`Redacted::mapping`] lets [`Redactor::reveal`] restore
    /// the original text.
    pub fn redact(&self, text: &str) -> Redacted {
        let detections = self.detect(text);
        if detections.is_empty() {
            return Redacted {
                text: text.to_string(),
                mapping: HashMap::new(),
            };
        }

        let mut per_type_index: HashMap<String, usize> = HashMap::new();
        let mut value_to_placeholder: HashMap<(String, String), String> = HashMap::new();
        let mut mapping: HashMap<String, String> = HashMap::new();

        for d in &detections {
            let key = (d.kind.clone(), d.value.clone());
            if !value_to_placeholder.contains_key(&key) {
                let idx = per_type_index.entry(d.kind.clone()).or_insert(0);
                let placeholder = format!("<{}_{}>", d.kind, *idx);
                *idx += 1;
                value_to_placeholder.insert(key.clone(), placeholder.clone());
                mapping.insert(placeholder, d.value.clone());
            }
        }

        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for d in &detections {
            out.push_str(&text[cursor..d.start]);
            let key = (d.kind.clone(), d.value.clone());
            out.push_str(&value_to_placeholder[&key]);
            cursor = d.end;
        }
        out.push_str(&text[cursor..]);

        Redacted { text: out, mapping }
    }

    /// Reverse a [`Redactor::redact`] call by substituting placeholders
    /// back to their original values.
    ///
    /// The mapping is applied longest-key-first to keep `<EMAIL_10>` from
    /// colliding with `<EMAIL_1>`. Unknown placeholders are left alone.
    pub fn reveal(&self, text: &str, mapping: &HashMap<String, String>) -> String {
        if mapping.is_empty() {
            return text.to_string();
        }
        let mut keys: Vec<&String> = mapping.keys().collect();
        keys.sort_by(|a, b| b.len().cmp(&a.len()));
        let mut out = text.to_string();
        for k in keys {
            if out.contains(k.as_str()) {
                out = out.replace(k.as_str(), &mapping[k]);
            }
        }
        out
    }
}

/// Return `true` if the digit-only characters of `s` pass the Luhn
/// checksum used to validate credit card numbers.
fn luhn_ok(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut total: u32 = 0;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = *d;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        total += v;
    }
    total % 10 == 0
}

#[cfg(test)]
mod luhn_tests {
    use super::luhn_ok;

    #[test]
    fn known_valid_visa_passes() {
        assert!(luhn_ok("4111111111111111"));
    }

    #[test]
    fn flipped_last_digit_fails() {
        assert!(!luhn_ok("4111111111111112"));
    }

    #[test]
    fn too_short_fails() {
        assert!(!luhn_ok("411111"));
    }

    #[test]
    fn too_long_fails() {
        assert!(!luhn_ok("41111111111111111111"));
    }

    #[test]
    fn ignores_non_digits() {
        assert!(luhn_ok("4111-1111-1111-1111"));
    }
}
