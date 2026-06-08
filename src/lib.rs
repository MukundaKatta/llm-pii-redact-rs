/*!
llm-pii-redact: reversible PII redaction for LLM prompts and tool outputs.

Replace PII (email, phone, SSN, credit card, IPs, IBAN, URL) with stable
placeholders before sending text to an LLM, then restore the originals from
the returned mapping.

```rust
use llm_pii_redact::Redactor;

let r = Redactor::default();
let out = r.redact("Email me at ops@example.invalid or call 555-123-4567");
// out.text    -> "Email me at <EMAIL_0> or call <PHONE_US_0>"
// out.mapping -> { "<EMAIL_0>": "ops@example.invalid",
//                  "<PHONE_US_0>": "555-123-4567" }
assert!(out.text.contains("<EMAIL_0>"));

let assistant_reply = format!("Confirmed: {}", "<EMAIL_0>");
let restored = r.reveal(&assistant_reply, &out.mapping);
assert_eq!(restored, "Confirmed: ops@example.invalid");
```

Stable placeholders mean the LLM keeps coherent references: repeated values
share a single placeholder, so the redacted text is deterministic.

For a multi-turn conversation where a value must keep the *same* placeholder
across several messages, use a [`Session`] (via [`Redactor::session`]), which
accumulates one placeholder mapping across every call.
*/

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use regex::Regex;

// ---- Detector kind constants ----------------------------------------------

/// Email addresses, e.g. `ops@example.invalid`.
pub const EMAIL: &str = "EMAIL";
/// US phone numbers, e.g. `555-123-4567`, `+1 (555) 123-4567`.
pub const PHONE_US: &str = "PHONE_US";
/// US Social Security Numbers, e.g. `000-00-0000` or 9 contiguous digits.
pub const SSN: &str = "SSN";
/// Credit-card numbers (13-19 digit runs, Luhn-validated).
pub const CREDIT_CARD: &str = "CREDIT_CARD";
/// IPv4 addresses, e.g. `192.0.2.10`.
pub const IP_V4: &str = "IP_V4";
/// IPv6 addresses, e.g. `2001:db8::1`, `::1`.
pub const IP_V6: &str = "IP_V6";
/// IBAN account numbers, e.g. `DE89370400440532013000`.
pub const IBAN: &str = "IBAN";
/// HTTP/HTTPS URLs.
pub const URL: &str = "URL";

// ---- Errors ---------------------------------------------------------------

/// Error returned when a custom pattern cannot be registered.
#[derive(Debug)]
pub enum PatternError {
    /// The detector name was empty.
    EmptyName,
    /// The supplied regex failed to compile.
    InvalidRegex(regex::Error),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternError::EmptyName => write!(f, "detector name must not be empty"),
            PatternError::InvalidRegex(e) => write!(f, "invalid regex: {e}"),
        }
    }
}

impl Error for PatternError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PatternError::InvalidRegex(e) => Some(e),
            PatternError::EmptyName => None,
        }
    }
}

// ---- Luhn check -----------------------------------------------------------

/// Validate a candidate credit-card string with the Luhn checksum.
///
/// Non-digit characters (spaces, dashes) are ignored. The run must contain
/// between 13 and 19 digits.
fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).expect("filtered to ascii digit"))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut n = d;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    // `% 10 == 0` is kept (rather than `is_multiple_of`) to avoid raising the
    // crate's minimum supported Rust version.
    #[allow(clippy::manual_is_multiple_of)]
    {
        sum % 10 == 0
    }
}

// ---- Detection ------------------------------------------------------------

/// A single PII match found in a piece of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The detector kind that produced this match (e.g. [`EMAIL`]).
    pub kind: String,
    /// The matched text (the original PII value).
    pub value: String,
    /// Byte offset where the match starts.
    pub start: usize,
    /// Byte offset where the match ends (exclusive).
    pub end: usize,
}

// ---- Redacted -------------------------------------------------------------

/// The result of [`Redactor::redact`]: redacted text plus the reverse mapping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Redacted {
    /// Text with every detected value replaced by a `<KIND_N>` placeholder.
    pub text: String,
    /// Maps each placeholder to its original value.
    pub mapping: HashMap<String, String>,
}

// ---- Placeholder allocation ------------------------------------------------

/// Mutable bookkeeping for allocating stable `<KIND_N>` placeholders.
///
/// Shared by [`Redactor::redact`] (a fresh state per call) and [`Session`]
/// (one state reused across many calls), so the allocation rules — one
/// placeholder per distinct value, per-kind counters starting at `0` — are
/// defined in exactly one place.
#[derive(Debug, Clone, Default)]
struct PlaceholderState {
    /// Maps each placeholder to its original value (the reverse mapping).
    mapping: HashMap<String, String>,
    /// Maps each seen value to the placeholder already assigned to it.
    value_to_placeholder: HashMap<String, String>,
    /// Per-kind running index used to number new placeholders.
    counters: HashMap<String, usize>,
}

impl PlaceholderState {
    /// Return the placeholder for `(kind, value)`, allocating a new one on the
    /// first sight of `value` and reusing it on every subsequent sight.
    fn placeholder_for(&mut self, kind: &str, value: &str) -> String {
        if let Some(existing) = self.value_to_placeholder.get(value) {
            return existing.clone();
        }
        let idx = self.counters.entry(kind.to_owned()).or_insert(0);
        let ph = format!("<{kind}_{idx}>");
        *idx += 1;
        self.mapping.insert(ph.clone(), value.to_owned());
        self.value_to_placeholder
            .insert(value.to_owned(), ph.clone());
        ph
    }
}

// ---- Detector -------------------------------------------------------------

#[derive(Debug, Clone)]
struct Detector {
    kind: String,
    regex: Regex,
    luhn: bool,
}

impl Detector {
    fn new(kind: &str, pattern: &str, luhn: bool) -> Self {
        Self {
            kind: kind.to_owned(),
            regex: Regex::new(pattern).expect("built-in PII regex must compile"),
            luhn,
        }
    }
}

// ---- Built-in patterns ----------------------------------------------------

// A US phone is matched only when it carries some structural marker (a `+1`
// prefix, parentheses, or a separator) so that bare 9/10-digit runs do not
// shadow the SSN detector or produce false positives like `911`.
const PHONE_PATTERN: &str =
    r"(?:\+1[-.\s]?\d{10}\b)|(?:(?:\+1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]?\d{4})";

const EMAIL_PATTERN: &str = r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b";

// Dashed SSN, or exactly nine contiguous digits.
const SSN_PATTERN: &str = r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b";

// 13-19 digit run, optionally separated by single spaces or dashes. Luhn is
// applied afterwards.
const CC_PATTERN: &str = r"\b\d(?:[ -]?\d){12,18}\b";

const IPV4_PATTERN: &str = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b";

// Full and compressed IPv6 forms. Most-specific alternatives first so the
// longest valid address wins.
const IPV6_PATTERN: &str = r"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|:(?::[0-9a-f]{1,4}){1,7}|(?:[0-9a-f]{1,4}:){1,7}:";

// IBAN: two-letter country code, two check digits, then 11-30 alphanumerics.
const IBAN_PATTERN: &str = r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b";

const URL_PATTERN: &str = r"(?i)https?://[^\s]+";

fn email_detector() -> Detector {
    Detector::new(EMAIL, EMAIL_PATTERN, false)
}
fn phone_detector() -> Detector {
    Detector::new(PHONE_US, PHONE_PATTERN, false)
}
fn ssn_detector() -> Detector {
    Detector::new(SSN, SSN_PATTERN, false)
}
fn cc_detector() -> Detector {
    Detector::new(CREDIT_CARD, CC_PATTERN, true)
}
fn ipv4_detector() -> Detector {
    Detector::new(IP_V4, IPV4_PATTERN, false)
}
fn ipv6_detector() -> Detector {
    Detector::new(IP_V6, IPV6_PATTERN, false)
}
fn iban_detector() -> Detector {
    Detector::new(IBAN, IBAN_PATTERN, false)
}
fn url_detector() -> Detector {
    Detector::new(URL, URL_PATTERN, false)
}

// ---- Redactor -------------------------------------------------------------

/// Detects PII in text and redacts it to reversible placeholders.
#[derive(Debug, Clone)]
pub struct Redactor {
    detectors: Vec<Detector>,
}

/// The default redactor registers all built-in detectors, in this order:
/// email, phone, SSN, credit card, IPv4, IPv6, IBAN, URL.
impl Default for Redactor {
    fn default() -> Self {
        Self {
            detectors: vec![
                email_detector(),
                phone_detector(),
                ssn_detector(),
                cc_detector(),
                ipv4_detector(),
                ipv6_detector(),
                iban_detector(),
                url_detector(),
            ],
        }
    }
}

impl Redactor {
    /// Create an empty redactor with no detectors registered.
    ///
    /// Use [`Redactor::default`] for the full built-in set, or chain
    /// [`Redactor::with_pattern`] to add custom detectors.
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// A redactor with only the email detector.
    pub fn email() -> Self {
        Self {
            detectors: vec![email_detector()],
        }
    }

    /// A redactor with only the US phone detector.
    pub fn phone() -> Self {
        Self {
            detectors: vec![phone_detector()],
        }
    }

    /// A redactor with only the SSN detector.
    pub fn ssn() -> Self {
        Self {
            detectors: vec![ssn_detector()],
        }
    }

    /// A redactor with only the credit-card detector.
    pub fn cc() -> Self {
        Self {
            detectors: vec![cc_detector()],
        }
    }

    /// A redactor with only the IPv4 and IPv6 detectors.
    pub fn ip() -> Self {
        Self {
            detectors: vec![ipv4_detector(), ipv6_detector()],
        }
    }

    /// Register a custom detector.
    ///
    /// Returns an error if `name` is empty or `pattern` is not a valid regex.
    pub fn with_pattern(mut self, name: &str, pattern: &str) -> Result<Self, PatternError> {
        if name.is_empty() {
            return Err(PatternError::EmptyName);
        }
        let regex = Regex::new(pattern).map_err(PatternError::InvalidRegex)?;
        self.detectors.push(Detector {
            kind: name.to_owned(),
            regex,
            luhn: false,
        });
        Ok(self)
    }

    /// The names of the registered detectors, in registration order.
    pub fn detector_names(&self) -> Vec<&str> {
        self.detectors.iter().map(|d| d.kind.as_str()).collect()
    }

    /// Find every PII match in `text`.
    ///
    /// Matches are returned in document order and never overlap: where two
    /// detectors match the same region, the leftmost-longest match wins
    /// (ties broken by detector registration order).
    pub fn detect(&self, text: &str) -> Vec<Detection> {
        // Collect every candidate, tagged with its detector index for
        // deterministic tie-breaking.
        let mut candidates: Vec<(usize, Detection)> = Vec::new();
        for (idx, det) in self.detectors.iter().enumerate() {
            for m in det.regex.find_iter(text) {
                if det.luhn && !luhn_check(m.as_str()) {
                    continue;
                }
                candidates.push((
                    idx,
                    Detection {
                        kind: det.kind.clone(),
                        value: m.as_str().to_owned(),
                        start: m.start(),
                        end: m.end(),
                    },
                ));
            }
        }

        // Leftmost-longest, then earliest detector index.
        candidates.sort_by(|a, b| {
            a.1.start
                .cmp(&b.1.start)
                .then(b.1.end.cmp(&a.1.end))
                .then(a.0.cmp(&b.0))
        });

        let mut chosen: Vec<Detection> = Vec::new();
        let mut covered_to = 0usize;
        for (_, det) in candidates {
            if det.start >= covered_to {
                covered_to = det.end;
                chosen.push(det);
            }
        }
        chosen
    }

    /// Redact `text`, returning the placeholder-substituted text and the
    /// reverse mapping.
    ///
    /// Identical values share a single placeholder, so the output is
    /// deterministic and the LLM can refer to the same entity consistently.
    ///
    /// Each call is independent: placeholder counters start from `0`. To keep
    /// placeholders consistent across several pieces of text (for example a
    /// prompt and a later follow-up message), use a [`Session`] instead.
    pub fn redact(&self, text: &str) -> Redacted {
        let mut state = PlaceholderState::default();
        let out = self.redact_into(text, &mut state);
        Redacted {
            text: out,
            mapping: state.mapping,
        }
    }

    /// Redact `text` against the shared placeholder `state`, returning only the
    /// substituted text. `state` accumulates the value-to-placeholder mapping
    /// and per-kind counters, so repeated values across calls reuse the same
    /// placeholder. This is the shared core of [`Redactor::redact`] and
    /// [`Session::redact`].
    fn redact_into(&self, text: &str, state: &mut PlaceholderState) -> String {
        let detections = self.detect(text);

        let mut out = String::with_capacity(text.len());
        let mut last_end = 0usize;
        for det in &detections {
            out.push_str(&text[last_end..det.start]);
            let placeholder = state.placeholder_for(&det.kind, &det.value);
            out.push_str(&placeholder);
            last_end = det.end;
        }
        out.push_str(&text[last_end..]);
        out
    }

    /// Restore placeholders in `text` using a mapping from [`Redactor::redact`].
    ///
    /// Unknown placeholders are left untouched. Longer placeholders are
    /// substituted first so that `<EMAIL_1>` does not corrupt `<EMAIL_10>`.
    pub fn reveal(&self, text: &str, mapping: &HashMap<String, String>) -> String {
        reveal_with(text, mapping)
    }

    /// Start a stateful [`Session`] that keeps placeholders consistent across
    /// several [`Session::redact`] calls.
    ///
    /// ```
    /// use llm_pii_redact::Redactor;
    ///
    /// let mut session = Redactor::default().session();
    /// let first = session.redact("contact a@b.invalid");
    /// // The same value seen again reuses the original placeholder, even
    /// // though this is a separate call.
    /// let second = session.redact("again, a@b.invalid");
    /// assert!(first.contains("<EMAIL_0>"));
    /// assert!(second.contains("<EMAIL_0>"));
    /// ```
    pub fn session(self) -> Session {
        Session {
            redactor: self,
            state: PlaceholderState::default(),
        }
    }
}

/// Restore placeholders in `text` using `mapping`.
///
/// Unknown placeholders are left untouched. Longer placeholders are
/// substituted first so that `<EMAIL_1>` does not corrupt `<EMAIL_10>`.
fn reveal_with(text: &str, mapping: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = mapping.keys().collect();
    keys.sort_by(|a, b| b.len().cmp(&a.len()).then(a.as_str().cmp(b.as_str())));

    let mut result = text.to_owned();
    for key in keys {
        if let Some(original) = mapping.get(key) {
            result = result.replace(key.as_str(), original.as_str());
        }
    }
    result
}

// ---- Session --------------------------------------------------------------

/// A stateful redactor that keeps placeholders consistent across calls.
///
/// A bare [`Redactor`] numbers placeholders from `0` on every [`Redactor::redact`]
/// call, so the same value can map to `<EMAIL_0>` in one call and `<EMAIL_0>`
/// again — but two *different* texts processed separately have no shared
/// numbering, and `reveal` needs the mapping from the matching call.
///
/// A `Session` solves the multi-message case: it accumulates one mapping across
/// every [`Session::redact`] call, so a value that appeared in an earlier
/// message reuses the placeholder it was first assigned, and a single
/// [`Session::reveal`] (or the accumulated [`Session::mapping`]) restores values
/// from *any* of the redacted messages.
///
/// ```
/// use llm_pii_redact::Redactor;
///
/// let mut session = Redactor::default().session();
/// let prompt = session.redact("Email a@b.invalid and c@d.invalid");
/// let followup = session.redact("Resend to a@b.invalid only");
///
/// // a@b.invalid keeps <EMAIL_0> in both messages.
/// assert!(prompt.contains("<EMAIL_0>"));
/// assert!(followup.contains("<EMAIL_0>"));
/// assert!(!followup.contains("<EMAIL_1>"));
///
/// // One mapping reveals placeholders from either message.
/// assert_eq!(session.reveal("ok <EMAIL_1>"), "ok c@d.invalid");
/// ```
#[derive(Debug, Clone)]
pub struct Session {
    redactor: Redactor,
    state: PlaceholderState,
}

impl Session {
    /// Redact `text`, reusing placeholders already assigned in this session and
    /// allocating new ones for values seen for the first time.
    pub fn redact(&mut self, text: &str) -> String {
        self.redactor.redact_into(text, &mut self.state)
    }

    /// The accumulated placeholder-to-value mapping for every value redacted in
    /// this session so far.
    pub fn mapping(&self) -> &HashMap<String, String> {
        &self.state.mapping
    }

    /// Restore placeholders in `text` using the session's accumulated mapping.
    ///
    /// Because the mapping spans every [`Session::redact`] call, this restores
    /// values that were redacted in any earlier message of the session.
    pub fn reveal(&self, text: &str) -> String {
        reveal_with(text, &self.state.mapping)
    }

    /// Consume the session and return the underlying [`Redactor`].
    pub fn into_redactor(self) -> Redactor {
        self.redactor
    }
}

/// Return the built-in detector kind names in registration order.
pub fn builtin_detector_names() -> Vec<&'static str> {
    vec![EMAIL, PHONE_US, SSN, CREDIT_CARD, IP_V4, IP_V6, IBAN, URL]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_known_test_numbers() {
        assert!(luhn_check("4111111111111111")); // Visa
        assert!(luhn_check("5500005555555559")); // Mastercard
        assert!(luhn_check("378282246310005")); // Amex (15)
    }

    #[test]
    fn luhn_rejects_bad_or_short() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890123456"));
        assert!(!luhn_check("123"));
    }

    #[test]
    fn default_registers_all_detectors() {
        let r = Redactor::default();
        assert_eq!(r.detector_names(), builtin_detector_names());
    }

    #[test]
    fn new_is_empty() {
        let r = Redactor::new();
        assert!(r.detector_names().is_empty());
    }

    #[test]
    fn redact_round_trips() {
        let r = Redactor::default();
        let src = "reach me at a@b.invalid or 555-123-4567";
        let out = r.redact(src);
        assert!(!out.text.contains("a@b.invalid"));
        assert_eq!(r.reveal(&out.text, &out.mapping), src);
    }

    #[test]
    fn repeated_value_shares_one_placeholder() {
        let r = Redactor::email();
        let out = r.redact("a@b.invalid and a@b.invalid");
        assert_eq!(out.mapping.len(), 1);
        assert_eq!(out.text.matches("<EMAIL_0>").count(), 2);
    }

    #[test]
    fn with_pattern_rejects_empty_name_and_bad_regex() {
        assert!(Redactor::new().with_pattern("", r".+").is_err());
        assert!(Redactor::new().with_pattern("X", "(").is_err());
        assert!(Redactor::new().with_pattern("X", r"\d+").is_ok());
    }

    #[test]
    fn session_reuses_placeholder_across_calls() {
        let mut s = Redactor::email().session();
        let first = s.redact("ping a@b.invalid");
        let second = s.redact("ping a@b.invalid again");
        assert!(first.contains("<EMAIL_0>"));
        assert!(second.contains("<EMAIL_0>"));
        // Only one mapping entry, shared across both messages.
        assert_eq!(s.mapping().len(), 1);
    }

    #[test]
    fn session_numbers_new_values_continuing_from_prior_calls() {
        let mut s = Redactor::email().session();
        let _ = s.redact("a@b.invalid");
        let second = s.redact("now c@d.invalid");
        // The second distinct value continues the counter rather than resetting.
        assert!(second.contains("<EMAIL_1>"));
        assert_eq!(s.mapping().len(), 2);
    }

    #[test]
    fn session_reveal_spans_all_calls() {
        let mut s = Redactor::default().session();
        let _ = s.redact("Email a@b.invalid and c@d.invalid");
        let _ = s.redact("Resend to a@b.invalid only");
        // A single reveal restores values first seen in different calls.
        assert_eq!(
            s.reveal("<EMAIL_0> and <EMAIL_1>"),
            "a@b.invalid and c@d.invalid"
        );
    }

    #[test]
    fn session_into_redactor_round_trips() {
        let r = Redactor::email();
        let names = r
            .detector_names()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let s = r.session();
        let back = s.into_redactor();
        let back_names = back
            .detector_names()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        assert_eq!(names, back_names);
    }

    #[test]
    fn plain_redact_still_resets_per_call() {
        // The stateless API must be unchanged: each call starts at index 0.
        let r = Redactor::email();
        let a = r.redact("a@b.invalid");
        let b = r.redact("c@d.invalid");
        assert!(a.text.contains("<EMAIL_0>"));
        assert!(b.text.contains("<EMAIL_0>"));
    }
}
