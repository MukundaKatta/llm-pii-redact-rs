/*!
llm-pii-redact: reversible PII redaction for LLM prompts.

Replace PII (email, phone, SSN, credit card) with stable placeholders before
sending text to an LLM, then restore the originals from the returned map.

```rust
use llm_pii_redact::Redactor;

let r = Redactor::default();
let (redacted, map) = r.redact("Contact user@example.com for help.");
assert!(redacted.contains("[EMAIL_0]"));
let restored = r.restore(&redacted, &map);
assert!(restored.contains("user@example.com"));
```
*/

use regex::Regex;
use std::collections::HashMap;

// ---- Luhn check -----------------------------------------------------------

fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap())
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
    sum % 10 == 0
}

// ---- PiiPattern -----------------------------------------------------------

/// A named PII pattern.
#[derive(Debug, Clone)]
pub struct PiiPattern {
    pub name: String,
    regex: Regex,
    /// If true, apply Luhn validation before treating match as PII.
    luhn: bool,
}

impl PiiPattern {
    pub fn new(name: &str, pattern: &str) -> Self {
        Self {
            name: name.to_owned(),
            regex: Regex::new(pattern).expect("invalid PII regex"),
            luhn: false,
        }
    }

    pub fn with_luhn(mut self) -> Self {
        self.luhn = true;
        self
    }
}

// ---- Redactor -------------------------------------------------------------

/// Redacts PII from text and provides reversible restoration.
pub struct Redactor {
    patterns: Vec<PiiPattern>,
    /// Optional hook: `custom_patterns` added on top of built-ins.
    extra: Vec<PiiPattern>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self {
            patterns: builtin_patterns(),
            extra: Vec::new(),
        }
    }
}

impl Redactor {
    /// Create with only the built-in patterns.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a custom pattern (appended after built-ins).
    pub fn with_pattern(mut self, p: PiiPattern) -> Self {
        self.extra.push(p);
        self
    }

    fn all_patterns(&self) -> impl Iterator<Item = &PiiPattern> {
        self.patterns.iter().chain(self.extra.iter())
    }

    /// Redact PII from `text`. Returns `(redacted_text, restore_map)`.
    ///
    /// The restore map maps placeholder → original value.
    pub fn redact(&self, text: &str) -> (String, HashMap<String, String>) {
        let mut result = text.to_owned();
        let mut map: HashMap<String, String> = HashMap::new();
        // Counter per pattern name.
        let mut counters: HashMap<String, usize> = HashMap::new();

        for pat in self.all_patterns() {
            let mut new_result = String::new();
            let mut last_end = 0;
            for m in pat.regex.find_iter(&result) {
                let matched = m.as_str();
                // For credit cards, run Luhn check.
                if pat.luhn && !luhn_check(matched) {
                    new_result.push_str(&result[last_end..m.end()]);
                    last_end = m.end();
                    continue;
                }
                let idx = counters.entry(pat.name.clone()).or_insert(0);
                let placeholder = format!("[{}_{}]", pat.name.to_uppercase(), idx);
                *idx += 1;
                map.insert(placeholder.clone(), matched.to_owned());
                new_result.push_str(&result[last_end..m.start()]);
                new_result.push_str(&placeholder);
                last_end = m.end();
            }
            new_result.push_str(&result[last_end..]);
            result = new_result;
        }

        (result, map)
    }

    /// Restore placeholders in `text` using the map from `redact()`.
    pub fn restore(&self, text: &str, map: &HashMap<String, String>) -> String {
        let mut result = text.to_owned();
        for (placeholder, original) in map {
            result = result.replace(placeholder.as_str(), original.as_str());
        }
        result
    }
}

fn builtin_patterns() -> Vec<PiiPattern> {
    vec![
        // Credit card (Luhn-validated).
        PiiPattern::new(
            "cc",
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        )
        .with_luhn(),
        // Email.
        PiiPattern::new(
            "email",
            r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b",
        ),
        // US SSN.
        PiiPattern::new("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
        // US phone.
        PiiPattern::new(
            "phone",
            r"\b(?:\+1\s?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        ),
    ]
}

/// Return the built-in PII pattern names.
pub fn builtin_pattern_names() -> Vec<&'static str> {
    vec!["cc", "email", "ssn", "phone"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_redacted() {
        let r = Redactor::new();
        let (out, map) = r.redact("send to user@example.com please");
        assert!(out.contains("[EMAIL_0]"));
        assert!(!out.contains("user@example.com"));
        assert_eq!(map["[EMAIL_0]"], "user@example.com");
    }

    #[test]
    fn email_restored() {
        let r = Redactor::new();
        let (redacted, map) = r.redact("email: user@example.com");
        let restored = r.restore(&redacted, &map);
        assert!(restored.contains("user@example.com"));
    }

    #[test]
    fn ssn_redacted() {
        let r = Redactor::new();
        let (out, _) = r.redact("SSN: 123-45-6789");
        assert!(out.contains("[SSN_0]"));
        assert!(!out.contains("123-45-6789"));
    }

    #[test]
    fn phone_redacted() {
        let r = Redactor::new();
        let (out, _) = r.redact("call 555-867-5309 now");
        assert!(out.contains("[PHONE_0]"));
    }

    #[test]
    fn no_pii_unchanged() {
        let r = Redactor::new();
        let text = "The sky is blue and 42 is the answer.";
        let (out, map) = r.redact(text);
        assert_eq!(out, text);
        assert!(map.is_empty());
    }

    #[test]
    fn multiple_emails_indexed() {
        let r = Redactor::new();
        let (out, map) = r.redact("a@a.com and b@b.com");
        assert!(out.contains("[EMAIL_0]"));
        assert!(out.contains("[EMAIL_1]"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn restore_multiple() {
        let r = Redactor::new();
        let (redacted, map) = r.redact("a@a.com and b@b.com");
        let restored = r.restore(&redacted, &map);
        assert!(restored.contains("a@a.com"));
        assert!(restored.contains("b@b.com"));
    }

    #[test]
    fn luhn_valid_cc_redacted() {
        // Known valid Visa test number
        let r = Redactor::new();
        let (out, map) = r.redact("card: 4111111111111111");
        assert!(out.contains("[CC_0]"));
        assert_eq!(map["[CC_0]"], "4111111111111111");
    }

    #[test]
    fn luhn_invalid_number_not_redacted() {
        let r = Redactor::new();
        // Same length as a Visa but Luhn fails
        let (out, _) = r.redact("4111111111111112");
        assert!(!out.contains("[CC_0]"));
    }

    #[test]
    fn luhn_check_valid() {
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500005555555559")); // Mastercard test
    }

    #[test]
    fn luhn_check_invalid() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890123456"));
    }

    #[test]
    fn luhn_check_too_short() {
        assert!(!luhn_check("123"));
    }

    #[test]
    fn custom_pattern_added() {
        let custom = PiiPattern::new("zip", r"\b\d{5}(?:-\d{4})?\b");
        let r = Redactor::new().with_pattern(custom);
        let (out, map) = r.redact("zip code 12345 here");
        assert!(map.values().any(|v| v == "12345"), "map={:?} out={}", map, out);
    }

    #[test]
    fn builtin_pattern_names_non_empty() {
        assert!(!builtin_pattern_names().is_empty());
    }

    #[test]
    fn empty_text() {
        let r = Redactor::new();
        let (out, map) = r.redact("");
        assert_eq!(out, "");
        assert!(map.is_empty());
    }

    #[test]
    fn restore_no_placeholders_unchanged() {
        let r = Redactor::new();
        let map = HashMap::new();
        let text = "plain text no placeholders";
        assert_eq!(r.restore(text, &map), text);
    }
}
