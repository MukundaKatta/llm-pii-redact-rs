// Integration tests for llm-pii-redact.
//
// Fixtures intentionally use synthetic placeholder shapes:
//   - emails end in `example.invalid`
//   - SSNs use 000-00-0000 / 999-99-9999 style
//   - credit-card examples are the well-known industry test values
//   - phone numbers use 555-prefix exchanges
// This keeps GitHub Push Protection happy and keeps the suite from looking
// like a credential dump.

use std::collections::HashMap;

use llm_pii_redact::{Redactor, CREDIT_CARD, EMAIL, IBAN, IP_V4, IP_V6, PHONE_US, SSN, URL};

// -- Email --------------------------------------------------------------------

#[test]
fn email_basic_hit() {
    let r = Redactor::default();
    let dets = r.detect("write to ops@example.invalid");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].kind, EMAIL);
    assert_eq!(dets[0].value, "ops@example.invalid");
}

#[test]
fn email_plus_tag_hit() {
    let r = Redactor::default();
    let dets = r.detect("alias is a.b+filter@sub.example.invalid");
    assert!(dets
        .iter()
        .any(|d| d.value == "a.b+filter@sub.example.invalid"));
}

#[test]
fn email_miss_on_bare_at() {
    let r = Redactor::default();
    assert!(r.detect("@notanemail").is_empty());
}

// -- US phone -----------------------------------------------------------------

#[test]
fn phone_with_dashes_hit() {
    let r = Redactor::default();
    let out = r.redact("call 555-123-4567 today");
    assert_eq!(out.text, "call <PHONE_US_0> today");
    let mut expected: HashMap<String, String> = HashMap::new();
    expected.insert("<PHONE_US_0>".to_string(), "555-123-4567".to_string());
    assert_eq!(out.mapping, expected);
}

#[test]
fn phone_parens_and_plus_one_hit() {
    let r = Redactor::default();
    for src in ["+1 (555) 123-4567", "+15551234567", "(555) 123 4567"] {
        let dets = r.detect(src);
        assert_eq!(dets.len(), 1, "missed phone form: {src}");
        assert_eq!(dets[0].kind, PHONE_US);
    }
}

#[test]
fn phone_miss_on_short_number() {
    let r = Redactor::default();
    assert!(r.detect("press 911 now").is_empty());
}

// -- SSN ----------------------------------------------------------------------

#[test]
fn ssn_dashed_hit() {
    let r = Redactor::default();
    let dets = r.detect("SSN 000-00-0000");
    let pairs: Vec<(String, String)> = dets
        .iter()
        .map(|d| (d.kind.clone(), d.value.clone()))
        .collect();
    assert_eq!(pairs, vec![(SSN.to_string(), "000-00-0000".to_string())]);
}

#[test]
fn ssn_nine_digit_hit() {
    let r = Redactor::default();
    let dets = r.detect("SSN 000000000 maybe");
    assert!(dets.iter().any(|d| d.kind == SSN && d.value == "000000000"));
}

#[test]
fn ssn_miss_on_longer_run() {
    let r = Redactor::default();
    // 10 contiguous digits should not match SSN as a 9-digit token.
    // Bare 10-digit run is plausibly a US phone, so use a form that the
    // phone detector also rejects (leading digit context).
    let dets = r.detect("ref 1234567890123 here");
    assert!(!dets.iter().any(|d| d.kind == SSN));
}

// -- Credit card --------------------------------------------------------------

#[test]
fn credit_card_luhn_valid_hit() {
    // 4111 1111 1111 1111 is the well-known industry-published Luhn-valid
    // Visa test number. It is not a real card.
    let r = Redactor::default();
    let dets = r.detect("card 4111 1111 1111 1111 expiring");
    assert!(dets.iter().any(|d| d.kind == CREDIT_CARD));
}

#[test]
fn credit_card_luhn_invalid_rejected() {
    // Same shape, last digit flipped to break Luhn.
    let r = Redactor::default();
    let dets = r.detect("card 4111 1111 1111 1112 expiring");
    assert!(!dets.iter().any(|d| d.kind == CREDIT_CARD));
}

#[test]
fn credit_card_amex_15_digits_hit() {
    // Industry-published Amex test number. Luhn valid.
    let r = Redactor::default();
    let dets = r.detect("amex 3782 822463 10005 charge");
    assert!(dets.iter().any(|d| d.kind == CREDIT_CARD));
}

#[test]
fn cc_helper_only_detects_cc() {
    let r = Redactor::cc();
    let dets = r.detect("ops@example.invalid card 4111 1111 1111 1111");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].kind, CREDIT_CARD);
}

// -- IPv4 / IPv6 --------------------------------------------------------------

#[test]
fn ipv4_hit() {
    let r = Redactor::default();
    let dets = r.detect("server 192.0.2.10 is up");
    assert!(dets
        .iter()
        .any(|d| d.kind == IP_V4 && d.value == "192.0.2.10"));
}

#[test]
fn ipv4_miss_on_out_of_range() {
    let r = Redactor::default();
    let dets = r.detect("server 999.999.999.999 fake");
    assert!(!dets.iter().any(|d| d.kind == IP_V4));
}

#[test]
fn ipv6_hit() {
    let r = Redactor::default();
    let dets = r.detect("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ok");
    assert!(dets.iter().any(|d| d.kind == IP_V6));
}

#[test]
fn ipv6_compressed_hit() {
    let r = Redactor::default();
    let dets = r.detect("loopback ::1 reachable");
    assert!(dets.iter().any(|d| d.kind == IP_V6));
}

#[test]
fn ip_helper_detects_v4_and_v6() {
    let r = Redactor::ip();
    let dets = r.detect("v4 192.0.2.1 and v6 2001:db8::1 here");
    assert!(dets.iter().any(|d| d.kind == IP_V4));
    assert!(dets.iter().any(|d| d.kind == IP_V6));
}

// -- IBAN ---------------------------------------------------------------------

#[test]
fn iban_hit() {
    // ISO 13616 IBAN example value (DE example used in spec docs).
    let r = Redactor::default();
    let dets = r.detect("send to DE89370400440532013000 please");
    assert!(dets.iter().any(|d| d.kind == IBAN));
}

#[test]
fn iban_miss_on_short_value() {
    let r = Redactor::default();
    let dets = r.detect("DE89 short");
    assert!(!dets.iter().any(|d| d.kind == IBAN));
}

// -- URL ----------------------------------------------------------------------

#[test]
fn url_https_hit() {
    let r = Redactor::default();
    let dets = r.detect("see https://example.invalid/path?q=1 for details");
    assert!(dets
        .iter()
        .any(|d| d.kind == URL && d.value.starts_with("https://example.invalid")));
}

#[test]
fn url_http_hit() {
    let r = Redactor::default();
    let dets = r.detect("plain http://x.invalid/y here");
    assert!(dets.iter().any(|d| d.kind == URL));
}

// -- Dedupe / placeholder behavior -------------------------------------------

#[test]
fn same_value_twice_shares_placeholder() {
    let r = Redactor::default();
    let out = r.redact("mail a@b.invalid and a@b.invalid again");
    let mut expected: HashMap<String, String> = HashMap::new();
    expected.insert("<EMAIL_0>".to_string(), "a@b.invalid".to_string());
    assert_eq!(out.mapping, expected);
    assert_eq!(out.text.matches("<EMAIL_0>").count(), 2);
}

#[test]
fn distinct_values_get_distinct_placeholders() {
    let r = Redactor::default();
    let out = r.redact("a@b.invalid and c@d.invalid");
    let values: std::collections::HashSet<String> = out.mapping.values().cloned().collect();
    let expected_values: std::collections::HashSet<String> =
        ["a@b.invalid".to_string(), "c@d.invalid".to_string()]
            .into_iter()
            .collect();
    assert_eq!(values, expected_values);
    let keys: std::collections::HashSet<String> = out.mapping.keys().cloned().collect();
    let expected_keys: std::collections::HashSet<String> =
        ["<EMAIL_0>".to_string(), "<EMAIL_1>".to_string()]
            .into_iter()
            .collect();
    assert_eq!(keys, expected_keys);
}

#[test]
fn placeholders_namespaced_by_type() {
    let r = Redactor::default();
    let out = r.redact("a@b.invalid call 555-123-4567");
    assert!(out.mapping.contains_key("<EMAIL_0>"));
    assert!(out.mapping.contains_key("<PHONE_US_0>"));
}

// -- Redact + reveal round trip ----------------------------------------------

#[test]
fn redact_reveal_round_trip() {
    let r = Redactor::default();
    let src = "Email me at john@example.invalid or call 555-123-4567";
    let out = r.redact(src);
    assert!(!out.text.contains("john@example.invalid"));
    assert!(!out.text.contains("555-123-4567"));
    assert_eq!(r.reveal(&out.text, &out.mapping), src);
}

#[test]
fn reveal_handles_unknown_placeholders() {
    let r = Redactor::default();
    let mut mapping: HashMap<String, String> = HashMap::new();
    mapping.insert("<EMAIL_0>".to_string(), "a@b.invalid".to_string());
    // No <FOO_0> entry, so it must be left alone.
    let out = r.reveal("hello <FOO_0>", &mapping);
    assert_eq!(out, "hello <FOO_0>");
}

#[test]
fn reveal_does_not_confuse_index_prefixes() {
    let r = Redactor::default();
    let text = "<EMAIL_10> and <EMAIL_1>";
    let mut mapping: HashMap<String, String> = HashMap::new();
    mapping.insert("<EMAIL_1>".to_string(), "one@x.invalid".to_string());
    mapping.insert("<EMAIL_10>".to_string(), "ten@x.invalid".to_string());
    assert_eq!(r.reveal(text, &mapping), "ten@x.invalid and one@x.invalid");
}

#[test]
fn reveal_with_empty_mapping_returns_text() {
    let r = Redactor::default();
    let mapping: HashMap<String, String> = HashMap::new();
    assert_eq!(r.reveal("nothing to do", &mapping), "nothing to do");
}

// -- Custom pattern ----------------------------------------------------------

#[test]
fn custom_pattern_detected_and_redacted() {
    let r = Redactor::default()
        .with_pattern("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}")
        .expect("regex compiles");
    let out = r.redact("key=AKIAABCDEFGHIJKLMNOP ok");
    assert!(out.text.contains("<AWS_ACCESS_KEY_0>"));
    assert_eq!(out.mapping["<AWS_ACCESS_KEY_0>"], "AKIAABCDEFGHIJKLMNOP");
}

#[test]
fn custom_pattern_invalid_regex_rejected() {
    // Unbalanced paren.
    let result = Redactor::new().with_pattern("BAD", "(");
    assert!(result.is_err());
}

#[test]
fn custom_pattern_name_required() {
    let result = Redactor::new().with_pattern("", r".+");
    assert!(result.is_err());
}

// -- Type filtering / single-detector helpers --------------------------------

#[test]
fn email_helper_leaves_phone_untouched() {
    let r = Redactor::email();
    let out = r.redact("a@b.invalid phone 555-123-4567");
    assert!(out.text.contains("555-123-4567"));
    assert!(out.text.contains("<EMAIL_0>"));
    let values: std::collections::HashSet<String> = out.mapping.values().cloned().collect();
    let expected: std::collections::HashSet<String> =
        ["a@b.invalid".to_string()].into_iter().collect();
    assert_eq!(values, expected);
}

#[test]
fn phone_helper_leaves_email_untouched() {
    let r = Redactor::phone();
    let out = r.redact("ops@example.invalid call 555-123-4567");
    assert!(out.text.contains("ops@example.invalid"));
    assert!(out.text.contains("<PHONE_US_0>"));
}

#[test]
fn ssn_helper_leaves_email_untouched() {
    let r = Redactor::ssn();
    let out = r.redact("ops@example.invalid ssn 000-00-0000");
    assert!(out.text.contains("ops@example.invalid"));
    assert!(out.text.contains("<SSN_0>"));
}

#[test]
fn detector_names_reflect_registration_order() {
    let r = Redactor::default();
    assert_eq!(
        r.detector_names(),
        vec![EMAIL, PHONE_US, SSN, CREDIT_CARD, IP_V4, IP_V6, IBAN, URL]
    );
}

#[test]
fn empty_redactor_finds_nothing() {
    let r = Redactor::new();
    let out = r.redact("ops@example.invalid 555-123-4567");
    assert_eq!(out.text, "ops@example.invalid 555-123-4567");
    assert!(out.mapping.is_empty());
}

// -- Edge cases ---------------------------------------------------------------

#[test]
fn empty_text_returns_empty() {
    let r = Redactor::default();
    let out = r.redact("");
    assert_eq!(out.text, "");
    assert!(out.mapping.is_empty());
    assert!(r.detect("").is_empty());
}

#[test]
fn no_pii_returns_text_unchanged() {
    let r = Redactor::default();
    let src = "no personal data here, just words";
    let out = r.redact(src);
    assert_eq!(out.text, src);
    assert!(out.mapping.is_empty());
}

#[test]
fn detect_returns_value_matching_span() {
    let r = Redactor::default();
    let src = "see john@example.invalid here";
    let dets = r.detect(src);
    assert_eq!(dets.len(), 1);
    let d = &dets[0];
    assert_eq!(&src[d.start..d.end], d.value);
}

#[test]
fn overlapping_matches_handled_deterministically() {
    // A URL string that contains an email-shaped substring. Whichever
    // detector wins on overlap, the output must not double-count.
    let r = Redactor::default();
    let src = "visit https://site.invalid/path";
    let out = r.redact(src);
    assert_eq!(out.mapping.keys().filter(|k| k.starts_with('<')).count(), 1);
}

#[test]
fn detect_returns_matches_in_document_order() {
    let r = Redactor::default();
    let src = "first a@b.invalid then 555-123-4567";
    let dets = r.detect(src);
    let starts: Vec<usize> = dets.iter().map(|d| d.start).collect();
    let mut sorted = starts.clone();
    sorted.sort();
    assert_eq!(starts, sorted);
}

#[test]
fn redact_preserves_text_outside_matches() {
    let r = Redactor::default();
    let src = "before a@b.invalid middle 555-123-4567 after";
    let out = r.redact(src);
    assert!(out.text.starts_with("before "));
    assert!(out.text.ends_with(" after"));
    assert!(out.text.contains(" middle "));
}

#[test]
fn redacted_is_default_constructible() {
    let r: llm_pii_redact::Redacted = Default::default();
    assert!(r.text.is_empty());
    assert!(r.mapping.is_empty());
}
