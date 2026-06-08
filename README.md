# llm-pii-redact

[![Crates.io](https://img.shields.io/crates/v/llm-pii-redact.svg)](https://crates.io/crates/llm-pii-redact)
[![Documentation](https://docs.rs/llm-pii-redact/badge.svg)](https://docs.rs/llm-pii-redact)
[![License](https://img.shields.io/crates/l/llm-pii-redact.svg)](https://crates.io/crates/llm-pii-redact)

**Regex-based PII redaction for LLM prompts and tool outputs, with reversible placeholders.**

```rust
use llm_pii_redact::Redactor;

let r = Redactor::default();
let out = r.redact("Email me at ops@example.invalid or call 555-123-4567");
// out.text    -> "Email me at <EMAIL_0> or call <PHONE_US_0>"
// out.mapping -> { "<EMAIL_0>": "ops@example.invalid",
//                  "<PHONE_US_0>": "555-123-4567" }

let answer_from_llm = format!("Confirmed: <EMAIL_0>");
let restored = r.reveal(&answer_from_llm, &out.mapping);
// restored -> "Confirmed: ops@example.invalid"
```

Stable placeholders mean the LLM keeps coherent references (talk about "<EMAIL_0>" five times in the reply, restore to the real address everywhere). Repeated values share a single placeholder, so the redacted text is deterministic.

Catches by default:

| Type | Example shape |
|---|---|
| `EMAIL` | `ops@example.invalid` |
| `PHONE_US` | `555-123-4567`, `+1 (555) 123-4567` |
| `SSN` | `000-00-0000`, 9 contiguous digits |
| `CREDIT_CARD` | 13-19 digit runs, Luhn-checked |
| `IP_V4` | `192.0.2.10` |
| `IP_V6` | `2001:db8::1`, `::1` |
| `IBAN` | `DE89370400440532013000` |
| `URL` | `http://`, `https://` |

The credit-card detector runs the Luhn checksum on every candidate. A 16-digit run with a flipped last digit is dropped.

## Why

`tool-secret-scrubber` covers API keys, JWTs, bearer tokens, AWS keys. It is the right tool for "do not log this." `llm-pii-redact` is the right tool for "send this through the LLM, then put the real values back." That second case wants:

- Reversible mapping, not a one-way redact.
- Per-value stable placeholders so the model can talk about the same person twice.
- PII detectors (emails, phones, SSN, cards) rather than credential detectors.

## Install

```toml
[dependencies]
llm-pii-redact = "0.1"
```

Optional `serde` feature to derive `Serialize`/`Deserialize` for `Redacted`:

```toml
[dependencies]
llm-pii-redact = { version = "0.1", features = ["serde"] }
```

## Use

Default detectors:

```rust
use llm_pii_redact::Redactor;

let r = Redactor::default();
let out = r.redact("ping ops@example.invalid");
assert!(out.text.contains("<EMAIL_0>"));
```

One detector at a time:

```rust
use llm_pii_redact::Redactor;

let r = Redactor::email(); // or ::phone(), ::ssn(), ::cc(), ::ip()
let out = r.redact("ops@example.invalid call 555-123-4567");
assert!(out.text.contains("<EMAIL_0>"));
assert!(out.text.contains("555-123-4567")); // phone untouched
```

Custom pattern:

```rust
use llm_pii_redact::Redactor;

let r = Redactor::default()
    .with_pattern("AWS_KEY", r"AKIA[0-9A-Z]{16}")
    .unwrap();
let out = r.redact("key=AKIAABCDEFGHIJKLMNOP ok");
assert_eq!(out.mapping["<AWS_KEY_0>"], "AKIAABCDEFGHIJKLMNOP");
```

Round trip with an LLM:

```rust
use llm_pii_redact::Redactor;

let r = Redactor::default();
let user_message = "Confirm subscription for ops@example.invalid";

let red = r.redact(user_message);
// send red.text to the LLM
let assistant_reply = format!("Confirmed: {}", "<EMAIL_0>"); // pretend the LLM said this
let real_reply = r.reveal(&assistant_reply, &red.mapping);
assert_eq!(real_reply, "Confirmed: ops@example.invalid");
```

### Consistent placeholders across a conversation

Each `redact` call is independent: counters restart at `0`, so the same value can
get `<EMAIL_0>` in two unrelated calls, and `reveal` needs the mapping from the
matching call. For a multi-turn conversation you usually want one value to keep
the *same* placeholder across every message and one mapping that reveals values
from any turn. That is what a `Session` provides:

```rust
use llm_pii_redact::Redactor;

let mut session = Redactor::default().session();

let prompt   = session.redact("Email a@b.invalid and c@d.invalid");
let followup = session.redact("Resend to a@b.invalid only");

// a@b.invalid keeps <EMAIL_0> in both messages; c@d.invalid is <EMAIL_1>.
assert!(prompt.contains("<EMAIL_0>"));
assert!(followup.contains("<EMAIL_0>"));   // reused, not renumbered
assert!(!followup.contains("<EMAIL_1>"));

// One accumulated mapping reveals placeholders from either turn.
assert_eq!(session.reveal("ok <EMAIL_1>"), "ok c@d.invalid");
```

`session.mapping()` exposes the accumulated placeholder-to-value map, and
`session.into_redactor()` hands back the underlying stateless `Redactor`.

## API

| Item | What it is |
|---|---|
| `Redactor::default()` | Redactor with all built-in detectors (email, phone, SSN, card, IPv4, IPv6, IBAN, URL). |
| `Redactor::new()` | Empty redactor; add detectors with `with_pattern`. |
| `Redactor::email()` / `phone()` / `ssn()` / `cc()` / `ip()` | Single-purpose redactors. |
| `Redactor::with_pattern(name, regex)` | Register a custom detector; errors on empty name or bad regex. |
| `Redactor::detect(text) -> Vec<Detection>` | Non-overlapping matches in document order. |
| `Redactor::redact(text) -> Redacted` | Stateless redaction: `{ text, mapping }`. |
| `Redactor::reveal(text, &mapping) -> String` | Restore originals from a mapping. |
| `Redactor::session() -> Session` | Stateful redactor that keeps placeholders consistent across calls. |
| `Session::redact(text) -> String` | Redact reusing placeholders from earlier calls. |
| `Session::reveal(text) -> String` | Restore using the session's accumulated mapping. |
| `Session::mapping() -> &HashMap` | The accumulated placeholder-to-value map. |
| `Redacted` | `{ text: String, mapping: HashMap<String, String> }`; `Serialize`/`Deserialize` under the `serde` feature. |
| `Detection` | `{ kind, value, start, end }` for one match. |
| `builtin_detector_names()` | The built-in kind names in registration order. |

## What it does NOT do

- No name / address / DOB classifier. Regex only.
- No network calls, no async, no I/O.
- No secret / credential detection. Use [`tool-secret-scrubber`](https://crates.io/crates/tool-secret-scrubber) for that.

## Companion crates

- [`tool-secret-scrubber`](https://crates.io/crates/tool-secret-scrubber): API keys, JWTs, bearer tokens, AWS keys.
- [`agentguard-rs`](https://crates.io/crates/agentguard): network egress allowlist for agent tools.
- [`agentvet-rs`](https://crates.io/crates/agentvet): tool-arg validator for LLM tool calls.

## License

MIT. See `LICENSE`.
