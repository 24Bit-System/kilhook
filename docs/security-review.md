# Security review (internal)

Date: 2026-11-21
Reviewer: internal, AI-assisted
Status: **Pass for v1, with the caveats below.** This is not a third-party
sign-off. The project owner declined an external review, so treat this document
as the packet an external reviewer would start from, not as independent
assurance.

## Scope

The whole application, not only the fuzzer:

- `internal/format` — `.kh` parsing and serialization
- `internal/http` — request building, env interpolation, redirects, transports, env file loading
- `internal/fuzz` — target resolver, runner, rate limit, budget, retries, heuristics, wordlists
- `internal/spec` — OpenAPI loading and response validation
- `internal/diff` — JSON and text comparison
- `internal/report` — report model and HTML export
- `internal/engine` — the loop, workspace confinement, redaction
- `cmd/kh-cli`, `cmd/kh-app` — CLI and Wails bridge
- `cmd/kh-app/frontend` — Svelte window, UI-side guards, vendored `deepmerge`
- `scripts/verify.ps1`, `scripts/smoke.ps1`, `cmd/kh-app/frontend/scripts/write-source-hash.mjs`

## Method

Code reading against the documented threat model, an adversarial pass over each
trust boundary, targeted tests, and these checks:

- `govulncheck ./...` — no known vulnerabilities
- `go mod verify` — all modules verified
- `npm audit` (runtime and full) — 0 vulnerabilities
- tracked-content secret scan (cloud tokens, private keys) — clean
- fresh-clone `npm ci`, `npm run build`, `scripts/verify.ps1` — green

## Fuzz heuristics review (2026-11-13)

1. **Destructive payload** — the bundled list contained `"; DROP TABLE x; --`
   while the docs promised read-only payloads. Replaced with `SELECT 1` and
   guarded by `TestBundledWordlistIsNonDestructive`. **Fixed.**
2. **Baseline error strings reported as findings** — an error pattern already in
   the baseline was re-reported per target. Now suppressed per pattern. **Fixed.**
3. **Corpus arithmetic** — 540 payloads vs 572 requests (32 retries) was stated
   wrong. Corrected. **Fixed in docs.**
4. **"100% precision" from zero findings** — precision is undefined at zero
   findings. Reworded to "zero false positives". **Fixed in docs.**
5. **Documentation drift** — wordlist resolution, retry budget, internal
   `workers`, size caps. Corrected. **Fixed in docs.**

## Application pass (2026-11-21)

Findings that affected confidentiality, integrity or the safety controls:

1. **Text baseline diffs were not redacted (high).** `redactChanges` ran only on
   the JSON branch; a `text/plain` response could put a session token into the
   report and HTML export. Text diffs now go through the same redactor, and the
   redactor also scrubs credential-shaped values inside ordinary fields. **Fixed.**
2. **`redactBody` failed open (high).** NDJSON, a form body with one bad percent
   escape, and multipart bodies bypassed redaction entirely. It now decodes every
   JSON document, redacts form pairs without `url.ParseQuery`, handles multipart
   parts, and falls back to a text pass when parsing fails. **Fixed.**
3. **Fuzz evidence and spec violation messages were unredacted (high).**
   `Finding.Evidence` is a raw response window and `Violation.Message` can quote
   a response value. Both now pass through redaction before export. **Fixed.**
4. **Unsafe-method confirmation could be bypassed (high).** After saving a
   method change, the window kept the old `Workfile` object, so a GET→DELETE save
   skipped the typed confirmation while the engine fuzzed the new write method.
   The selection now refreshes from the latest discovery result. **Fixed.**
5. **Header fuzz target could silently do nothing (high, detection).** A
   case-variant target created a second header key; canonicalisation made the
   original value win, so no payload was sent. The existing key is now mutated.
   **Fixed.**
6. **Body fuzzing corrupted large integers (high, integrity).** No `UseNumber`,
   so snowflake IDs changed in every request. **Fixed.**
7. **Rate-limit floor was not enforced (medium).** CLI and runner accepted rates
   below `MinRateLimit`; a tiny finite rate overflowed the limiter and disabled
   throttling. The floor is enforced in both places, with a defensive clamp.
   **Fixed.**
8. **URL redaction re-encoded the query (medium).** Redacting userinfo rewrote
   and reordered every query parameter; usernames and semicolon-delimited values
   were also missed. Redaction is now per-pair and byte-preserving. **Fixed.**
9. **Workspace confinement was inconsistent (medium).**
   `Create` used a case-insensitive check on case-sensitive filesystems; `Discover`
   read through symlinks that left the workspace; `SaveHTML` had a
   check-then-write window. All three now use the symlink-aware rule or a
   temp-file rename. **Fixed.**
10. **Environment files were unbounded (medium).** `LoadEnvironment` read the whole
    file; capped at 1 MiB. **Fixed.**
11. **Gate could pass with a reverted security patch (medium, supply chain).** The
    frontend content hash did not cover `package-lock.json` or
    `vendor/deepmerge`. Both are now hashed. **Fixed.**

Correctness fixes that reduce false positives/negatives (not security defects on
their own): `pickStatusKey` prefers a lowercase `2xx` over `default`; a top-level
`$ref` keeps `nullable`; wildcard responses report the real status; `//` paths
are preserved; typed injection rejects trailing garbage; strict JSON trailing
data; reflection is 2xx-only; deterministic media-type selection; `---` inside a
YAML block scalar no longer splits the file; CRLF previews; non-ASCII slugs keep
their hash; saved files keep their permissions.

## §11.4 checklist

| Area | Verdict |
| --- | --- |
| Injection-point resolver correctness | **Pass.** Mutations copy the request; only declared targets change; case-variant headers mutate the real key; untouched path segments keep their escaping and slash count; body targets are JSON-only and preserve number precision; managed headers are rejected; `header.Host` goes through `http.Request.Host`, which does not change the dial target. |
| Detection heuristic quality | **Pass with caveats.** Status anomaly is high only when the baseline was below 400; error strings are specific and baseline-suppressed; reflection is low and 2xx-only; timing is advisory and off by default. It does not detect authz/IDOR/business-logic issues. |
| Payload safety | **Pass.** 596 bundled payloads; destructive fragments are denied by test; custom lists are bounded to 5 MiB / 200,000 payloads and confined to the workspace. |
| Rate limiting adequacy | **Pass.** One global token bucket, two in-flight requests per host, hard `max_requests` cap that includes retries, non-localhost guard, redirect guard, no environment proxy on local-only runs, minimum rate enforced. Write methods require typed confirmation in the window and add a report warning in the CLI. |
| Default wordlist review | **Pass.** Families and counts match the docs; the destructive-fragment test is the regression guard. |
| Local-path handling | **Pass.** `spec.baseline`, `fuzz.wordlist` and environment paths use `withinDir`/`WithinDir`; `Discover` refuses escaping symlinks; HTML export writes via temp file + rename; env reads and every file/response/spec/baseline read is size-bounded. |
| Report confidentiality | **Pass with caveat.** Headers, query, URL userinfo, JSON/NDJSON/form/multipart bodies, text and JSON diffs, fuzz evidence and violation messages are redacted by name and by credential shape. Redaction of unstructured text is best-effort. |
| HTML export | **Pass.** `html/template` contextual escaping; no `{@html}` or `innerHTML` in the frontend; report fields are inserted as text. |
| Desktop bridge | **Pass.** Run/Cancel/Save are mutex-guarded; the workspace root is required for Open/Run/Save/Create/Modified; generated bindings match the Go signatures. |
| Dependency surface | **Pass.** `govulncheck` clean, `npm audit` clean, `go mod verify` clean, patched `deepmerge` present and hashed by the gate. |

## Precision evidence

| Measurement | Result |
| --- | --- |
| Offline clean fixture | 0 findings / 150 payloads — zero false positives |
| Offline SQL-error fixture | status anomaly + error string, no extra rows |
| Offline echo fixture | one reflection (low), expected |
| Offline slow fixture | nothing by default; one advisory with `--timing` |
| Live public APIs | 9 APIs, 540 payloads, 572 requests, 0 false positives after triage, 2 expected reflections, 1 triaged true positive |
| Skipped live API | agify returned 429; not counted |

The live corpus is not part of the offline gate and its triage is manual. The
offline fixture corpus is the enforcing gate.

## Residual risks

1. **No independent review.** This is an AI-assisted internal review. Its
   independence is not established, and an external reviewer could disagree with
   severity or thresholds.
2. **Shallow detection.** Status, error-string and reflection checks are leads,
   not proof of exploitability. Authz, IDOR and business-logic bugs are out of
   reach.
3. **`spec.source` is not confined.** A shared `.kh` can point the spec loader at
   any path the user can read. The file is parsed, not exported, and the read is
   capped at 8 MiB, but its existence and parse errors surface in warnings. This
   is deliberate: absolute spec paths are supported.
4. **Redaction is best-effort on unstructured text.** A secret in an unusual
   format inside a response preview or fuzz evidence could still reach a report.
5. **`localhost` trusts the system resolver.** A poisoned hosts file could point
   it elsewhere; the loopback guard checks the name/address, not DNS provenance.
6. **Write-method fuzzing** can still mutate a reachable test system after the
   typed confirmation.
7. **Timing is advisory.** No time-based confirmation is claimed.
8. **Binaries are unsigned.** Windows SmartScreen may warn; build from source if
   that matters.

## Verdict

**Pass for v1.** The confidentiality, path-confinement and safety-control defects
found in the 2026-11-21 pass are fixed and covered by tests, and the dependency
and secret checks are clean.

The standing caveat is independence: this document is an internal, AI-assisted
review. If the project ever needs an external assurance statement, hand this file
to the reviewer as the starting packet.
