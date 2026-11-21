# Fuzz heuristics and precision — internal security review

Date: 2026-11-13
Reviewer: internal self-review (AI-assisted)
Status: **Conditional pass for v1.** This replaces the third-party advisor
review that `project.md` §11.4 originally required. The project owner explicitly
waived that independent review, so the independence caveat below is real and
must stay with this document.

## What was reviewed

- `internal/fuzz/resolver.go` — target parsing and mutation
- `internal/fuzz/runner.go` — worker pool, rate limit, budget, retry, cancellation
- `internal/fuzz/heuristics.go` — detection and severity
- `internal/fuzz/wordlist.go` and `internal/fuzz/wordlists/*.txt` — payloads
- `internal/fuzz/corpus_test.go` and `corpus_live_test.go` — precision evidence
- `internal/format/parser.go` — target filtering at parse time
- `internal/http/client.go` — loopback/redirect/proxy behaviour
- `internal/engine/engine.go` — report warnings and write-method warning
- `docs/fuzzing-guide.md` — claims checked against the code

Method: code reading, focused tests, an adversarial pass over the wordlist, and
an arithmetic check of the published corpus numbers.

## Findings

### 1. Destructive payload contradicted the safety claim — fixed (high)

The bundled injection list contained `"; DROP TABLE x; --` while the wordlist
header, the fuzzing guide and the security model all said the payloads never
write, drop or delete. A table literally named `x` is rare, but the claim and
the list disagreed.

Fix: replaced it with a read-only `"; SELECT 1; --`. Added
`TestBundledWordlistIsNonDestructive`, which scans every bundled payload for
destructive SQL and command fragments (`DROP TABLE`, `DELETE FROM`, `rm -rf`,
`mkfs`, …).

### 2. Baseline error strings were reported as payload findings — fixed (medium)

An error pattern already present in the baseline response was reported again for
every target, even though the payload did not cause it. That is a false-positive
class, and it inflates the finding count on an API that is already leaking.

Fix: `Analyze` now skips an error pattern that also matches the baseline body.
A different pattern in the fuzz response is still reported. Tests cover the
baseline match, a new match, and a different-pattern match.

### 3. Corpus arithmetic was wrong — fixed in docs (low)

The live corpus table sums to **572 requests**: eight APIs at 60 plus
`rickandmorty` at 92 (60 payloads + 32 confirmation retries). The docs said
"540 requests". 540 is the planned payload count, not the request count.

Fix: docs and `project.md` now say **540 payloads / 572 requests including 32
confirmation retries**.

### 4. "100% precision" from zero findings — fixed in docs (low)

The clean fixture reports zero findings, so precision is `0/0` and is undefined.
It is a valid zero-false-positive result, not a precision estimate.

Fix: the guide now says "zero-false-positive result" and explains why precision
is undefined. The live set, where three findings were triaged as true/expected,
is the only place a precision statement is meaningful.

### 5. Documentation drift — fixed (low)

- Custom wordlists were documented as relative to the working directory; the
  engine resolves them next to the `.kh` file and confines them to the workspace.
- The limits table said all four knobs were configurable per file; `workers` is
  internal.
- The retry paragraph said "every 5xx" and did not say retries consume the same
  `max_requests` budget.
- The size/payload caps on custom wordlists were undocumented.

## §11.4 checklist

| Area | Verdict |
| --- | --- |
| Injection-point resolver correctness | **Pass.** Mutations copy the request; only declared targets change; untouched path segments keep their escaping; body targets are JSON-only; array indices and missing containers error explicitly; managed headers are rejected; `header.Host` is routed through `http.Request.Host`. |
| Detection heuristic quality | **Pass with caveats.** Status anomaly is high only when the baseline was below 400; error strings are specific and baseline-suppressed; reflection is low and 2xx-only; timing is advisory and off by default. The rules are shallow by design and do not detect authz/IDOR/business-logic issues. |
| Payload safety | **Pass after the fix.** 596 payloads (323 injection, 187 boundary, 86 type-confusion). Destructive fragments are now denied by test. 1 MB boundary payloads are read-only but can be rejected by request-line limits. |
| Rate limiting adequacy | **Pass.** One global token bucket, two in-flight requests per host, hard `max_requests` cap that includes confirmation retries, non-localhost guard, redirect guard, no environment proxy on local-only runs. Write methods require typed confirmation in the desktop app and produce a warning in the CLI/report. |
| Default wordlist review | **Pass after the fix.** Families and counts match the docs. The destructive-fragment test is the regression guard. Custom lists remain the user's responsibility, now bounded to 5 MiB / 200,000 payloads and confined to the workspace. |

## Precision evidence

| Measurement | Result |
| --- | --- |
| Offline clean fixture | 0 findings / 150 payloads — zero false positives |
| Offline SQL-error fixture | status anomaly + error string, no extra rows |
| Offline echo fixture | one reflection (low), expected |
| Offline slow fixture | nothing by default; one advisory with `--timing` |
| Live public APIs | 9 APIs, 540 payloads, 572 requests, 0 false positives after triage, 2 expected reflections, 1 triaged true positive |
| Skipped live API | agify returned 429; not counted |

Caveats: the live corpus is not part of the offline gate and its triage is
manual. The offline fixture corpus is the enforcing gate. The live sample is
small, public-API-shaped, and not a substitute for an application-specific test.

## Residual risks

1. **No independent sign-off.** This is a self-review; a third party could
   disagree with the severity mapping or the heuristic thresholds.
2. **Shallow detection.** Status, error-string and reflection checks do not
   prove exploitability. A finding is a lead, not a vulnerability report.
3. **Status sensitivity.** A 500 caused by a payload is not reported when the
   baseline was already 4xx/5xx.
4. **Error patterns are language-specific.** The list covers common SQL, Python,
   Java, Go, PHP and template stacks; other stacks are false negatives.
5. **Timing is advisory.** No time-based confirmation is claimed; the
   `timing_outlier` heuristic stays off by default.
6. **Write-method fuzzing.** The desktop app requires a typed confirmation, and
   the CLI/report warns, but a user can still mutate a reachable test system.
7. **Boundary payloads can be large.** 1 MB values are read-only but may consume
   bandwidth or be rejected at the edge.
8. **Custom wordlists are user-supplied.** They are bounded and workspace-local,
   but their content is not vetted.

## Verdict

**Conditional pass for v1.** The fuzzer's claims are now consistent with its
code and corpus: non-destructive payloads, bounded execution, loopback-by-default,
baseline-aware error detection, and honest precision wording. No blocking defect
remains from this review.

The condition is the independence caveat: this document is an internal
self-review, not a third-party security sign-off. If the project later needs an
external assurance statement, this document is the packet to hand the reviewer.
