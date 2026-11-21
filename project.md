Project Kilhook — Master Plan
Version: 1.20 (verified) · Status: Phases 0–4 complete; Phase 5 ship pending (signing/submission excluded by the owner) — every engine package gated at 80% · Stack: Go 1.26 + Wails v3.1.0 · Target: Windows-first v1

Changelog v1.22: Deep pre-open-source review closed 32 findings. Seven high-severity items: text baseline diffs and fuzz/spec report fields are now redacted; `redactBody` handles NDJSON, malformed forms and multipart without failing open; case-variant header fuzz targets now mutate the existing header key (previously a silent no-op); body fuzzing preserves large JSON integers with `UseNumber`; `pickStatusKey` prefers a lowercase `2xx` over `default`; and the desktop app refreshes `selected` after a save so a changed method cannot bypass the typed unsafe-method confirmation. Also fixed: Save & Run no longer runs after a failed save, stale report/HTML clearing, one-shot `updateBaseline`, rate-limit minimum in CLI/runner and limiter overflow, `$ref` sibling keywords, wildcard violation status, `//` path preservation, typed-injection trailing garbage, strict JSON trailing-data detection, 2xx-only reflection, deterministic media-type pick, complete content-hash inputs with CRLF normalisation, case-sensitive workspace root check, safe temp-file HTML write, Ctrl+S modal guard, clipboard cleanup, block-scalar `---` parsing, CRLF previews, non-ASCII slug hashing, bounded `Discover` reads, preserved file permissions, and four stale docs claims. Regression tests added across format/engine/fuzz/spec/diff and the frontend helpers.

Changelog v1.21: Open-source readiness hardening. Four review findings are closed: the Wails bridge now shares the engine's symlink-resolving workspace confinement (`engine.WithinDir`), so a junction or symlink inside a workspace cannot escape it; cancellation seen by fuzz workers after the producer finishes queueing now marks the run aborted instead of reporting the skips as `max_requests`; the non-localhost guard now skips only the fuzz pass, with a warning and an incomplete (exit 2) verdict, so the baseline, contract and diff report survives; and the configured per-host concurrency now reaches the cached HTTP transport's connection pool. Regression tests cover each path. Open-source readiness followed: MIT license, CONTRIBUTING/SECURITY/CODE_OF_CONDUCT/CHANGELOG, an expanded `.gitignore`, corrected stale docs and layout, `npm ci`/Go-toolchain guidance, de-staled MSIX branding strings, and a content-hash frontend check that cannot fail on a fresh clone. Open-source attribution now names the maker: 24Bit System / Two Four Bit Systech India Private Limited, with the MIT copyright, AUTHORS.md, README credits, and a real security contact (info@24bitsystem.com). The no-git/no-CI workflow and the waived independent security sign-off are unchanged.

Changelog v1.20: The two remaining Phase 3/4 UI deliverables are closed. Every fuzz finding has a Copy button that writes a portable plain-text block (severity, kind, target, payload, status, hits, evidence) through the Wails clipboard bridge, with `navigator.clipboard` and a textarea fallback for browser/dev use. Contract violations expose their JSON path as a button: clicking it finds the last path segment in the response preview, highlights it with a temporary mark and scrolls it into view; a Copy button writes the path, message, operation and status as text. Both paths are covered by Vitest (`findingText`, `violationText`, `lastPathKey`). Phase 3 and Phase 4 are now code-complete.

Changelog v1.19: Phase 2 is closed by an internal self-review rather than a third-party advisor, a deviation the project owner explicitly accepted. The review found and fixed three substantive issues: the bundled wordlist contained `"; DROP TABLE x; --`, contradicting the "nothing writes, drops or deletes" claim, so it is now a read-only `SELECT 1` and `TestBundledWordlistIsNonDestructive` enforces a destructive-fragment denylist; error strings already present in the baseline are no longer reported as payload findings, removing a false-positive class without hiding a new leak; and the corpus arithmetic was corrected — 540 planned payloads are 572 requests once 32 confirmation retries are counted. The docs and the corpus test log stop calling zero findings "100% precision" (precision is undefined at zero findings), and now state that custom wordlists resolve next to the .kh file and are confined to the workspace, that retries draw from the same max_requests budget, and that workers is internal. Residual risk: this is a self-review, not an independent sign-off.

Changelog v1.18: The brand assets are wired through the product: logo.png and fevicon.png feed the window mark, the empty state, the browser favicon, the 1024px app icon, the multi-size Windows .ico and the regenerated syso; docs carry a dark banner so the white wordmark survives light-mode Markdown. The app now fits its window to the primary work area at startup and the DPI manifest is embedded, so a 125%-scaled 1366x768 or 1536x864 display no longer clips the right edge. The frontend build vendors a patched deepmerge 4.3.1 (prototype-poisoning keys rejected unconditionally) under vendor/deepmerge with install-links=true, which makes `npm ci` reproducible and `npm audit` clean. The frontend gained a Vitest suite for selection, save/run, palette, severity and formatting helpers, and the stale installed-package screenshot was removed rather than left to misdescribe the current UI; the smoke-report screenshot was regenerated from a live Petstore run.

Changelog v1.17: A review-driven hardening pass closed the remaining v1 gaps. Reports now redact credentials from headers, query parameters, URL userinfo, JSON/form request bodies, response previews and baseline diffs; custom wordlists are capped by bytes and payload count, and the mutation slice is clamped to the request budget before allocation; LoadDocument bounds its read, and the window marks files Discover could not parse. Fuzz targets now reject connection-level headers and route header.Host through Request.Host, which is the only override net/http honours. rate_limit is validated as finite and bounded in both the file and CLI overrides, and MaxRequests is a hard ceiling that confirmation retries also draw from. A spec load or match failure is a warning instead of aborting the fuzz/diff loop. Open/Run/Modified are confined to registered workspace roots, local-only fuzzing disables environment proxies, and svelte-check joined the verify gate (the JS frontend keeps checkJs off and checks markup/a11y instead). A Vitest suite covers the extracted selection, palette, severity and formatting helpers. Write-method fuzzing now requires a typed confirmation in the window and adds a warning to the report, and the desktop screenshots were regenerated from the current build with the DPI manifest.

Changelog v1.16: The two Phase 1 UI gaps are closed. The workspace box has a Browse… button driving the native folder picker, and cancelling it changes nothing — the first cut surfaced the picker's "cancelled by user" as a red error bar, so the mapping lives in dialogResult with a test. The env box became a dropdown fed by .kilhook/env/*.yaml, keeping the current name selectable when no file exists yet so a fresh workspace does not silently lose it. Both were verified in the running window through UI Automation, not by reading Svelte. Separately, internal/engine joined the coverage gate at 81.2%: units_test.go covers operation-hint parsing and matching, baseline path resolution including the workspace confinement, env loading precedence, and the small helpers. Discover now explains an empty folder instead of reporting "open :".

Changelog v1.15: The pre-submission smoke test is now scripted and passing: scripts/smoke.ps1 runs the whole loop against four public read-only APIs, including the Swagger Petstore validated against its live OpenAPI document (200, no violations), and exports the standalone HTML report for each. httpbin is the only case with a finding, a low reflection, because it echoes its input by design. Requests live in testdata/smoke/ so the check is reproducible rather than a claim in a report, and the petstore host needed curl rather than Invoke-WebRequest because it answers 403 to the PowerShell user agent.

Changelog v1.14: The review the security advisor would do was prepared by auditing what the fuzzer is actually trusted to do, and it found two defects. The loopback guard only covered the first hop: a local server could answer 302 to the internet and every fuzz request would follow it, so redirects are now stopped unless they stay on loopback (tests for both). And `spec.baseline` is a path inside a file that may have been shared, while `--update-baseline` writes a response body to it — so a file-supplied baseline may no longer leave the workspace; `--baseline` on the command line still may, because that is the user typing it. A third suspicion did not survive checking: spec loading already caps files at 8 MiB, the constant was simply unused-looking. The remaining Phase 2 item is still a person: the advisor's sign-off on these heuristics and numbers.

Changelog v1.13: The live corpus reached nine public APIs and 540 payloads (572 requests including 32 confirmation retries) with zero false positives. It also showed why one high finding was noise: a 5xx from open-meteo that could not be reproduced afterwards, so the runner now re-sends every 5xx once and drops the status and error-string findings if the retry lands below 500. A persistent 5xx is still reported, with tests for both. The one surviving high finding is a genuine defect (a non-numeric path segment returns 500 rather than 4xx). The security advisor's review of these numbers was the remaining Phase 2 item; it was later waived in v1.19 in favour of the internal self-review in `docs/security-review.md`.

Changelog v1.12: The false-positive corpus now reaches the real internet. A second harness (internal/fuzz/corpus_live_test.go, build tag corpuslive, three requests per second, sixty payloads per API) measures httpbin, postman-echo, jsonplaceholder, dummyjson and Rick and Morty: 300 requests, zero false positives, two expected reflection findings on the APIs that echo input, and one high finding triaged as a genuine defect (a non-numeric path segment returns 500, not 4xx). The offline fixture corpus stays the enforcing gate; the live one reports numbers and fails only on harness faults.

Changelog v1.11: Fuzzing noise is now measured instead of asserted. A four-fixture corpus (internal/fuzz/corpus_test.go) covers a clean API, a SQL-error API, an echoing API and a slow API; the clean fixture reports 0 findings over 150 payloads (100% precision) and the vulnerable ones are detected with no extra rows. It found a real defect on the first run: a 500 page that quotes the input produced both error_string and reflection for one observation, so reflection is now restricted to 2xx responses. The bundled wordlist grew from 95 to 596 payloads (SQLi, NoSQL, template, command, path, LDAP, XSS markers, format strings, boundary and type-confusion families), all non-destructive.

Changelog v1.10: The package was installed, launched and used, not just built. Developer-mode registration (Add-AppxPackage -Register) needs no admin and works; the signed-package path fails with 0x800B0109 until the self-signed root is trusted in the machine store, which the Store path makes unnecessary. The packaged window showed kilhook 0.1.0, loaded a workspace and ran the loop (200 in 19 ms, one violation, five findings). Uninstalled and the certificate deleted afterwards; a trusted package on a clean VM is still unproven. The install test found a real defect: an MSIX launch starts in System32 and the workspace box offered that path, so Workspace.Home now rejects Windows, Program Files and ProgramData and falls back to the user profile, with tests.

Changelog v1.9: The MSIX package is built and inspected: wails3 tool msix drives the Windows SDK's MakeAppx.exe from cmd/kh-app/build/config.yml and produces an 11.7 MB x64 package with identity com.kilhook.app 0.1.0.0; the executable is 22.7 MB, inside the 30 MB v1 budget. It is unsigned, so installing needs a trusted certificate. The editor gained an unsaved-changes chip, a Ctrl+S shortcut and Save & Run, all verified in the running window. The coverage floor now covers internal/fuzz and internal/http, which already sat at 81.2% and 80.3% and were the two packages left out of the gate by accident rather than by decision.

Changelog v1.8: The desktop window is now an editor as well as a runner: a Document model over the parsed frontmatter feeds a form (headers, query, auth, body, fuzz targets/limits, spec, timeout), and Save goes through the canonical serializer, reparses before writing, writes atomically, omits values equal to defaults and is byte-idempotent. Unknown fields are surfaced before a save because the rewrite drops them. Running is still blocked on the saved file, which the editor states. Verified by typing into the live window, saving, and diffing the file on disk.

Changelog v1.7: The loop moved into internal/engine so cmd/kh-cli and the new cmd/kh-app share one implementation, and the desktop half exists: a Wails v3.1.0 window with a Svelte 5 frontend that lists workspace requests, runs send → validate → fuzz → diff, renders the report model, cancels an in-flight run, and exports the standalone HTML. Verified by building and screenshotting the live window, not by compiling alone. Two defects the screenshot caught: the default workspace opened on a folder with no requests, and a stored baseline was never picked up unless spec.baseline named it.

Changelog v1.6: Phase 0 shipped and the local gate is green: internal/{format,http,fuzz,spec,diff,report} plus cmd/kh-cli (run loop, text/JSON/HTML reports, exit codes 0/1/2) are implemented and tested, docs/ carries the format reference, fuzzing guide and quickstart, and scripts/verify.ps1 passes all seven checks. Two design corrections found by running the loop for real: fuzz payloads are interleaved across methods and targets so a request cap cannot starve later targets, and progress output goes to stderr so --json stays machine-readable.

Changelog v1.5: Removed every dependency on a version-control host and CI service for the team's own workflow — no git, no GitHub, no CI: §10.3 is now a single local gate (`scripts/verify.ps1`), dependency updates are a monthly manual pass, §12.1 drops the GitHub Releases row, §13.1 drops the GitHub line, .github/ is gone from the repo layout. Product claims about diffable text files and user-side CI are unchanged — those describe users' workflows, not ours.

Changelog v1.4: Pinned the Week 1 packaging fallback to WebView2 + .NET single-project MSIX (removing the Wails v2 option — same failure surface, not a different one) and stated its cost: cmd/kh-app's Wails bridge is discarded, internal/* survives as a sidecar; 1–2 week schedule hit, no scope change. Added the Phase 2 rate-limiting deliverable (FuzzConfig defaults, no hard-coded constants).

Changelog v1.3: Declared multipart and form-urlencoded body fuzzing out of scope for v1 — behavior defined, format unchanged (`format: 1` stays frozen): the parser warns and skips `body.*` targets on those body types instead of failing silently. Recorded as accepted gap R13 and as a v1.1 item requiring a real user case.

Changelog v1.2: Raised Wails v3 floor to beta.21 (MSIX command registration fix, PR #6115); added the Week 1 MSIX-failure fallback decision node (options left open until v1.4); set concurrency defaults (5 req/s global, 2 per host) and the `--allow-nonlocal` guard; demoted the timing-outlier heuristic to advisory/off-by-default; clarified spec parsing vs. spec→request generation; specified `path.N` indexing scope and in-memory-only fuzz mutations; moved the binary-size gate to end of Phase 1.

Changelog v1.1: Pinned kin-openapi ≥ v0.148.0 (CVE-2026-100352); clarified spec parsing vs. response validation ownership; added Wails v3 MSIX command; noted free Store dev account; updated competitive landscape (Raill_HTTPX, Bruno contract testing).

Table of Contents
Executive Summary

Problem & Opportunity

Product Definition

V1 Scope (Locked)

The .kh Request Format

Architecture & Tech Stack

Repository Layout

Development Phases

Team & Roles

Testing & Quality Gates

Security Model

Distribution & Legal

Budget

Risk Register

Post-V1 Roadmap

Immediate Next Steps

Appendix: Glossary & References

1. Executive Summary
Kilhook is a local-first Windows desktop application that fuses three workflows developers currently perform in separate tools: authoring an API request, fuzzing it for security issues, and validating it against an OpenAPI contract.

The core insight: today a developer authors a request in Postman/Bruno, re-authors it in Burp to fuzz it, and then uses a third tool to validate the response against the spec. Context is lost at every seam. Kilhook makes a single Git-diffable request file the source of truth that flows through all three phases in one loop, producing one combined report.

Key characteristics:

Single native binary (target < 30 MB MSIX, measured at end of Phase 1), no Electron, no cloud account

Zero external dependencies at runtime (no Docker, no database server)

Zero cash cost for v1 (Windows Store signing and dev account registration are free)

16-week build to Store submission

Team: 3 engineers + part-time security review

Security baseline: every dependency pinned, govulncheck in the local verify gate, kin-openapi ≥ v0.148.0 (see R11/CVE note)

The one gate that matters: if the Phase 0 spike does not feel meaningfully better than running three tools separately, the project stops.

2. Problem & Opportunity
2.1 The Pain
Developers working with APIs repeatedly author the same request across disconnected tools:

Phase	Typical tool	Problem
Authoring	Postman / Bruno / Yaak	Cloud-first, login required, or client-only
Security testing	Burp / custom scripts	Request must be re-created; not integrated with client
Contract validation	Schemathesis / Specmatic / CI scripts	Separate tool, separate config, separate output
Every handoff loses context — auth, environment, headers, the exact tuned body. The output of each tool is a separate report that must be stitched together manually.

2.2 The Market Gap
Tool	What it does	Where it breaks the chain
Postman	Client + test scripting	Cloud-first; fuzzing and spec validation not native; requests live in their cloud
Bruno / Yaak / Postkid	Local-first API client	Fuzzing absent; Bruno is actively adding contract testing, narrowing the gap
Burp Suite	Security testing	Not a client; request re-authored inside it
Raill_HTTPX	Single binary: client + MITM proxy + fuzzer + scanner	Closest active competitor. Early-stage; shallow on OpenAPI contract validation; not driven by a Git-diffable declarative file
Stubrix	Unifies mocking, contract testing	Requires Docker, Node.js, full infrastructure stack
Routebase	OpenAPI-driven lifecycle	Commercial platform, not local binary
Specmatic	Contract testing	Separate tool; not fused with client or fuzzer
2.3 The Opportunity
No existing open-source tool combines all of the following in a single dependency-free binary:

Core client workflow (collections, environments, auth)

Built-in security fuzzing

OpenAPI spec and contract validation

Response diffing against known-good baselines

Zero infrastructure

A Git-diffable request file that declaratively carries the fuzz and spec configuration

The fusion of client and security tester into one artifact, driven by one request file, is the unfilled gap. The window is narrowing (Raill_HTTPX and Bruno are moving), which is why the Phase 0 gate and narrow scope matter.

3. Product Definition
3.1 One-Liner
A local-first Windows app where you author an API request once, then fuzz it and validate it against your OpenAPI spec — in one loop, one file, one report.

3.2 Target User
Primary: Backend and full-stack developers, and small API teams (2–15 people) who:

Already use Git for their code

Work with OpenAPI/Swagger specs

Need basic security testing but don't want the weight of Burp

Are frustrated by re-authoring requests across tools

Value privacy and local-first tooling

Secondary: Security-conscious indie developers, DevRel engineers testing public APIs, QA engineers writing contract tests.

3.3 The Differentiator (One Sentence)
The Git-diffable request file is the same object that gets fuzzed, validated, and diffed — no export, no re-entry, no context switch.

3.4 What Kilhook Is Not
Not a Postman replacement for teams needing cloud collaboration

Not a Burp Suite replacement (no full vulnerability scanner)

Not an AI agent platform (v1 has no AI/MCP)

Not a CI/CD-first tool (v1 is desktop-only; CI mode is post-v1)

Not a load-testing tool

3.5 Success Criteria for v1
Metric	Target
Time from cold open to first request sent	< 60 seconds
Time from request authored to fuzz results	< 1 click, < 10 seconds for small wordlists
False-positive rate in fuzzing report	< 10% on internal test corpus
Binary size (MSIX packaged)	< 30 MB, measured at end of Phase 1
Store certification	Passed within two submissions
Beta user retention (week 4)	> 50% of 10–20 beta users still active
4. V1 Scope (Locked)
Scope rule: If a feature is not in this section, it does not go in the repo before v1 ships. Deferred items go to the Post-V1 Roadmap.

4.1 ✅ In Scope
Request Authoring
HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS

Headers, query parameters, path parameters

Body types: JSON, form-urlencoded, multipart, raw text

Auth: Basic, Bearer token, API key (header or query)

Environment variable interpolation ({{base_url}}, etc.)

Redirects, timeouts, TLS options

Request Files
.kh plain-text format (see §5)

One file per request, Git-diffable

Folders as workspaces (no database)

Environments as local files

Fuzzing
Wordlist-driven payload injection

Injection targets declared in the .kh file: headers, query params, path segments, body fields

Bundled default wordlist + custom wordlist support

Fuzz targets resolve against JSON bodies, query parameters, headers, and path segments in v1. Multipart and form-urlencoded body fuzzing is out of scope (see §4.2).

Detection heuristics:

Status code anomalies (500s on valid input)

Error-string pattern matching (SQL errors, stack traces)

Input reflection in responses

Response timing outliers — **advisory only and off by default in v1** (the largest source of false positives against the < 10% budget in §10.2; the UI shows it as an unranked observation, never a finding, until the corpus justifies a threshold)

Per-run summary with severity classification

Spec Validation
OpenAPI 3.0 and 3.1 spec parsing (local file) — parsing by kin-openapi, response schema validation by santhosh-tekuri/jsonschema

Operation matching (path + method → operation)

Response schema validation (status code, required fields, types)

Schema drift detection against stored baseline

Readable error paths (e.g., response.users[3].email: expected string, got null)

Scope note: **spec parsing for validation is in scope; spec→request generation (writing .kh files from a spec) is not** — see §4.2.

Response Diffing
JSON-aware structured diff

Field-level added/removed/changed

Comparison against last known-good response

Fallback to text diff for non-JSON

Combined Report
Single report view: request → fuzz findings → spec violations → diff

Export to standalone HTML file

Copy-to-clipboard for individual findings

Distribution
MSIX package via Microsoft Store (Store-signed)

In-app updates via Store mechanism

4.2 ❌ Explicitly Out of V1
Cloud sync or team collaboration

AI/MCP integration

CI/CD integration or headless runner

Full vulnerability scanner (XSS, CSRF, auth bypass chains)

Code generation / SDK export

Mock server

Load testing

Multipart and form-urlencoded body fuzzing (authoring these body types is in scope; fuzzing them is not)

Collection runner with variable chaining

macOS / Linux binaries

Telemetry or crash reporting

Plugin system

Import from Postman/Insomnia, and generating .kh request files from an OpenAPI spec (spec *parsing* for validation stays in scope — see §4.1; authoring is manual in v1)

4.3 Deferred but Designed For
Architecturally accommodated (not built) so they can be added without rewrites:

CLI mode: internal/* packages are pure logic, usable by cmd/kh-cli

MCP server: report model is serializable; no UI coupling

Import: .kh parser is designed to be a target for converters

Plugin system: fuzz heuristics and validators are interfaces

5. The .kh Request Format
This format is the product's spine. Design it in week 1, freeze it, version it.

5.1 Design Principles
Git-diffable: metadata and body separated so body changes don't churn metadata

Declarative: fuzz targets and spec source are part of the file, not separate config

Backward-compatible client: a .kh file with no fuzz or spec block is a valid HTTP client request

Versioned: format: 1 in every file from day one

Human-readable: no binary, no base64 for text bodies

5.2 Format Specification
yaml
# Example: login.kh
format: 1
name: Login
method: POST
url: "{{base_url}}/auth/login"
headers:
  Content-Type: application/json
  Accept: application/json
auth:
  type: none
fuzz:
  targets:
    - body.email
    - body.password
    - header.X-Forwarded-For
  wordlist: default
  methods:
    - injection
    - boundary
spec:
  source: "../openapi.yaml"
  operation: "/auth/login post"
---
{"email": "user@example.com", "password": "secret"}
5.3 Frontmatter Fields
Field	Required	Type	Description
format	✅	int	Format version (currently 1)
name	✅	string	Human-readable name
method	✅	string	HTTP method
url	✅	string	URL with {{var}} interpolation
headers	❌	map	Header name → value
query	❌	map	Query param → value
auth	❌	object	Auth config (see below)
fuzz	❌	object	Fuzz configuration
spec	❌	object	OpenAPI validation config
timeout_ms	❌	int	Request timeout (default: 30000)
follow_redirects	❌	bool	Default: true
5.4 Auth Object
yaml
auth:
  type: basic      # none | basic | bearer | api_key
  username: "{{user}}"
  password: "{{pass}}"
yaml
auth:
  type: bearer
  token: "{{token}}"
yaml
auth:
  type: api_key
  in: header       # header | query
  name: X-API-Key
  value: "{{api_key}}"
5.5 Fuzz Object
yaml
fuzz:
  targets:
    - body.email           # JSON body field
    - query.q              # query parameter
    - header.User-Agent    # header
    - path.0               # path segment (0-indexed, URL path only)
  wordlist: default        # bundled | path to custom file
  methods:
    - injection            # SQL/command/template injection payloads
    - boundary             # empty, null, very long, unicode
    - type_confusion       # wrong types (string where number expected)
  max_requests: 500        # safety cap per run

Path indices count URL path segments only: scheme, host, port, the leading slash and the query string are not segments, and `{{base_url}}` is resolved before indexing. For `/users/{{id}}/posts`, `path.0` = `users`, `path.1` = the resolved id, `path.2` = `posts`. An index beyond the segment count is a parse warning (the target is skipped, never silently mutated into something else).

`body.<field>` targets resolve only when the body is JSON. If `body.*` targets are declared on a multipart or form-urlencoded body, the parser emits a warning and skips those targets; the run proceeds with the remaining targets. Contract: `internal/format/parser_test.go` must assert that such a file yields exactly one warning and no resolved `body.*` targets — written at format freeze (§5.9), not in Phase 2.

5.6 Spec Object
yaml
spec:
  source: "../openapi.yaml"              # relative or absolute path
  operation: "/users/{id} get"           # optional; inferred from method+url if omitted
  baseline: ".kilhook/last-good.json"    # optional; for drift detection
5.7 Body Section
Everything after --- is the raw request body. For JSON bodies, Kilhook parses it to resolve body.* fuzz targets. Fuzz mutations are applied **in memory only** and are never written back to the .kh file; "preserve original formatting" applies to UI edits only, which rewrite the file through the serializer (§6.3 step 2).

5.8 Environment Files
yaml
# .kilhook/env/dev.yaml
base_url: "http://localhost:8080"
user: "dev"
pass: "devpass"
token: "eyJ..."
Selected at runtime via UI dropdown or --env dev in CLI mode.

5.9 Versioning Policy
format: 1 is frozen at Phase 1 completion

Breaking changes require format: 2 and a migration tool

Additive fields (new optional keys) do not bump the version

The parser must accept unknown fields with a warning, not an error

6. Architecture & Tech Stack
6.1 Stack Decision (Final)
Layer	Choice	Rationale
Language	Go 1.26.9+ (toolchain go1.26.11)	Fast compile, simple concurrency, easy hiring; patch-level floor matches go.mod
Desktop shell	Wails v3	Native WebView2 on Windows, single small binary, native MSIX packaging
UI	Svelte (static build)	Small bundle, no runtime dependency; compiled to static assets
HTTP	net/http stdlib	No third-party dependency risk
OpenAPI parsing	kin-openapi ≥ v0.148.0	Most mature Go OpenAPI 3.x library; CVE-2026-100352 fixed in 0.148.0 — pin required
JSON Schema validation	santhosh-tekuri/jsonschema (draft 2020-12)	Actively maintained; performs the actual response validation
YAML parsing	gopkg.in/yaml.v3	Standard Go YAML library
Templating	text/template (stdlib)	Variable interpolation, report rendering
Diffing	sergi/go-diff (text) + custom JSON differ on map[string]any	Structured diff is core; don't outsource
CLI	cobra	Same core library, separate binary
MSIX packaging	`wails3 tool msix --config cmd/kh-app/build/config.yml --executable bin/kh-app.exe --arch x64 --out bin/kh-app-amd64.msix --publisher "CN=24Bit System"`	Native Wails v3 MSIX output; Store-signed on submission, so locally built packages are unsigned. **Requires Wails v3 >= beta.21** (PR #6115 fixed MSIX command registration for fresh projects) plus `makeappx.exe` from the Windows SDK (10.0.26100.0 here). `wails3 package GOOS=windows FORMAT=msix` runs this same tool through `cmd/kh-app/build/windows/Taskfile.yml`; calling the tool directly drops the Taskfile dependency. Verified: 11.7 MB x64 package, identity read from `build/config.yml`
6.2 Component Architecture
text
┌─────────────────────────────────────────────────────┐
│  UI (Svelte in WebView2)                            │
│  ┌────────────┬──────────────┬──────────────────┐   │
│  │ Request    │ Results      │ Report           │   │
│  │ Editor     │ Viewer       │ Exporter         │   │
│  └────────────┴──────────────┴──────────────────┘   │
├─────────────────────────────────────────────────────┤
│  Wails Bridge (Go ↔ JS)                             │
├─────────────────────────────────────────────────────┤
│  internal/ (pure Go, no Wails dependency)           │
│  ┌──────────┬──────────┬──────────┬──────────────┐  │
│  │ format   │ http     │ fuzz     │ spec         │  │
│  │ (.kh)    │ engine   │ engine   │ validator    │  │
│  ├──────────┴──────────┴──────────┼──────────────┤  │
│  │ diff (JSON-aware)              │ report       │  │
│  └────────────────────────────────┴──────────────┘  │
├─────────────────────────────────────────────────────┤
│  Local filesystem (no database)                     │
│  ~/Kilhook/workspaces/  ── .kh files, env, baselines│
│  ~/.kilhook/cache/      ── last-known-good responses│
└─────────────────────────────────────────────────────┘
6.3 The .kh → Report Data Flow (The Loop)
text
1. User edits request in UI
       ↓
2. UI serializes to .kh file on disk
       ↓
3. User clicks "Run Loop" (or individual actions)
       ↓
4. internal/format parses .kh → Request struct
       ↓
5. internal/http sends baseline request → Response
       ↓
6. internal/spec:
     a) kin-openapi loads + parses OpenAPI → Spec model
     b) santhosh-tekuri/jsonschema validates Response body vs. operation schema → Violations
       ↓
7. internal/diff compares Response vs baseline → Diff
       ↓
8. If fuzz block present:
   internal/fuzz runs payloads against targets → Findings
       ↓
9. internal/report aggregates all results → Report
       ↓
10. UI renders Report; user exports HTML or copies findings
6.4 Concurrency Model
Fuzzing pass: worker pool sized to min(NumCPU, 10), throttled by a token bucket — **default 5 req/s globally and 2 concurrent requests per host**, both configurable in the .kh fuzz block

Safety cap: max_requests per run (default 500) prevents runaway

Non-localhost guard: fuzzing a host that is not localhost / 127.0.0.1 / ::1 is skipped before the first fuzz request unless `--allow-nonlocal` is passed (CLI) or the UI confirmation is typed; the baseline, contract and diff phases still produce a report with a warning, and plain (non-fuzz) requests are unaffected

Cancellation: context-based; UI "Stop" button cancels all in-flight requests

No background processes: all work happens on user action; nothing runs when app is idle

6.5 Storage Model
No database. All state is files:

Data	Location	Format
Request files	User's workspace folder	.kh
Environments	<workspace>/.kilhook/env/*.yaml	YAML
Last-known-good responses	<workspace>/.kilhook/baselines/*.json	JSON
Run history (last 10 runs)	<workspace>/.kilhook/history/*.json	JSON
App settings	%APPDATA%/Kilhook/config.yaml	YAML
Workspaces are fully portable, Git-friendly, and backup-able by copying a folder.

6.6 Dependency & Security Baseline
Pin kin-openapi to ≥ v0.148.0 in go.mod (fixes CVE-2026-100352: YAML NaN/Infinity DoS)

govulncheck ./... runs inside scripts/verify.ps1 before a change is handed to the tech lead; a known vulnerability fails the gate

go mod verify + go mod tidy check inside scripts/verify.ps1 (no VCS to fall back on — the check compares against a temp copy)

Minimal dependency surface: stdlib net/http; no third-party HTTP client

Dependency review on the first Monday of each month: `go list -m -u all`, bump patch/minor, rerun scripts/verify.ps1. No bot updates — there is no CI to run them

7. Repository Layout
text
kilhook/
├── go.mod / go.sum
├── README.md
├── LICENSE                       # MIT
├── CONTRIBUTING.md               # build, test, contributor workflow
├── SECURITY.md                   # vulnerability reporting
├── CODE_OF_CONDUCT.md
├── project.md                    # this document + full changelog
├── scripts/
│   ├── verify.ps1                # local gate: vet, test, lint, vulns, deps, coverage, bundle hash
│   └── smoke.ps1                 # full loop against public APIs (networked)
├── cmd/
│   ├── kh-cli/                   # headless binary
│   │   └── main.go / main_test.go
│   └── kh-app/                   # Wails app entrypoint
│       ├── main.go               # //go:embed frontend/dist
│       ├── service.go            # Wails bindings (thin)
│       ├── build/                # icons, MSIX/NSIS config, DPI manifest
│       └── frontend/             # Svelte 5 + Vite (not ui/)
│           ├── package.json
│           ├── scripts/          # writes dist/.source-hash for the verify gate
│           ├── vendor/deepmerge/ # locally patched dependency (PATCH.md, license.txt)
│           ├── src/
│           └── dist/             # generated but tracked (//go:embed needs it)
├── internal/
│   ├── format/                   # .kh parse + serialize
│   ├── http/                     # request engine, env interpolation
│   ├── fuzz/                     # resolver, runner, heuristics, wordlists/
│   ├── spec/                     # kin-openapi parse + jsonschema validation
│   ├── diff/                     # JSON-aware + text diff
│   ├── report/                   # unified model + standalone HTML
│   ├── engine/                   # the loop shared by both binaries
│   └── strx/                     # small string helpers
├── testdata/
│   ├── specs/petstore.yaml
│   ├── requests/                 # sample .kh files + .kilhook env/baselines
│   └── smoke/                    # networked smoke-test requests
└── docs/
    ├── kh-format.md              # user-facing format reference
    ├── fuzzing-guide.md
    ├── quickstart.md
    ├── desktop-app.md
    └── security-review.md
Dependency rule: internal/* must never import wails or github.com/wailsapp/*. Enforced by a check in scripts/verify.ps1.

8. Development Phases
Phase 0 — Spike (Weeks 1–2)
Goal: Prove the seam exists and is meaningful before committing to the product.

Deliverables (in cmd/kh-cli only):

Parse a .kh file (frontmatter + body split)

Send the request via net/http with environment interpolation

Run one fuzzing pass: iterate a small wordlist into declared injection points

Load an OpenAPI file via kin-openapi and validate the baseline response with jsonschema

Print one combined terminal report

Specific risks to test:

Feed kin-openapi a large real-world spec (Stripe or GitHub subset). Confirm parse speed and correctness with kin-openapi ≥ v0.148.0.

Confirm the kin-openapi → jsonschema handoff works for nested response schemas (the most likely friction point).

Gate: Your own team uses the spike on a real internal API and says "this feels different from running three tools separately."

✅ Pass: Proceed to Phase 1

❌ Fail: Stop. Two weeks spent, four months saved. Reassess the market gap.

Phase 1 — Core Client (Weeks 3–6)
Goal: A usable daily-driver Git-friendly HTTP client.

Deliverables:

Finalize .kh format spec; freeze format: 1

internal/format: parser + serializer with round-trip tests

internal/http: request engine with environments, auth, redirects, timeouts

Wails app shell with minimal UI:

Folder picker plus a flat request list (workspace folder). A tree is deliberately
not shipped: Discover does not recurse, so one folder is one workspace and a
picker is enough.

Request editor (method, URL, headers, query, body, auth)

Environment selector, fed from .kilhook/env/*.yaml

Send button + response viewer (Run loop)

Explicit Save with a dirty chip and Ctrl+S, not save-on-edit. Silent writes to a
file the user is editing are the wrong default for a tool that shares its
workspace with an editor and a CLI.

Milestone: An engineer uses Kilhook instead of curl + a text editor for one full day and doesn't switch back.

Phase 2 — Fuzz Engine (Weeks 7–9)
Goal: Fuzzing runs from the same request file with one click.

Deliverables:

internal/fuzz/resolver.go: .kh fuzz targets → concrete request mutations

internal/fuzz/runner.go: worker pool, rate limiting, cancellation, max_requests cap

Rate limiting implemented as FuzzConfig{RateLimit, PerHostConcurrency} struct defaults (5, 2), overridden by .kh fuzz block; no hard-coded constants in the runner

internal/fuzz/heuristics.go: detection for status anomalies, error strings, reflection, timing

Bundled default wordlist (596 payloads: SQLi, NoSQL, command and template injection, path traversal, LDAP, XSS markers, format strings, boundary values, type confusion), non-destructive by design

Custom wordlist support

UI: fuzz tab, progress bar, findings list with severity

Security advisor review at end of phase. See §11. (Waived by the owner; replaced by the internal self-review in `docs/security-review.md`.)

Milestone: Fuzzing a request produces a findings list with < 10% false positives on the internal corpus.

Phase 3 — Spec Validator (Weeks 10–11)
Goal: Contract violations surface in the same report as fuzz results.

Deliverables:

internal/spec/loader.go: kin-openapi wrapper with caching and size limits (parse only)

internal/spec/validator.go: operation matching, response schema validation via jsonschema, readable error paths

internal/spec/drift.go: compare current response against stored baseline; detect schema drift

UI: spec tab, violations list with JSON path navigation

Milestone: A known-bad response (missing required field, wrong type) is caught with a clear error message pointing to the exact field.

Phase 4 — Diff & Combined Report (Weeks 12–13)
Goal: The 5-minute demo exists end to end.

Deliverables:

internal/diff/json.go: structured JSON diff (added/removed/changed, array-aware)

internal/diff/text.go: fallback text diff for non-JSON

internal/report/model.go: unified report model

internal/report/html.go: standalone HTML export template

UI: combined report view with sections for request, fuzz findings, spec violations, diff

Export to HTML, copy individual findings

Milestone: A complete loop (author → fuzz → validate → diff → report → export) runs in under 2 minutes on a sample API.

Phase 5 — Ship (Weeks 14–16)
Goal: Store submission.

Deliverables:

MSIX packaging via wails3 package GOOS=windows FORMAT=msix

Store listing: name, description, screenshots, privacy policy

Privacy policy stating: "No telemetry. No network calls except the API requests you author."

Docs: docs/kh-format.md, docs/fuzzing-guide.md, docs/quickstart.md

Closed beta with 10–20 developers; collect feedback

Fix top 5 friction points from beta

Store submission (Microsoft re-signs the MSIX; dev account registration is free)

Milestone: MSIX accepted by Microsoft Store certification within two submissions.

Timeline Summary
Phase	Duration	Cumulative
0 — Spike	2 wk	Week 2
1 — Core client	4 wk	Week 6
2 — Fuzz engine	3 wk	Week 9
3 — Spec validator	2 wk	Week 11
4 — Diff & report	2 wk	Week 13
5 — Ship	3 wk	Week 16
Total: 16 weeks.

9. Team & Roles

kilhook is designed, built and maintained by **24Bit System**, the product name
of **Two Four Bit Systech India Private Limited** (www.24bitsystem.com,
info@24bitsystem.com). The roles below describe the original team; named
contributors are credited in `AUTHORS.md`. The MIT copyright holder is the legal
entity above.

9.1 Minimum Viable Team
Role	Count	Allocation	Responsibility
Tech lead	1	Full-time	Architecture, .kh format, code review, scope guard, dependency pinning
Core dev	2	Full-time	HTTP engine, fuzz engine, spec validator, diff
UI dev	1 (can be one of the above)	Full-time	Wails UI, report rendering, Store assets
Security advisor	1	Part-time / consulting	Fuzz heuristics review, false-positive tuning, threat model
Designer	optional	Part-time	Report layout, Store screenshots
Total: 3 full-time engineers + part-time security review.

9.2 Role Details
Tech lead:

Owns the .kh format decision and freeze

Reviews every change that touches internal/format or internal/spec

Enforces scope: any change adding a feature not in §4.1 is rejected

Runs the Phase 0 gate review

Manages the security advisor engagement

Owns dependency pinning and govulncheck policy

Core devs:

Rotate across internal/http, internal/fuzz, internal/spec, internal/diff

Write tests before merging (see §10)

Dogfood Kilhook on internal APIs

UI dev:

Owns ui/ (Svelte) and the Wails bridge in cmd/kh-app

Responsible for the 5-minute demo experience

Coordinates Store screenshots and listing copy with tech lead

Security advisor:

Reviews fuzz heuristics at end of Phase 2

Signs off that detection logic is not superficial

Reviews false-positive rate against the test corpus

Not a builder; a gatekeeper

9.3 Communication Cadence
Daily: 15-minute standup (blockers, today's focus)

Weekly: Phase progress review against milestone; scope guard check

End of phase: Milestone demo + gate review (tech lead + advisor for Phase 2)

Ad hoc: Any scope change request goes to tech lead; decision documented in project.md

10. Testing & Quality Gates
10.1 Test Types
Type	Scope	Tool	Gate
Unit tests	internal/* packages	go test	80% line coverage on internal/format, internal/spec, internal/diff, internal/fuzz, internal/http, internal/engine
Round-trip tests	.kh parse → serialize → parse	go test	Zero diff on test corpus
Golden-file tests	Full report output on sample requests	go test with testdata/	Byte-identical output unless intentionally updated
Integration tests	Real HTTP against test server	go test + httptest	All pass in scripts/verify.ps1
Fuzz corpus tests	False-positive rate on known-good API	Custom harness: 4 offline fixtures (internal/fuzz/corpus_test.go) + 9 live APIs behind -tags corpuslive	< 10% false positives; currently 0 offline and 0 false positives on 9 live APIs (540 payloads / 572 requests including retries)
Vulnerability scan	Dependency CVEs	govulncheck	Fail on any known vulnerability
Manual smoke tests	Full loop on 3 real public APIs	Checklist	Signed off before beta
10.2 The False-Positive Budget
The fuzzer is only credible if its noise is low. Target: < 10% false positives on the internal test corpus.

The corpus: 10 real APIs (Petstore, GitHub, Stripe subset, internal APIs) with known-good responses

What exists today: a four-fixture harness (`internal/fuzz/corpus_test.go`) — a clean API, an API that returns a SQL error page, an API that reflects input, and an API that is slow only for `sleep` payloads. The clean fixture is the precision measurement by construction: **0 findings over 150 payloads**, a zero-false-positive result (precision is undefined when there are no findings). The vulnerable fixtures are detected with no extra rows. That found one real defect: reflection was reported on 500 error pages that merely quoted the input, so it is now restricted to 2xx responses.

Nine real public APIs are measured too (`internal/fuzz/corpus_live_test.go`, behind the `corpuslive` build tag so the offline gate never needs the network; agify answered 429 and was skipped): 540 payloads (572 requests including 32 confirmation retries) at three per second produced no false positives, two expected reflection findings on the APIs that echo input, and one high finding triaged as a genuine defect — `/api/character/' OR 1=1--` on Rick and Morty returns 500 for any non-numeric id, which is a server error for a client mistake.

That run also justified a change to the runner: the first live pass reported a 5xx on open-meteo that could not be reproduced by hand, so every 5xx is now re-sent once and dropped if the retry lands below 500. The persistent one is still reported. These results were reviewed internally (v1.19); the independent advisor sign-off was waived by the project owner, so that independence remains a residual risk.

A "false positive" is a finding flagged on a request that should produce no findings

Every release candidate runs the corpus; a breach of 10% is a release blocker

The security advisor reviews the corpus results

10.3 Local Verification Gate (no CI service)
There is no CI service and no version-control host. The gate is one local script, `scripts/verify.ps1`, run by the contributor before handing a change to the tech lead, and again by the tech lead before each milestone demo and every Store submission. It exits non-zero on the first failure and prints the failing step:

go vet ./...

go test ./... -race -coverprofile=coverage.out

golangci-lint run

go mod tidy check (copy go.mod/go.sum to a temp dir, run tidy, diff the copies; abort on any difference)

govulncheck ./... (fails on known vulnerabilities — including any regression below kin-openapi v0.148.0)

Dependency rule check: internal/* must not import wails

Coverage gate: fail if internal/format, internal/spec, internal/diff, internal/fuzz, internal/http or internal/engine coverage < 80%

Frontend staleness check: `npm run build` writes a content hash of the frontend inputs to `cmd/kh-app/frontend/dist/.source-hash`; the gate recomputes it so a stale bundle ships silently neither on a developer machine nor on a fresh clone (git does not preserve mtimes)

Merge rule: a change that cannot leave the gate green does not land. Since nothing runs automatically, the gate is also the only thing between a broken build and a Store submission — treat a skipped run as a failed run.

10.4 Release Gate Checklist
Before any Store submission:

□ scripts/verify.ps1 green (including govulncheck)
□ kin-openapi ≥ v0.148.0 pinned; no vulnerable dependencies
□ False-positive budget met on test corpus
□ Security advisor sign-off on fuzz heuristics
□ .kh format spec frozen and documented
□ Privacy policy published
□ MSIX builds and installs on a clean Windows 10 and Windows 11 VM
□ Full loop smoke test passes on 3 public APIs — scripted and passing on 4 (scripts/smoke.ps1); awaiting sign-off
□ Beta feedback top 5 issues resolved or documented as deferred
11. Security Model
11.1 What Kilhook Does
Sends HTTP requests to user-specified URLs

Runs fuzzing payloads against user-specified targets

Validates responses against user-specified OpenAPI specs

All work happens locally; no data leaves the machine except the API requests themselves

11.2 What Kilhook Does Not Do
No telemetry, no analytics, no crash reporting

No background processes; nothing runs when the app is idle

No cloud sync; workspace files are local

No code execution from responses or specs

No privilege escalation; runs as a standard user

11.3 Threat Model
Threat	Mitigation
Fuzzing a production API causes damage	max_requests cap (default 500); warning dialog when URL is not localhost; rate limiting; non-destructive payloads
Malicious response payload exploits parser	Go memory safety; bounded response size (default 10 MB); no eval
Malicious OpenAPI spec	kin-openapi ≥ v0.148.0 (CVE-2026-100352 fixed); spec size limits; no external $ref resolution by default
Wordlist poisoning	Bundled wordlist is versioned and reviewed; custom wordlists are user's responsibility
Supply chain (dependency compromise)	govulncheck + go mod verify in scripts/verify.ps1; minimal dependency surface; pinned versions
MSIX package tampering	Store signing; no sideloading in v1
User runs Kilhook against unauthorized targets	Out of scope — user responsibility; documented in quickstart
11.4 Security Advisor Scope (Phase 2 Review)
Status: waived by the project owner. Replaced with an internal self-review recorded in `docs/security-review.md` and changelog v1.19; it is not an independent sign-off. The review scope below is what was assessed.

The advisor reviews:

Injection point resolver correctness — are declared targets actually being mutated? Are undeclared fields accidentally mutated?

Detection heuristics quality — do the heuristics catch real issues without flooding false positives?

Payload safety — are bundled payloads non-destructive? (e.g., time-based blind SQLi rather than destructive statements)

Rate limiting adequacy — can a fuzzing run overwhelm a small API?

Default wordlist review — are the ~500 payloads appropriate and effective?

Deliverable: Written sign-off or list of required changes.

Budget: $2,000–$5,000 for 2–3 days of review.

12. Distribution & Legal
12.1 Signing & Distribution
Channel	Signing	Cost
Microsoft Store (primary)	Store-signed MSIX	$0 (dev account registration is free; Store re-signs package)
Decision for v1: Ship Store-only. No direct downloads. Revisit direct downloads only if demand appears and a certificate becomes justified.

12.2 License
Recommended: MIT or Apache-2.0.

Maximizes adoption (developers can use it internally without legal review)

Permits commercial use, modification, distribution

No copyleft concerns for enterprise users

Not AGPL — would deter enterprise adoption and is unnecessary for a local tool with no hosted service

12.3 Privacy Policy
Store listing must state:

Kilhook runs entirely on your machine. It does not collect telemetry, analytics, or crash reports. It does not contact any server except the API endpoints you explicitly configure it to call. Your request files, environments, and results stay in your local workspace folder.

This is a marketing asset — put it prominently in the Store listing.

12.4 Name & Trademark
Name: Kilhook (name availability checked on package registries; no software trademark found)
Owner: 24Bit System / Two Four Bit Systech India Private Limited (www.24bitsystem.com)

Action required before Phase 1: live WHOIS on kilhook.dev and kilhook.io

Trademark: no software trademark found; file a defensive trademark only if the project gains traction (post-v1)

13. Budget
13.1 Cash Costs
Item	Cost	Notes
Hosting / infrastructure	$0	Local tool; no server
Dependencies	$0	All open-source
Source, releases, docs	$0	Local working copy + Store listing; no paid hosting, no CI service
Windows Store dev account	$0	Registration is free
Windows Store signing	$0	Store re-signs the MSIX
Domain names (optional)	~$15/year	kilhook.dev + kilhook.io
Security advisor review	$2,000–$5,000	Phase 2, one-time
Total v1 cash	$2,015–$5,015	
13.2 Team Cost (Opportunity Cost, Not New Cash)
Role	Weeks	Hourly equivalent	Notional cost
Tech lead	16	$75/hr	$48,000
Core dev × 2	16 each	$75/hr	$96,000
UI dev	16	$75/hr	$48,000
Total notional			~$192,000
This is the opportunity cost of existing payroll, not new spending. The only new cash is the security review.

13.3 Cost Comparison
Alternative	Cost
Kilhook v1	~$2–5k cash + team time
Buying existing tools (Postman Team + Burp Pro + contract tool) for 5 devs, 1 year	~$5,000–$8,000/year, recurring
Building a cloud-hosted API platform	$50k+ infrastructure/year
14. Risk Register
#	Risk	Likelihood	Impact	Mitigation	Owner
R1	Fuzzing produces noise, tool loses credibility	Medium	High	Security advisor + <10% false-positive budget + narrow heuristics	Tech lead
R2	Scope creep ("add just one more feature")	High	High	Locked v1 table; tech lead enforces; deferred items to roadmap	Tech lead
R3	kin-openapi struggles with large/messy specs	Medium	High	Phase 0 spike against Stripe/GitHub; narrowed-subset fallback	Core dev
R4	.kh format needs breaking changes later	Medium	Medium	Phase 0 freeze; version from day one; migration tool policy	Tech lead
R5	Raill_HTTPX or Bruno adds deep spec validation	Medium	Medium	Ship fast; own the .kh declarative format as switching cost	Tech lead
R6	Wails v3 MSIX path has rough edges	Medium	Medium	Pin Wails v3 ≥ beta.21 (PR #6115 fixed MSIX command registration); prove hello-world MSIX in week 1, not week 14; if it will not install on clean Win10/11 VMs by end of week 1, fall back to WebView2 + .NET single-project MSIX (fixed fallback, +1–2 wk schedule, no scope change)	UI dev
R7	Store certification delays	Low	Medium	Submit early in Phase 5; have unpackaged fallback	UI dev
R8	Team lacks security depth for credible fuzzing	Medium	High	Budget the part-time advisor; treat sign-off as a gate	Tech lead
R9	Beta users don't adopt (the seam isn't compelling)	Medium	High	Phase 0 gate; beta feedback loop; willingness to stop	Tech lead
R10	Go concurrency bugs in fuzz runner	Low	Medium	-race in scripts/verify.ps1; bounded worker pool; context cancellation tests	Core dev
R11	Dependency CVE (e.g., kin-openapi pre-0.148.0 DoS)	Medium	High	Pin kin-openapi ≥ v0.148.0; govulncheck in scripts/verify.ps1; monthly manual dependency review	Tech lead
R12	User fuzzes production and causes incident	Medium	High	max_requests cap; non-localhost guard (--allow-nonlocal required); rate limiting (5 req/s, 2/host); non-destructive payloads; docs	Core dev
R13	Multipart/form body fuzzing not supported in v1; users expect body.* to work on all body types	Medium	Low	Explicit §4.2 scope line; parser warning + skip; documented in docs/fuzzing-guide.md; revisit as v1.1 feature with a real user case	Tech lead
14.1 The Stop Conditions
The project stops if:

Phase 0 gate fails — the spike doesn't feel meaningfully better than three separate tools

False-positive budget cannot be met after advisor review and one iteration

Beta retention < 30% at week 4 of closed beta

Scope creep cannot be contained — v1 keeps growing past week 10

Each stop condition is a decision point, not a failure. Documented in the project log.

15. Post-V1 Roadmap
None of these are promised to users until shipped. Each gets its own validation cycle.

15.1 Near-Term (v1.1–v1.3, Months 5–8)
CLI mode — headless kilhook run request.kh for scripts and CI. Core is already decoupled.

Collection runner — sequential requests with variable chaining ({{response.user_id}})

Import from OpenAPI — generate .kh files from an OpenAPI spec

Import from Postman/Bruno — converter scripts

Multipart / form-urlencoded body fuzzing — part-aware targets, ordering-preserving mutation, binary-part handling. Requires a real user case and a format: 2 discussion before implementation.

15.2 Medium-Term (v2.0, Months 9–14)
CI mode — kilhook ci with exit codes and JUnit XML output, consumable from any runner the user already has

Contract diff in CI — fail builds on breaking OpenAPI changes

MCP server mode — expose workspace to local AI agents

macOS / Linux — Wails cross-build; Apple signing budget

15.3 Long-Term (v3.0+, Months 15+)
Plugin system — custom fuzz heuristics, custom validators

Team collaboration — optional, opt-in, self-hosted sync server (only if demand)

GraphQL support — schema validation and fuzzing for GraphQL endpoints

Load testing mode — lightweight, bounded, not a JMeter replacement

15.4 Explicitly Not Planned
Cloud-hosted SaaS version of Kilhook

Full vulnerability scanner (XSS, CSRF, auth chain analysis)

AI-generated test cases in v1 or v2 (only if MCP proves demand)

Mobile clients

16. Immediate Next Steps
This Week (Week 1)
#	Action	Owner	Output
1	Confirm the name. Live WHOIS on kilhook.dev and kilhook.io; check package-registry name availability	Tech lead	Registered name or fallback decision
2	Hello-world Wails v3 app packaged as MSIX via the Wails v3 MSIX tool	UI dev	MSIX builds and installs in developer mode (com.kilhook.app 0.1.0.0 x64); a trusted install on a clean Win10/11 VM still to prove
3	Spike kin-openapi ≥ v0.148.0 + jsonschema. Feed a large real spec (Stripe or GitHub subset). Confirm parse and validation speed	Core dev	Report: smooth / needs fallback / blocked
4	Write the one-page .kh format spec and circulate for review	Tech lead	docs/kh-format.md draft
5	Line up the security advisor for Phase 2 (week 9)	Tech lead	Engagement letter or LOI

Decision node (end of Week 1): if the MSIX does not build, does not install, or fails Store pre-check on a clean Win10 *and* Win11 VM, switch the shell to **WebView2 + .NET single-project MSIX** — the fallback is fixed, not a menu. Do not carry a broken packaging path into Phase 5. Record the decision in §17.3.

Why WebView2 + .NET and not Wails v2: a Wails v3 MSIX failure is likely the *same* failure surface as Wails v2, so v2 trades a pre-release risk for an older one. WebView2 + .NET is the path where MSIX is Microsoft's own first-class scenario — a different failure surface, which is what a fallback is for.

Fallback cost note: the Wails bridge in cmd/kh-app is discarded; internal/* is reused unchanged as a sidecar process. Budget 1–2 weeks for the IPC layer (local HTTP or stdio JSON-RPC) and .NET shell if the fallback fires. This is a schedule hit, not a scope hit.
Week 2
#	Action	Owner	Output
6	Build the Phase 0 CLI spike (see §8)	Core dev	cmd/kh-cli working on 1 real API
7	Team dogfoods the spike on internal APIs	All engineers	Feedback notes
8	Phase 0 gate review	Tech lead	✅ Proceed / ❌ Stop decision
9	Freeze .kh format v1 if proceeding	Tech lead	Committed spec
The One Gate That Matters
If the Phase 0 spike does not feel meaningfully better than running Bruno + a fuzzer + a schema validator separately, stop.

Two weeks spent, four months saved.

17. Appendix: Glossary & References
17.1 Glossary
Term	Definition
.kh file	Kilhook request file: frontmatter (metadata) + --- + raw body
The loop	Author → fuzz → validate → diff → report, in one tool
The seam	The context switch between tools that Kilhook eliminates
False positive	A fuzz finding flagged on a request that should produce no findings
Baseline	Last known-good response, stored for drift and diff comparison
Drift	When an API's actual response no longer matches its OpenAPI spec
Injection target	A field declared in .kh for fuzzing (header, query, path, body)
Wordlist	A list of payloads injected during fuzzing
17.2 Key References
Existing tools (competitive landscape):

Postman — https://www.postman.com

Bruno — https://www.usebruno.com

Yaak — https://yaak.app

Raill_HTTPX — GitHub (single-binary Rust client + fuzzer + scanner; closest competitor)

Stubrix — GitHub (unified API lifecycle, Docker-based)

Routebase — commercial OpenAPI lifecycle platform

Specmatic — https://specmatic.io

Go libraries:

kin-openapi — https://github.com/getkin/kin-openapi (pin ≥ v0.148.0; CVE-2026-100352)

santhosh-tekuri/jsonschema — https://github.com/santhosh-tekuri/jsonschema

sergi/go-diff — https://github.com/sergi/go-diff

cobra — https://github.com/spf13/cobra

Wails:

Wails v3 — https://wails.io

MSIX packaging — wails3 package GOOS=windows FORMAT=msix

Specification:

OpenAPI 3.x — https://spec.openapis.org/oas/v3.1.0

JSON Schema — https://json-schema.org

Security:

OWASP API Security Top 10 — https://owasp.org/API-Security/

CVE-2026-100352 — kin-openapi YAML NaN/Infinity DoS (fixed in v0.148.0)

17.3 Document Changelog
Version	Date	Author	Changes
1.0	—	Tech lead	Initial plan: Go + Wails stack, 16-week timeline, locked v1 scope
1.1	—	Tech lead	Pinned kin-openapi ≥ v0.148.0 (CVE-2026-100352); clarified kin-openapi parses spec vs. jsonschema validates response; added Wails v3 MSIX command; noted free Store dev account; updated competitive landscape
1.2	—	Tech lead	Wails v3 ≥ beta.21 floor + Week 1 MSIX fallback node; concurrency defaults (5 req/s, 2/host) and --allow-nonlocal; timing heuristic demoted to advisory; spec parsing vs. generation clarified; path.N scope and in-memory-only fuzz mutations specified; binary-size gate moved to end of Phase 1
1.3	—	Tech lead	Multipart/form body fuzzing declared out of scope for v1 (parser warns + skips body.* targets; no format change); R13 accepted gap; v1.1 roadmap item gated on a real user case
1.4	—	Tech lead	Week 1 fallback pinned to WebView2 + .NET single-project MSIX (Wails v2 option removed) with stated 1–2 week schedule cost and sidecar rationale; Phase 2 rate-limiting deliverable (FuzzConfig defaults, no hard-coded constants)
1.5	—	Tech lead	Team workflow made VCS- and CI-free: scripts/verify.ps1 as the single local gate, monthly manual dependency review, .github/ removed from layout, GitHub Releases and GitHub budget line dropped. Product language about diffable files and user-side CI kept deliberately
1.6	—	Tech lead	Phase 0 implemented and verified (CLI loop, tests, docs, green local gate). Fuzz payloads interleaved across methods and targets so max_requests cannot starve later targets; progress output moved to stderr to keep --json parseable; --html creates its parent directory; JSON always emits warnings, spec.violations, fuzz.findings and diff.changes
1.7	—	Tech lead	Loop extracted to internal/engine (shared by CLI and app); cmd/kh-app Wails v3.1.0 + Svelte 5 window implemented and screenshot-verified; default baselines now resolve without a spec.baseline entry; progress callbacks fire for every run
1.8	—	Tech lead	Document model + editor form implemented in cmd/kh-app (load, edit, save, warnings); Save reparses before writing, writes atomically, omits defaults, byte-idempotent; JS error overlay added after a render fault surfaced as a dead tab
1.9	—	Tech lead	MSIX package built via wails3 tool msix + SDK MakeAppx from cmd/kh-app/build/config.yml (identity com.kilhook.app 0.1.0.0 x64; 11.7 MB package, 22.7 MB exe) and inspected; unsigned, so signing and Store submission remain. Editor gained dirty chip, Ctrl+S and Save & Run. Coverage floor extended to internal/fuzz (81.2%) and internal/http (80.3%)
1.10	—	Tech lead	MSIX install proven by developer-mode registration (no admin) and an end-to-end run from the installed package; signed-package install blocked by machine-store trust (0x800B0109), which Store re-signing removes. Fixed Workspace.Home offering C:\Windows\System32 as the workspace after an MSIX launch; now falls back to the user profile (cmd/kh-app/service_test.go)
1.11	—	Tech lead	Four-fixture fuzz corpus added (clean, SQL-error, echo, slow) measured at 0 false positives on the clean fixture; reflection restricted to 2xx so error pages stop double-reporting; bundled wordlist grown 95 -> 596 payloads across injection, boundary and type-confusion families. 10-real-API corpus and advisor review remain open
1.12	—	Tech lead	Live false-positive corpus added behind -tags corpuslive (5 public read-only APIs, 60 payloads each, 3 req/s): 0 false positives in 300 requests; 2 expected reflection findings on echo APIs; 1 high finding triaged as a real defect (Rick and Morty returns 500 for any non-numeric id). Offline fixture corpus remains the enforcing gate
1.13	—	Tech lead	Live corpus extended to nine public APIs (540 payloads / 572 requests including retries, 0 false positives, one triaged true positive). Runner now re-sends each 5xx once and suppresses status/error findings that do not reproduce, after a transient open-meteo 5xx was reported and could not be re-created; tests cover both transient and persistent cases
1.14	—	Tech lead	Trust-boundary review of the fuzzer: loopback guard extended to redirects (WithLocalOnly, wired in the runner, two tests) so a local 302 cannot spray a remote host; file-supplied spec.baseline confined to the workspace because --update-baseline writes through it. Spec size cap verified already present at 8 MiB. Advisor sign-off remains the only open Phase 2 item
1.15	—	Tech lead	Full-loop smoke test scripted (scripts/smoke.ps1) and passing against 4 public APIs with testdata/smoke/ requests; Petstore validated against its live OpenAPI document, HTML exported and inspected. Checklist item still needs sign-off
1.16	—	Tech lead	Phase 1 UI closed: native folder picker with cancel-as-no-op (dialogResult + test) and env dropdown from .kilhook/env; both screenshot-verified via UI Automation. internal/engine added to the coverage gate at 81.2% with units_test.go
1.17	—	Tech lead	Review-driven hardening: secret redaction in reports; wordlist/mutation bounds; bounded document reads; managed-header and Host fuzz handling; finite rate limits; spec failures degrade to warnings; workspace confinement for Open/Run/Modified; local-only proxies disabled; svelte-check added to the gate
1.18	—	Tech lead	Brand assets wired through window, empty state, favicon, app icon, Windows .ico, syso and docs; startup window fitted to the work area; DPI manifest embedded; deepmerge vendored with a prototype-poisoning fix and install-links=true; Vitest suite added; stale installed-package screenshot removed; live Petstore report screenshot regenerated
1.19	—	Tech lead	Phase 2 closed by internal self-review, independent advisor waived. Removed the destructive DROP TABLE payload and added a wordlist safety test; suppressed baseline error strings; corrected 540 payloads vs 572 requests and the zero-findings precision wording; documented wordlist confinement, retry budget and internal workers. Residual risk: no independent sign-off
1.20	—	Tech lead	Phase 3/4 UI gaps closed: per-finding clipboard copy (Wails bridge + browser fallback) and click-to-locate JSON-path navigation for contract violations with a temporary highlight; violation copy as text. Vitest covers the text/path helpers. Phase 3 and Phase 4 code-complete
End of Project Kilhook — Master Plan v1.20

The request file is the spine. The seam is the product. Ship the loop, nothing else.