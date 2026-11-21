# Quickstart

Kilhook runs entirely on your machine. No account, no telemetry, no server. The
only network calls are the API requests you author.

## 1. Build

```powershell
go build -o bin/kh-cli.exe ./cmd/kh-cli
```

## 2. Write a request file

`requests/petstore-get.kh`:

```yaml
format: 1
name: Get Pet
method: GET
url: "{{base_url}}/pets/{{pet_id}}"
headers:
  Accept: application/json
fuzz:
  targets:
    - path.1
    - query.expand
spec:
  source: "../specs/petstore.yaml"
  operation: "/pets/{id} get"
---
```

`requests/.kilhook/env/dev.yaml` (environment files live next to your requests):

```yaml
base_url: "http://localhost:8080"
pet_id: "42"
```

An OpenAPI document next to it, `specs/petstore.yaml` — see
`testdata/specs/petstore.yaml` for a working example.

## 3. Run the loop

```powershell
bin/kh-cli.exe run requests/petstore-get.kh --env dev
```

One run sends the baseline request, validates it against the spec, fuzzes the
declared targets, and diffs against the stored baseline. The text report looks
like this:

```
kilhook 0.1.0 — problems found
GET http://localhost:8080/pets/42
response: 200 in 12ms, 48 bytes

spec: GET /pets/{id}
  violation response.id: got string, want integer

fuzz: 47 request(s) in 9214ms
  [high] status_anomaly path.1: baseline 200 -> 500 for payload "../../etc/passwd"

warnings:
  - fuzz.targets: body.email skipped, body is multipart not JSON
```

Exit codes: `0` clean, `1` findings or contract violations, `2` the run could
not complete (missing variable, dead host) **or** a declared fuzz pass that was
aborted or skipped by the non-localhost guard. An unreadable spec is a warning,
not an abort: the rest of the loop still runs. A run that already saw findings
or violations still exits `1`.

## 4. Useful flags

| Flag | Effect |
| --- | --- |
| `--env dev` | Load `.kilhook/env/dev.yaml` next to the request file |
| `--env-file path.yaml` | Load an explicit environment file |
| `--update-baseline` | Store this response as the last-known-good baseline |
| `--html report.html` | Write the standalone HTML report |
| `--json` | Print the report as JSON (machine-readable) |
| `--no-fuzz` / `--no-spec` / `--no-diff` | Skip one phase |
| `--max-requests 50` | Override the file's fuzz cap |
| `--rate-limit 2` | Override the global request rate |
| `--allow-nonlocal` | Permit fuzzing a host that is not localhost |
| `--timing` | Enable the advisory timing heuristic (off by default) |
| `--insecure` | Skip TLS certificate verification |

## 5. Baselines and drift

The first run with `--update-baseline` stores `.kilhook/baselines/<name>.json`
(or the path in `spec.baseline`). Later runs diff against it and report added,
removed, changed and type-changed fields:

```
diff vs C:\work\api\.kilhook\baselines\get-pet.json (json)
  ~ response.name "rex" -> "rex2"
  + response.vaccinated true
```

## 6. Verify the loop offline

The whole pipeline is covered by tests that spin up a local server, including a
run that finds a 500 and a SQL error string, and one that catches a contract
violation:

```powershell
go test ./cmd/kh-cli/ -v
```

## 7. Before you merge anything

```powershell
pwsh -File scripts/verify.ps1
```

That is the only gate (there is no CI): vet, `go test -race`, golangci-lint,
`go mod tidy` check, `govulncheck`, the "internal/* must not import wails" rule,
and the 80% coverage floor for `internal/format`, `internal/spec`,
`internal/diff`, `internal/fuzz`, `internal/http` and `internal/engine`, plus a
staleness check on the embedded frontend bundle. The build writes a content hash
of the frontend sources to `dist/.source-hash`, so the gate works on a fresh
clone (git does not preserve file timestamps).

## 8. Smoke test against public APIs

The one scripted check that uses the network, and the pre-submission checklist
item "full loop smoke test on 3 public APIs":

```powershell
pwsh -File scripts/smoke.ps1
```

It builds the CLI in a temp workspace, downloads the live Petstore OpenAPI
document, then runs send → contract → fuzz → report → HTML export against four
real read-only services (20 payloads each, 3 req/s). Requests are in
`testdata/smoke/`. Last run:

| Case | HTTP | Exit | Violations | Findings |
| --- | --- | --- | --- | --- |
| `petstore` (real spec) | 200 | 0 | 0 | 0 |
| `httpbin` | 200 | 1 | — | 1 low reflection (it echoes its input) |
| `jsonplaceholder` | 200 | 0 | — | 0 |
| `dummyjson` | 200 | 0 | — | 0 |

Exit 1 means "findings", not "broken". The Petstore case validates a live
response against a live spec document; the rendered HTML report is at
`screens/smoke-petstore.png`.

Nothing is left behind: the workspace is under your temp directory.

## Fuzzing safety

Fuzzing is capped at `max_requests`, rate-limited to 5 req/s with 2 in-flight
requests per host by default. Without `--allow-nonlocal`, a non-localhost target
is **skipped**: no fuzz requests are sent, a warning is recorded, and the
baseline, contract and diff results are still reported with exit code `2`
(incomplete). Bundled payloads are non-destructive. Point it at your dev
environment, not at someone else's production API.
