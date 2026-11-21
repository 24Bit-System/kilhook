# Fuzzing guide

Kilhook's fuzzer takes the request you already authored and injects payloads at
the points the file declares. No re-authoring, no separate config.

## What it does

For every target × payload pair it sends one request, then compares the response
to the baseline request's response:

| Finding | Severity | What it means |
| --- | --- | --- |
| `status_anomaly` | high | The baseline succeeded but this payload produced a 5xx |
| `error_string` | high | The response leaked SQL/stack/template/OS internals |
| `reflection` | low | The payload came back verbatim in a 2xx — an injection signal, not a bug on its own |
| `timing_outlier` | advisory | Slower than the baseline by the configured factor |

`timing_outlier` is **off by default** and never counts as a finding when
enabled; it appears in the report under "advisory observations". It is the
largest source of false positives on the internal corpus, so it is opt-in
(`--timing`) until the corpus justifies a threshold.

Every 5xx that produced a status anomaly is re-sent once before it is reported.
One overloaded backend moment is enough to fake the highest-value finding, and a
single retry removes that class of noise. The retry draws from the same
`max_requests` budget, so a 5xx-heavy run trades payload coverage for
confirmation. If the second response is below 500, the status and error-string
findings for that payload are dropped; transport errors and other kinds survive
untouched.

Reflection is only reported for success responses. An error page that quotes the
input is the error explaining itself, and that response already produces a status
or error-string finding, so counting reflection there would report one
observation twice.

Repeated hits are collapsed per (kind, target): one row with a count, not fifty
identical rows.

## Where requests are allowed to go

When the request's host is not this machine, `--allow-nonlocal` is required.
Without it the fuzz pass is skipped with a warning — no fuzz requests are sent —
but the baseline response, contract check and baseline diff still run and produce
a report (exit code `2`, incomplete). That rule also applies to redirects: a local server that answers
`302 Location: https://example.com/...` gets the redirect back as a 302 instead of
having the fuzz requests forwarded off-machine. Without that check the loopback
guard would only cover the first hop.

## Targets

```yaml
fuzz:
  targets:
    - body.email           # JSON body field
    - body.items.0.name    # nested, array index
    - query.q
    - header.X-Forwarded-For
    - path.1
```

- `body.*` only resolves for JSON bodies. Multipart and form-urlencoded body
  fuzzing is out of scope for v1; declaring `body.*` on those bodies produces a
  warning and the targets are skipped (the run continues).
- `path.N` counts URL path segments only, after `{{variables}}` are resolved.

## Measured false positives

The fuzzer has a fixture corpus in `internal/fuzz/corpus_test.go`: four local
servers whose correct answers are known by construction.

| Fixture | Behaviour | Expected | Measured |
| --- | --- | --- | --- |
| `clean` | validates and ignores input, never 5xx, never echoes | no findings | 0 findings |
| `sql-unsafe` | 500 + `SQLSTATE[42000]` when the input looks like SQL | status + error string | both, no extra |
| `echo` | echoes the payload in a 200 | reflection only | reflection |
| `slow` | 1.4 s only for `sleep` payloads | nothing unless `--timing` | nothing by default |

Every finding on `clean` is a false positive by construction. It currently
reports **0 findings over 150 payloads** — a zero-false-positive result, not a
precision estimate (precision is undefined when there are no findings). The
vulnerable fixtures are detected with no additional rows. Run it yourself:

```powershell
go test ./internal/fuzz/ -run TestCorpus -v
```

This corpus found one real defect: a 500 error page that quoted the offending
input produced both `error_string` and `reflection` for the same observation.
Reflection is now restricted to 2xx responses. Error strings already present in
the baseline are also excluded: an existing leak is not caused by the payload,
and reporting it once per target would inflate the finding count.

### Against real APIs

`internal/fuzz/corpus_live_test.go` does the same measurement against public,
read-only endpoints. It sits behind a build tag so the offline gate never depends
on the network, and it is polite: three requests per second, one connection per
host, sixty payloads per API.

```powershell
go test ./internal/fuzz/ -tags corpuslive -run TestLiveCorpusPrecision -v -timeout 15m
```

Last run, nine APIs measured (agify was rate-limited by the provider and skipped):

| API | Baseline | Requests | High | Medium | Low | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `httpbin` | 200 | 60 | 0 | 0 | 1 | echoes its input; reflection expected |
| `postman-echo` | 200 | 60 | 0 | 0 | 1 | echoes its input; reflection expected |
| `jsonplaceholder` | 200 | 60 | 0 | 0 | 0 | ignores the fuzzed header |
| `dummyjson` | 200 | 60 | 0 | 0 | 0 | ignores the query parameter |
| `rickandmorty` | 200 | 92 | 1 | 0 | 0 | **triaged: real defect** (32 retries) |
| `pokeapi` | 200 | 60 | 0 | 0 | 0 | 404s for unknown ids, never 5xx |
| `swapi` | 200 | 60 | 0 | 0 | 0 | no findings |
| `open-meteo` | 200 | 60 | 0 | 0 | 0 | one transient 5xx, suppressed by the retry |
| `sunrise-sunset` | 200 | 60 | 0 | 0 | 0 | no findings |
| `agify` | 429 | — | — | — | — | skipped: provider rate limit |

The one high finding is `status_anomaly` on `/api/character/' OR 1=1--`. Reproduced
by hand: the API answers `500 {"error":"Hey! you must provide an id"}` for *any*
non-numeric id, including `hello`. A bad path segment is a client error and should
be a 4xx; returning 5xx is the API's bug, so this is a true positive, not corpus
noise. False positives measured on real APIs: **0 across nine APIs — 540
payloads, or 572 requests including the 32 confirmation retries**. The request
column above is the real number; 540 is the planned payload count.

The retry earned its place here. Before it existed, `open-meteo` produced a
`status_anomaly` for `;
id` which could not be reproduced by hand afterwards —
a one-off 5xx from their backend. After the retry was added, the same payload
runs clean, and the only 5xx that survives is the reproducible one.

Two endpoints are deliberately absent: GitHub's API (its 60-per-hour limit would
be spent by one run) and the Swagger Petstore demo (it answers 403 to this client,
which would measure Cloudflare rather than the API).

## Methods and the bundled wordlist

| Method | Payloads | Injected as |
| --- | --- | --- |
| `injection` | 323 | string — SQLi, NoSQL, command, template, path traversal, LDAP, XSS markers, format strings, log injection |
| `boundary` | 187 | string — empty, very long, unicode, numeric and date limits, encoded nulls |
| `type_confusion` | 86 | JSON literal — objects, arrays, null, huge numbers |

596 payloads in total, deduplicated and interleaved across methods.

Bundled payloads are **non-destructive by design**: arithmetic markers (`${7*7}`),
harmless commands (`id`), read-only file probes (`/etc/passwd`), `SLEEP(0)`,
`pg_sleep(0)`, `WAITFOR DELAY '0:0:0'`. Nothing writes, drops or deletes.
`TestBundledWordlistIsNonDestructive` enforces that list and fails on fragments
such as `DROP TABLE`, `DELETE FROM`, `rm -rf` or `mkfs`.

Token expansion keeps the wordlist readable:

- `<empty>` — the empty string
- `<repeat:X:N>` — N copies of X (used for 1 KB and 64 KB payloads)
- `<longjson>` — a deeply nested JSON array

### Custom wordlists

Set `wordlist:` to a path relative to the `.kh` file's directory. The engine
resolves it there and refuses a path that leaves the workspace. Custom lists are
capped at 5 MiB and 200,000 payloads.

```
# one payload per line, # starts a comment
' OR 1=1--
${7*7}
```

Custom payloads are injected as strings against every selected method.

## Limits — and why they exist

| Knob | Default | Purpose |
| --- | --- | --- |
| `max_requests` | 500 | Hard cap per run; the rest are reported as skipped |
| `rate_limit` | 5 req/s | Shared token bucket across all workers |
| `per_host_concurrency` | 2 | In-flight requests per host |
| workers | min(NumCPU, 10) | Cancelled together by Ctrl+C / the UI Stop button |

The first three are configurable per file; `workers` is internal. The values are
fields on the run config, not constants in the runner, so a `.kh` file without
fuzz settings still gets the documented defaults.

## Non-localhost guard

Fuzzing a host that is not `localhost`, `127.0.0.1` or `::1` is **skipped before the
first fuzz request** unless `--allow-nonlocal` is passed; the run still reports the
baseline response, contract result and diff, with a warning explaining the skip.
Plain (non-fuzz) requests are unaffected. This is the v1 protection against turning
a production API into a test target.

## Reading the output

```
fuzz: 47 request(s) in 9214ms
  [high] status_anomaly query.q: baseline 200 -> 500 for payload "' OR 1=1--"
  [high] error_string query.q: SQLSTATE[42000]: syntax error at or near "OR"
```

A clean run prints `no findings` and exits 0. Any finding or contract violation
exits 1, so the CLI is usable in a script without parsing text.
