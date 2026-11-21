# Security policy

kilhook sends the HTTP requests you write and fuzzes them. There is no server,
no account and no telemetry. The parts worth attacking are the local paths the
app trusts and the report files it writes.

## Reporting

Email **info@24bitsystem.com**, or use the private advisory form at
[github.com/24Bit-System/kilhook/security/advisories/new](https://github.com/24Bit-System/kilhook/security/advisories/new).
Please do not open a public issue for something that is not fixed yet.

Include the kilhook version, a `.kh` file or spec that reproduces the problem,
and what you expected to happen instead. Redact any real credentials from the
files you send.

You will get a reply saying whether we can reproduce it. If we decide it is not
a defect, we will tell you why.

## In scope

- A shared `.kh` file making kilhook write outside the workspace. `spec.baseline`,
  `fuzz.wordlist` and environment paths pass through `withinDir` and
  `engine.WithinDir` in `internal/engine/engine.go` for this reason.
- The loopback guard in `internal/fuzz/runner.go` or the redirect check in
  `internal/http/client.go` letting fuzz traffic reach a non-loopback host
  without `--allow-nonlocal` or the typed confirmation in the window.
- Credentials appearing in a report or exported HTML, including JSON and text
  diffs and fuzz evidence. The single place to fix that is
  `internal/engine/redact.go`.
- A hostile spec, response, wordlist or baseline getting past the size caps
  (4 MiB `.kh`, 8 MiB spec, 10 MiB response, 5 MiB wordlist).
- Removal or reversion of the patched `deepmerge` under
  `cmd/kh-app/frontend/vendor/deepmerge`.

## Out of scope

- Testing an API you do not own or have permission to test. The loopback guard
  catches accidents; it is not an authorisation system.
- Bugs in the target API you point kilhook at.
- Anything that needs you to deliberately pass `--allow-nonlocal`, `--insecure`
  or `--update-baseline`.

## Supported versions

Fixes go into `main` and the next published version. The version string lives in
`internal/report/model.go` and the Windows build metadata.
