# Security policy

kilhook runs entirely on your machine. It sends only the HTTP requests you
author, collects no telemetry, and has no server. Its security surface is
therefore mostly local: parsing untrusted `.kh` files, specs and responses,
confining file writes to a workspace, and keeping fuzzing from becoming an
attack against a host you did not intend to test.

## Reporting a vulnerability

Report vulnerabilities privately to **[info@24bitsystem.com](mailto:info@24bitsystem.com)**,
or use GitHub's private advisory form at
[github.com/24Bit-System/kilhook/security/advisories/new](https://github.com/24Bit-System/kilhook/security/advisories/new).
Do **not** open a public issue for an unfixed vulnerability. kilhook is
maintained by 24Bit System — see [www.24bitsystem.com](https://www.24bitsystem.com).

Include: affected version, a minimal reproducer (a `.kh` file and/or spec),
the impact you believe it has, and whether you have already told anyone else.

Please allow time for a fix before disclosing publicly. We will acknowledge the
report, confirm or reject it with reasoning, and coordinate a release.

## In scope

- Workspace escape: a path from a shared `.kh` file (spec source, baseline,
  wordlist) resolving outside the registered workspace, including via
  symlinks/junctions.
- Loopback-guard or redirect-guard bypass that lets a fuzz request reach a
  non-local host without `--allow-nonlocal` / typed UI confirmation.
- Credential leakage into reports or exported HTML.
- Unbounded reads/allocations from hostile files (oversized `.kh`, spec,
  response, wordlist, baseline) that exhaust memory or hang the app.
- Dependency vulnerabilities; the verify gate runs `govulncheck` and pins
  kin-openapi >= v0.148.0.
- Prototype-pollution in the vendored frontend `deepmerge` patch.

## Out of scope

- Fuzzing a system you are not authorised to test. The safety guard is a
  speed bump for accidents, not an authorisation mechanism.
- Vulnerabilities in the target API you point kilhook at.
- Findings that require the user to intentionally disable a safety feature
  (`--allow-nonlocal`, `--insecure`, `--update-baseline`).

## Supported versions

Security fixes target the latest published release. The current version is
stamped in `internal/report/model.go` and the Windows build metadata.
