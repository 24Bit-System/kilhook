# Changelog

The full history, including the phase-by-phase entries, is at the top of
[project.md](project.md).

## v0.1.0 — first public source release

One `.kh` file goes through send, OpenAPI response validation, fuzzing, baseline
diff and one report. `kh-cli` and the Wails window call the same
`internal/engine` package.

Work done before publishing:

- Closed 32 findings from a full code review. The serious ones were credentials
  leaking through text diffs and fuzz evidence, NDJSON bodies skipping the
  redactor, case-variant header targets never reaching the wire, and a saved
  method change skipping the unsafe-method confirmation in the window.
- Added the MIT license, AUTHORS, CONTRIBUTING, SECURITY and code of conduct.
  The copyright is held by Two Four Bit Systech India Private Limited.
- Added issue and PR templates, and a content-hash check that survives a fresh
  clone.
- Changed the Go module to `github.com/24Bit-System/kilhook`.
- Ran an internal security pass over the whole app. Credential redaction now
  covers text diffs, NDJSON/form/multipart bodies, fuzz evidence and spec
  violations; env-file reads are capped; `Discover` refuses symlinks that leave
  the workspace. Details and residual risks are in `docs/security-review.md`.
  This is not an independent audit.
