# Changelog

The full, phase-by-phase changelog lives in [project.md](project.md) at the top
of the document. User-visible changes are recorded there with each version.

## 0.1.0 — in development

Deep pre-open-source review (plan version v1.22): closed 32 findings. Highlights:
credential redaction now covers text diffs, NDJSON/malformed/multipart bodies,
fuzz evidence and spec violations; case-variant header fuzz targets mutate the
real header; body fuzzing keeps large JSON integers intact; lowercase `2xx`
status classes win over `default`; the desktop unsafe-method confirmation can no
longer be bypassed by saving a method change; Save & Run stops on a failed save;
rate-limit minimums are enforced everywhere; JSON trailing data is detected
strictly; and the content-hash gate covers all build inputs.

Open-source readiness hardening (plan version v1.21):

- The desktop workspace guard now shares the engine's symlink-resolving
  confinement, so a junction/symlink inside a workspace cannot escape it.
- Fuzz cancellation observed after all jobs are queued is reported as aborted
  (exit 2) rather than as `max_requests` skips.
- The non-localhost guard now skips only the fuzz pass, with a warning and an
  incomplete verdict, preserving the baseline, contract and diff report.
- Per-host concurrency now reaches the cached HTTP transport's connection pool.
- The verify gate uses a frontend content hash instead of file timestamps, so a
  fresh clone cannot fail spuriously.
- Added MIT license (copyright Two Four Bit Systech India Private Limited),
  AUTHORS, contributing, security and code-of-conduct documents, and an expanded
  `.gitignore`. kilhook is made by 24Bit System — www.24bitsystem.com.
