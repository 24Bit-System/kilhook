## What changed

## Why
Link the issue if there is one.

## Gate
- [ ] `pwsh -File scripts/verify.ps1` is green (vet, race tests, lint, tidy,
      govulncheck, dependency rule, 80% coverage, frontend hash, svelte-check,
      Vitest)
- [ ] `scripts/smoke.ps1` was run if the HTTP/fuzz/spec/diff path changed
- [ ] Regression test added for the fix
- [ ] `project.md` changelog updated for user-visible changes
- [ ] No credential or personal path in the diff

There is no CI service. The local gate above is the only thing between a
change and a release — a skipped run is a failed review.

## Format / compatibility
- [ ] No `format: 1` breaking change (those require `format: 2` and a migration)
- [ ] Report fields that could carry secrets go through `internal/engine/redact.go`
