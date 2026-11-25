## Change

## Why

## Checks
- [ ] `pwsh -File scripts/verify.ps1` passes locally
- [ ] `scripts/smoke.ps1` if HTTP, fuzz, spec or diff code changed
- [ ] Regression test with the fix
- [ ] `CHANGELOG.md` entry for anything a user would notice

There is no CI here. Run the gate before asking for review.

## Compatibility
- [ ] No breaking change to `format: 1`
- [ ] New report fields go through `internal/engine/redact.go`
