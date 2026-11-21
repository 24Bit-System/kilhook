---
name: Bug report
about: Report something that does not work as documented
title: ''
labels: bug
assignees: ''
---

## What happened

## What you expected

## Steps to reproduce
1.
2.
3.

## Reproducer
If possible, attach the `.kh` file and the OpenAPI spec (redact any credentials
first — see the redaction rules in `internal/engine/redact.go`). A minimal file
that reproduces the problem is worth more than a description.

## Environment
- kilhook version (shown in the title bar / report footer):
- Windows version:
- Go version (if built from source):
- Frontend bundle built from current sources (run `pwsh -File scripts/verify.ps1`):

## Output
Paste the terminal report or attach the exported HTML. `pwsh -File scripts/verify.ps1`
must be green before a bug is triaged as a code defect.
