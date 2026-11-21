---
name: Bug report
about: Something does not work as documented
title: ''
labels: bug
assignees: ''
---

## What broke

## What you expected

## How to reproduce
1.
2.
3.

## Files
Attach the `.kh` file and spec if you can. Remove real tokens first; the
redactor in `internal/engine/redact.go` protects report fields, not files you
attach to an issue.

## Environment
- kilhook version (title bar or report footer):
- Windows version:

## Before opening this
Run `pwsh -File scripts/verify.ps1`. If it fails, paste the output.
