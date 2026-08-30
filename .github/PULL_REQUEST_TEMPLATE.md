## Summary

<!-- What does this change and why? -->

## Type of change

- [ ] New audit check (`L##` / `W##`)
- [ ] Fix to an existing check (false positive / false negative / severity)
- [ ] Orchestrator, reporting, history, baseline, API, or GUI change
- [ ] Documentation
- [ ] CI / tooling

## Checks affected

<!-- Script IDs, e.g. L07, W16. Write "none" for changes outside linux/ and windows/. -->

## Verification

```
# Paste the output of `make ci`, or the commands you ran.
```

- [ ] `make ci` passes (lint → tests → dry-run scan)
- [ ] Tests added or updated for the behaviour this changes
- [ ] Documentation updated in this PR (`docs/CATALOG.md`, `docs/REMEDIATION_GUIDE.md`,
      `docs/RUNTIME_REQUIREMENTS.md`, README) where applicable

## Project contract

- [ ] The change is **defensive only** — no offensive capability added
- [ ] Any new script is **read-only** unless `--fix` / `-Fix` is passed
- [ ] No credentials, tokens, keys, or PII appear in findings, logs, reports, or the
      history database
- [ ] New scripts emit `id`, `name`, `severity`, `status`, `detail`, and `remediation`
      in `--json` mode, and use exit codes `0` / `1` / `2`
