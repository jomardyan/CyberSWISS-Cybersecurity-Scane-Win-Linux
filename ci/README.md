# `ci/` — Pipeline Inputs

This directory holds inputs consumed by the CI pipeline. The workflow itself
lives at [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), which is
where GitHub Actions looks for it.

## `ci/baseline.json` (optional)

The accepted-risk baseline for the `baseline-gate` job. When present, findings
waived in it no longer fail the build, so the gate only breaks on genuinely new
risk. It is not committed by default — create it once the current findings have
been reviewed and signed off:

```bash
python3 common/runner.py --os linux --write-baseline ci/baseline.json
```

Then edit each entry to record the real justification, an owner, and an expiry
date before committing. See
[Baselines & Accepted Risk](../README.md#baselines--accepted-risk) for the file
format and matching rules.
