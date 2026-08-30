# Contributing to CyberSWISS

Thanks for considering a contribution. CyberSWISS is a defensive security audit platform
for Linux and Windows — contributions that add checks, improve remediation guidance, or
harden the orchestrator are all welcome.

For significant changes, open an issue first so the approach can be discussed before you
write code.

---

## Ground Rules

CyberSWISS is **defensive only**. Contributions must not add offensive capability:
no exploitation, no lateral movement, no credential harvesting, no evasion beyond the
existing `--delay` rate limiting. Detection, validation, inventory, and configuration
review are in scope; anything that attacks a third party is not.

Two more rules that are never negotiable:

1. **Read-only by default.** A script must make no change to the system unless the
   operator passes `--fix` / `-Fix`.
2. **No secrets in output.** Findings, logs, reports, and the history database must be
   safe to forward to a SIEM. Never emit a credential, token, key, or password — not
   even a partial one.

---

## Development Setup

```bash
git clone https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scan-Win-Linux.git
cd CyberSWISS-Cybersecurity-Scan-Win-Linux

pip install -r requirements.txt   # dev toolchain: pytest, flake8, pylint, black, isort
make check-env                    # verify the environment
```

The platform itself has **no third-party Python runtime dependencies** — everything is
standard library, so the scanner runs on a bare Python install.

## The Gate

Run this before opening a pull request:

```bash
make ci          # lint (flake8 + shellcheck + pylint) → tests → dry-run scan
```

Or the individual steps:

```bash
make lint        # flake8 + shellcheck + pylint
make test        # full pytest suite
make format      # black + isort
```

CI enforces the same gate: flake8 must pass (rules live in `.flake8`), pylint must score
at least 8.0, shellcheck must pass on every `linux/*.sh`, and the full test suite must
be green.

---

## Adding a New Audit Script

Scripts are numbered and paired across platforms where the check makes sense on both.

1. **Pick the next free ID** — `L##` for Linux (`linux/L34_your_check.sh`), `W##` for
   Windows (`windows/W34_Your_Check.ps1`). Use a descriptive snake_case name.

2. **Copy the header block** from an existing script. The orchestrator parses it, and
   the `Category` line is what `--tags` / `make scan-tag` filters on:

   ```bash
   # ID       : L34
   # Category : Network Exposure
   # Severity : High
   # OS       : Debian/Ubuntu, RHEL/CentOS/Fedora, SLES
   # Admin    : Yes
   # Language : Bash
   ```

3. **Implement the flag contract.** Every script must accept `--json` / `-Json` and
   `--fix` / `-Fix`, and must be read-only without the latter.

4. **Emit the finding contract** in JSON mode — each finding needs `id`, `name`,
   `severity` (`Info` / `Low` / `Med` / `High` / `Critical`), `status`
   (`PASS` / `FAIL` / `WARN` / `INFO`), `detail`, and `remediation`.

5. **Use the canonical exit codes**: `0` all passed, `1` at least one WARN, `2` at least
   one FAIL.

6. **Document it** in [`docs/CATALOG.md`](docs/CATALOG.md), add remediation steps to
   [`docs/REMEDIATION_GUIDE.md`](docs/REMEDIATION_GUIDE.md), list any new OS-level tool
   in [`docs/RUNTIME_REQUIREMENTS.md`](docs/RUNTIME_REQUIREMENTS.md), and add the row to
   the script catalog in the README.

7. **Add tests** under `tests/`.

A new script is complete when `make ci` passes and
`python3 common/runner.py --scripts L34 --json` emits a valid report.

---

## Changing the Orchestrator

`common/` is plain-standard-library Python. Keep it that way — adding a third-party
runtime dependency needs a discussion first.

| Module | Responsibility |
|---|---|
| `runner.py` | CLI orchestration, execution, terminal rendering |
| `report_generator.py` | HTML, CSV, text, SARIF, Markdown output |
| `db.py` | Scan history, drift detection, trend analytics, retention |
| `baseline.py` | Accepted-risk waivers |
| `api.py` | REST API server |
| `utils.py` | Script discovery, execution, shared helpers |
| `gui.py` | Tkinter operator console |

Report rendering belongs in `report_generator.py` — the runner, API, and GUI all import
from it rather than formatting output themselves.

---

## Pull Requests

- Branch from `main`
- Keep the change focused; unrelated cleanups belong in their own PR
- Describe what you changed, which checks are affected, and how you verified it
- Include evidence that `make ci` passes
- Update the docs in the same PR as the code

---

## Reporting Bugs and Vulnerabilities

Use the [issue templates](https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scan-Win-Linux/issues/new/choose)
for bugs, false positives, and feature requests.

**Security vulnerabilities go through private reporting, not public issues** — see
[SECURITY.md](SECURITY.md).
