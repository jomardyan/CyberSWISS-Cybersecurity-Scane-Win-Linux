# Security Policy

CyberSWISS is a defensive security tool. It performs read-only audit checks by default
and only changes a system when an operator passes `--fix` / `-Fix` explicitly.

## Supported Versions

Security fixes land on the `main` branch. There is no long-term support branch — please
run the latest `main` before reporting an issue.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Older tags / forks | ❌ |

## Reporting a Vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through GitHub:

1. Go to the [Security tab](https://github.com/jomardyan/CyberSWISS-Cybersecurity-Scan-Win-Linux/security)
2. Choose **Report a vulnerability**
3. Describe the issue, the affected script or module, and how to reproduce it

You should get an acknowledgement within a few days. Once a fix is available it will be
released on `main` and credited in the advisory unless you ask otherwise.

> Maintainers: private vulnerability reporting is enabled under
> *Settings → Code security and analysis → Private vulnerability reporting*.

## What Counts as a Vulnerability Here

Because CyberSWISS runs with elevated privileges on the hosts it audits, the following
are in scope:

- **Command injection** in any audit script — a hostname, path, package name, or scan
  target that reaches a shell without proper quoting
- **Privilege escalation** — a `--fix` action that widens permissions, weakens a
  control, or creates a writable path owned by a lower-privileged user
- **Secret disclosure** — any finding, report, log line, or database row that records a
  credential, token, key, or password. The project's stated contract is that all output
  is safe to forward to a SIEM
- **Path traversal or unsafe writes** in report generation, the baseline loader, or the
  scan history database
- **REST API issues** — the server in `common/api.py` binds `0.0.0.0:8080` by default and
  ships **no authentication by design**. Exposure of an unauthenticated instance is an
  operator configuration problem, not a vulnerability; a request that escapes the
  documented endpoints or reads files outside the reports directory is a vulnerability

## Out of Scope

- Findings produced *about* your systems — those are audit results, not tool bugs
- Running the REST API on an untrusted network without a reverse proxy or firewall
  (see the deployment note below)
- Missing hardening on a machine you scanned
- Vulnerabilities in optional third-party scanners the scripts shell out to
  (nmap, nikto, OpenVAS, Bandit, Semgrep, …) — report those upstream

## Operational Guidance

- Run audits only against systems you are **explicitly authorized** to assess
- Treat generated reports as sensitive: they enumerate weaknesses in detail. Store them
  access-controlled and prune the scan history (`make db-prune`) on a schedule
- Bind the REST API to `127.0.0.1` (`python3 common/api.py --host 127.0.0.1`) or place it
  behind an authenticating reverse proxy. Never expose it to the internet
- Review `--fix` behaviour in a staging environment before running it in production;
  destructive operations carry an abort window but are still changes to a live system
