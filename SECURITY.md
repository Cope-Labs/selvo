# Security Policy

## Supported Versions

Only the latest version on PyPI is actively maintained. Security fixes are not
backported to older minor versions.

| Version | Supported |
|---|---|
| 0.1.x (current) | ✅ |
| < 0.1.x | ❌ |

## Reporting a Vulnerability

**Do not file public GitHub issues for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://github.com/Cope-Labs/selvo/security/advisories/new)
to submit a report confidentially. You can also reach the maintainer directly via
the email address in `pyproject.toml`.

### What to include

- A concise description of the vulnerability and the affected component
- Steps to reproduce (minimal proof-of-concept is ideal)
- The impact you believe this has (data exposure, privilege escalation, RCE, etc.)
- Your name / handle for the acknowledgement section (optional)

### Response timeline

| Stage | Target SLA |
|---|---|
| Acknowledge receipt | 48 hours |
| Confirm / triage | 7 days |
| Patch released | 14 days for critical, 30 days for high |
| Public disclosure | After patch release, coordinated with reporter |

We practise responsible disclosure and will work with you to coordinate the
timing of any public write-up or CVE assignment.

## Scope

The following surfaces are in scope:

- The `selvo` CLI (all subcommands)
- The FastAPI REST server (`selvo api`, `selvo/api/`)
- The MCP server (`selvo/mcp_server.py`)
- The scoring / policy engine (`selvo/prioritizer/`, `selvo/analysis/policy.py`)
- Authentication / API-key handling (`selvo/api/auth.py`)
- Supply-chain of the published PyPI package itself

Out of scope:

- Vulnerabilities in third-party packages that `selvo` reports on (that is the
  tool's input, not its output)
- Theoretical attacks requiring physical access to the host
- Findings in code paths that are clearly marked experimental or `# TODO`

## Disclosure Policy

selvo is licensed under the **Elastic License 2.0 (ELv2)** and is maintained
by a solo operator. We do not yet have a formal bug-bounty programme, but
significant findings will be acknowledged publicly in the release notes and,
where appropriate, a CVE will be requested on the reporter's behalf.
