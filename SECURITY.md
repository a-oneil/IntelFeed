# Security Policy

IntelFeed is a threat intelligence platform, which makes it a slightly awkward
thing to have a vulnerability in. Reports are welcome and will be taken
seriously.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting instead:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the version or commit you saw it on, and how to
   reproduce it.

That opens a private advisory visible only to the maintainers. If private
reporting is unavailable to you for any reason, open a public issue containing
*only* "requesting a security contact" and nothing about the vulnerability
itself, and you will be pointed somewhere private.

### What to expect

- An acknowledgement within a few days.
- An assessment of severity and affected versions, shared with you.
- A fix and a published advisory once one is available, crediting you unless
  you would rather stay anonymous.

This is a self-hosted project maintained in spare time — there is no bug bounty
and no guaranteed remediation window.

### What's in scope

The application itself: the FastAPI backend, the React frontend, the Celery
workers, the shipped Docker images and compose files, and the default
configuration they produce.

Out of scope:

- Findings that require an attacker to already be an authenticated admin. Admins
  can edit AI prompts, automation rules and system settings by design.
- Vulnerabilities in a dependency with no IntelFeed-specific exploit path —
  report those upstream. `.github/workflows/security.yml` audits dependencies
  weekly and Dependabot opens the upgrade PRs.
- Anything about a deployment's own configuration: a missing reverse proxy, an
  exposed PostgreSQL port, a weak `SECRET_KEY`, a Meilisearch instance left
  open. See [setup.md](setup.md) for the intended production setup.
- Missing rate limits or security headers *without* a demonstrated impact.
- Denial of service by volume.

## Reporting a normal bug

Anything that isn't a vulnerability — a crash, a feed that won't parse, a
detection rule that renders wrong, a UI glitch — belongs in a regular
[GitHub issue](../../issues). Please include:

- What you expected and what happened instead.
- The commit or release you're running, and whether it's the Docker stack or a
  local install.
- Relevant logs: `docker compose -f docker-compose.dev.yml logs api --tail 100`
  (redact anything sensitive, including feed API keys).

Feature requests and questions are also fine as issues.

## Supported versions

The `main` branch only. There are no maintained release branches: fixes land on
`main` and self-hosted installs pick them up via `update.sh`.

## Running the security checks yourself

The same gates CI applies, on your own checkout:

```bash
# Committed secrets
gitleaks dir . --config .gitleaks.toml --redact

# Backend dependency advisories
pip-audit -r <(cd backend && pip freeze | grep -v '^-e ')

# Frontend dependency advisories, shipped tree only
cd frontend && pnpm audit --prod --audit-level=high
```
