# Security Policy

SSLCrtSrv handles TLS private keys and certificate issuance for every client host it manages, so a vulnerability here can have an outsized impact compared to a typical application bug. Security reports are taken seriously and prioritized accordingly.

## Supported Versions

This project doesn't maintain parallel release branches - it's a single, rolling line of 0.x releases. Only the most recently published release receives security fixes. If you're reporting an issue, please confirm it still reproduces against the latest release (see `debian/changelog`, or `sslcrtsrv.__version__`) first.

| Version        | Supported |
| -------------- | --------- |
| Latest release | ✅         |
| Anything older | ❌         |

## Reporting a Vulnerability

Please email **sslcrtsrv AT mlfwd.de** rather than opening a public issue. Include, as far as you're able to:

- A description of the issue and its potential impact
- The affected version or commit
- Steps to reproduce, or a proof of concept
- Whether and when you're planning to disclose publicly

This project is maintained by a single developer, not a dedicated security team - please allow a few business days for an initial response. There's no bug bounty program, but reporters are credited by name (or handle, or anonymously - your choice) in the fix's changelog entry.

No PGP key is published at the moment. If a report needs to stay confidential ahead of a fix, say so in your first email and that can be worked out directly.

## Scope

**In scope:**
- The client/server protocol and its cryptography (`src/sslcrtsrv/common/`)
- The ACME server implementation (RFC 8555 conformance, account/order/challenge handling)
- Certificate and private-key storage, including at-rest encryption
- Access control: client registration, trust grants, and permission checks
- The Debian packaging's default file ownership/permissions and service configuration

**Out of scope:**
- Anything under `web_admin/` - the optional web admin UI isn't included in this public release (not yet considered functional; see `Manual.MD`)
- Vulnerabilities in third-party dependencies (`cryptography`, `sqlalchemy`, `acme.sh`, etc.) - please report those to the upstream project directly, though a heads-up here is still welcome so this project can track its exposure
- Issues that require an attacker to already have root (or equivalent) access on the server or a client host
- Gaps covered by `Manual.MD`'s documented deployment responsibilities (e.g. host firewalling, OS patching, physical access to the server)

## Disclosure

Coordinated disclosure is appreciated: please allow a reasonable window to investigate and ship a fix before any public write-up. There's no fixed embargo period required - a good-faith conversation about timeline is enough.
