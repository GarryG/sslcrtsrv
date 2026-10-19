
# SSLCrtSrv Manual

*Version: 0.9.8 / Last Update: 2026-10-19* 

SSLCrtSrv is a self-hosted client/server system for centrally requesting, issuing, and securely distributing TLS certificates - via ACME DNS-01 automation or manual upload - to any number of registered client hosts. One administrator, and one server, replace per-host manual certificate handling across an entire fleet.

## Table of Contents

- [1. Introduction](#1-introduction)
  - [1.1. Overview and Goals](#11-overview-and-goals)
  - [1.2. Key Features](#12-key-features)
  - [1.3. System Components at a Glance](#13-system-components-at-a-glance)
  - [1.4. Terminology and Glossary](#14-terminology-and-glossary)
  - (1.5. Comparison with Alternative Approaches - moved to `TECHNICAL_REFERENCE.md` Section 1)

- [2. Requirements](#2-requirements)
  - [2.1. Supported Operating Systems](#21-supported-operating-systems)
  - [2.2. Python Version and Runtime Dependencies](#22-python-version-and-runtime-dependencies)
  - [2.3. External Tools](#23-external-tools)
    - [2.3.1. acme.sh](#231-acmesh)
    - [2.3.2. dig / dnsutils](#232-dig-dnsutils)
    - [2.3.3. DNS Backend (e.g. PowerDNS)](#233-dns-backend-eg-powerdns)
  - [2.4. Server Host Requirements](#24-server-host-requirements)
  - [2.5. Client Host Requirements](#25-client-host-requirements)
  - [2.6. Optional Components](#26-optional-components)
    - [2.6.1. systemd](#261-systemd)

- [3. Architecture and Technical Design](#3-architecture-and-technical-design) (moved to `TECHNICAL_REFERENCE.md` Section 2)

- [4. Installation and Deployment](#4-installation-and-deployment)
  - [4.1. Debian Packages](#41-debian-packages)
    - [4.1.1. sslcrtsrv-server](#411-sslcrtsrv-server)
    - [4.1.2. sslcrtsrv-client](#412-sslcrtsrv-client)
  - [4.2. Generic (Distribution-Agnostic) Tarballs](#42-generic-distribution-agnostic-tarballs)
  - [4.3. Initial Setup Walkthrough](#43-initial-setup-walkthrough)
    - [4.3.1. Server Initialization](#431-server-initialization)
    - [4.3.2. Client Initialization and Registration](#432-client-initialization-and-registration)
  - [4.4. systemd Service Management](#44-systemd-service-management)
  - [4.5. Upgrading](#45-upgrading)
  - [4.6. ACME Server Setup and Reverse Proxy](#46-acme-server-setup-and-reverse-proxy)
  - [4.7. RPM Packages](#47-rpm-packages)

- [5. Configuration Reference](#5-configuration-reference)
  - [5.1. Server Configuration (server_config.json)](#51-server-configuration-server_configjson)
  - [5.2. Client Configuration (client_config.json)](#52-client-configuration-client_configjson)
  - [5.3. Certificate Request Configuration (crtrequest_config.json)](#53-certificate-request-configuration-crtrequest_configjson)
  - [5.4. Configuration File Locations Summary](#54-configuration-file-locations-summary)

- [6. Tool and Script Reference](#6-tool-and-script-reference)
  - [6.1. server.py (scs-server)](#61-serverpy-scs-server)
  - [6.2. client.py (scs-client)](#62-clientpy-scs-client)
  - [6.3. crtmanager.py (scs-crtmanager)](#63-crtmanagerpy-scs-crtmanager)
  - [6.4. cltmanager.py (scs-cltmanager)](#64-cltmanagerpy-scs-cltmanager)
  - [6.5. crtrequest.py (scs-crtrequest)](#65-crtrequestpy-scs-crtrequest)
  - [6.6. admintui (scs-admintui)](#66-admintui-scs-admintui)
  - [6.7. build-tarballs.py](#67-build-tarballspy)
  - [6.8. dbmigrate.py (scs-dbmigrate)](#68-dbmigratepy-scs-dbmigrate)
  - [6.9. acme_server.py (scs-acme-server)](#69-acme_serverpy-scs-acme-server)

- [7. admintui Dashboard Guide](#7-admintui-dashboard-guide)
  - [7.1. Navigation, Layout, and Keybindings](#71-navigation-layout-and-keybindings)
  - [7.2. Onboarding Tab](#72-onboarding-tab)
  - [7.3. Certificates Tab](#73-certificates-tab)
  - [7.4. Requests Tab](#74-requests-tab)
  - [7.5. Clients Tab](#75-clients-tab)
  - [7.6. Config Tab](#76-config-tab)
  - [7.7. Maintenance Tab](#77-maintenance-tab)
  - [7.8. Notifiers Tab](#78-notifiers-tab)

- [8. Data Storage Reference](#8-data-storage-reference)
  - [8.1. Directory Layout](#81-directory-layout)
    - [8.1.1. /etc/sslcrtsrv](#811-etcsslcrtsrv)
    - [8.1.2. /opt/sslcrtsrv](#812-optsslcrtsrv)
    - [8.1.3. Per-Certificate acme.sh Working Directories](#813-per-certificate-acmesh-working-directories)
  - [8.2. Database Schema](#82-database-schema) (moved to `TECHNICAL_REFERENCE.md` Section 3)

- [9. Administration Workflows](#9-administration-workflows)
  - [9.1. Onboarding a New Client](#91-onboarding-a-new-client)
  - [9.2. Requesting and Approving Certificates](#92-requesting-and-approving-certificates)
  - [9.3. Renewing Certificates](#93-renewing-certificates)
  - [9.4. Diagnosing and Resolving DNS/Issuance Failures](#94-diagnosing-and-resolving-dnsissuance-failures)
  - [9.5. Rotating the Registration Secret](#95-rotating-the-registration-secret)
  - [9.6. Rotating DNS Provider Tokens](#96-rotating-dns-provider-tokens)
  - [9.7. Manually Adding or Updating Certificates](#97-manually-adding-or-updating-certificates)
  - [9.8. Deleting Certificates and Clients](#98-deleting-certificates-and-clients)
  - [9.9. Distributing and Updating the Client Package](#99-distributing-and-updating-the-client-package)
  - [9.10. Managing ACME Accounts and Orders](#910-managing-acme-accounts-and-orders)
  - [9.11. Trusted-Client Auto-Approval (Skipping Manual Confirm/Assign)](#911-trusted-client-auto-approval-skipping-manual-confirmassign)
  - [9.12. Device-Specific ACME Client Configuration Examples](#912-device-specific-acme-client-configuration-examples)
    - [9.12.1. acme.sh](#9121-acmesh)
    - [9.12.2. FortiGate (FortiOS up to 7.4)](#9122-fortigate-fortios-up-to-74)
  - [9.13. Netblock Access Control](#913-netblock-access-control)
  - [9.14. systemd Hardening](#914-systemd-hardening)

- [10. Notifications](#10-notifications)
  - [10.1. Email Notifications](#101-email-notifications)
  - [10.2. Multiple Named Notifiers](#102-multiple-named-notifiers)
    - [10.2.1. Example: One of Each Type](#1021-example-one-of-each-type)
    - [10.2.2. Example: Slack, Discord, Telegram, and More, via `webhook`](#1022-example-slack-discord-telegram-and-more-via-webhook)
  - [10.3. Event Routing](#103-event-routing)
    - [10.3.1. `client.py`: How Notifications Are Captured](#1031-clientpy-how-notifications-are-captured)
  - [10.4. Testing a Notifier](#104-testing-a-notifier)
  - [10.5. admintui's Notifiers Tab Test Button](#105-admintuis-notifiers-tab-test-button)
  - [10.6. Logging](#106-logging)
  - [10.7. Notification Rate Limiting](#107-notification-rate-limiting)
    - [10.7.1. Example](#1071-example)

- [11. Troubleshooting](#11-troubleshooting)
  - [11.1. Common Error Messages](#111-common-error-messages)
  - [11.2. Diagnosing DNS and ACME Failures](#112-diagnosing-dns-and-acme-failures)
  - [11.3. Diagnosing Connectivity Issues](#113-diagnosing-connectivity-issues)
  - [11.4. Logs and Debug Options](#114-logs-and-debug-options)
  - [11.5. ACME Server-Specific Troubleshooting](#115-acme-server-specific-troubleshooting)

- [12. Appendices](#12-appendices)
  - [A. Command-Line Quick Reference](#a-command-line-quick-reference)
  - [B. Exit Codes](#b-exit-codes)
  - [C. Status Codes and Constants Glossary](#c-status-codes-and-constants-glossary) (moved to `TECHNICAL_REFERENCE.md` Section 4)
  - [D. Changelog / Version History](#d-changelog-version-history)

---

## 1. Introduction

### 1.1. Overview and Goals

The push to shorten maximum public TLS certificate lifetimes - down to 47 days by 2029 under the CA/Browser Forum's schedule - turns certificate renewal from an annual chore into something that has to be fully automated to remain practical at all. The ACME protocol (as used by Let's Encrypt and other CAs) automates issuance itself, but its two challenge types each assume something that isn't always true: HTTP-01 requires the certificate's own host to be reachable from the Internet and able to serve plain HTTP, which rules out plenty of internal or non-web hosts (mail servers, internal appliances, firewalls); DNS-01 requires whoever's requesting the certificate to be able to insert a TXT record into the domain's authoritative DNS, which is often not the same party, or the same system, as the host that will actually use the certificate. Also, providers may chose not to make direct API access available due to security concerns.

SSLCrtSrv exists to close that gap for organizations managing certificates across more than a handful of hosts, or across hosts they don't fully control - the canonical case being an ISP or hosting provider that resells certificates to customers, and needs a way to hand out (and keep renewing) certificates for many customer domains without giving every customer host direct access to a shared ACME account or DNS credentials.

Its goals, in order of how directly they address that problem:

- **Central certificate management** - one inventory of certificates, whether they were issued via ACME or uploaded manually, with one place to see what's valid, what's expiring, and what's still pending.
- **Central, per-client authorization** - a certificate (or a set of FQDNs) is only ever handed to a client host the administrator has explicitly authorized for it, and one client can be authorized for several independent multi-domain certificates.
- **Authenticated, encrypted distribution** - a client host never needs direct DNS-provider or ACME-account credentials; it only needs a registered, authenticated relationship with the SSLCrtSrv server, over a protocol that signs and encrypts every message end-to-end.
- **Automatic renewal** - once a certificate is set up, SSLCrtSrv keeps it renewed as it approaches expiry without further manual intervention.

### 1.2. Key Features

- Central inventory of certificates - manually uploaded and ACME-issued certificates live side by side in one database, both manageable through the same tools.
- Per-client, per-FQDNs-set authorization: an administrator explicitly grants which client hosts may retrieve which certificate, and a client may be authorized for multiple, independent multi-domain certificates. Because this rights model is scoped per client and per certificate (`TECHNICAL_REFERENCE.md`'s Section 3.3), one server can serve any number of independently-administered, mutually distrusting clients side by side - e.g. an ISP's separate customers - each confined to exactly the certificates it's been granted, with no visibility into any other client's certificates or requests (see the multi-tenant discussion in `TECHNICAL_REFERENCE.md`'s Section 1.7).
- Certificates may be assigned to multiple clients, reducing renewal load when a certificate is used over and over again.
- A mutually authenticated, end-to-end encrypted client/server protocol running over a plain TCP socket - every message is signed by its sender and encrypted for its recipient, with no dependency on a separate transport-security layer.
- Automated ACME issuance and renewal via `acme.sh`, using DNS-01 challenges - including a CNAME-delegation scheme (see `TECHNICAL_REFERENCE.md`'s Section 2.5) for organizations whose primary DNS can't accept dynamic updates itself.
- DNS delegation verification, on by default before every issuance/renewal attempt - catches a missing or misconfigured CNAME entry before it causes a renewal to fail.
- At-rest encryption of stored certificate private keys, under a keypair kept entirely separate from the client/server transport keys.
- Config-file live reload: the server watches its own configuration file and restarts itself automatically when it changes, without requiring a manual restart or external supervisor support.
- A full-screen terminal admin dashboard (`admintui`) covering day-to-day certificate and client administration in one place, built on the same underlying functions as the single-purpose CLIs, making those operations more comfortable to do than running through command line options.
- Built-in client self-update: the server can host client install packages (file-agnostic) and the client can check for and install a newer version of itself.
- Packaged both as native Debian packages (with the client and server split into separate installable packages) and as distribution-agnostic tarballs for everything else.
- An optional, standards-based RFC 8555 ACME server interface (`scs-acme-server`, `TECHNICAL_REFERENCE.md`'s Section 2.7) alongside the native protocol - lets third-party ACME clients (certbot, `acme.sh`, appliances with built-in ACME support) request certificates through the same central inventory and admin-approval workflow, with no `client.py` installation needed on that host at all.

### 1.3. System Components at a Glance

| Component | Console command | Role |
|---|---|---|
| `server.py` | `scs-server` | The TCP server: client registration, certificate requests/retrieval, and client-package delivery over HTTP on the same port. |
| `client.py` | `scs-client` | Runs on each client host: registers with the server, requests and retrieves certificates, and can retrieve updates of itself. |
| `crtmanager.py` | `scs-crtmanager` | Server-side CLI for the certificate inventory: list, manually add/update/delete certificates, change ACME provider. |
| `cltmanager.py` | `scs-cltmanager` | Server-side CLI for client administration: confirm registrations, assign/revoke certificate permissions. |
| `crtrequest.py` | `scs-crtrequest` | Server-side automation that drives `acme.sh` for issuance/renewal, plus the DNS delegation checks. |
| `admintui` | `scs-admintui` | Full-screen terminal dashboard wrapping `crtmanager`/`cltmanager`/`crtrequest` in one interface. |
| `acme_server.py` | `scs-acme-server` | Optional, independent RFC 8555 ACME protocol server for third-party ACME clients (`TECHNICAL_REFERENCE.md`'s Section 2.7) - shares the same database as everything above. |

### 1.4. Terminology and Glossary

- **ACME** - Automatic Certificate Management Environment, the protocol Let's Encrypt and other CAs use for automated certificate issuance.
- **DNS-01 challenge** - the ACME challenge type that proves control of a domain via a DNS TXT record, as opposed to HTTP-01's web-server-based proof.
- **CNAME delegation** - this project's technique for satisfying DNS-01 challenges when the domain's primary DNS can't accept dynamic updates: a `CNAME` record delegates the challenge name to a backend DNS server `acme.sh` *can* update (see `TECHNICAL_REFERENCE.md`'s Section 2.5).
- **CHALLENGE_ALIAS** - the delegation target domain, configured once in `crtrequest_config.json`, that every domain's CNAME entry points to.
- **FQDNs (set)** - a comma-separated list of one or more domain names covered by a single certificate (a SAN certificate); used throughout as the identifier for "a certificate."
- **Client ID** - the identifier a client host registers under; defaults to the host's own FQDN or host name.
- **Registration secret** - a shared secret, distributed out-of-band, that a client must prove knowledge of before the server will accept its registration.
- **Relation status** - the state of a client's permission for one FQDNs set: pending/unassigned, or approved/active - see `TECHNICAL_REFERENCE.md`'s Section 3.3.
- **Placeholder certificate** - a `certificates` table row created before an ACME issuance attempt completes, automatically removed if that attempt fails, so it never lingers as a phantom entry.
- **Staging vs. production certificate** - a certificate from the CA's test environment (untrusted by browsers, used to avoid rate limits on production servers while testing) versus a real, trusted one.
- **acme.sh** - the third-party ACME client this project shells out to for the actual certificate issuance/renewal work.
- **Identity keypair vs. DB encryption keypair** - the client's or server's own RSA keypair, used for the network protocol, is a separate, distinct keypair from the one used only to encrypt certificate private keys at rest (see `TECHNICAL_REFERENCE.md`'s Section 2.3).
- **`cert-<ID>` directory** - each certificate's own isolated `acme.sh` working directory, named after its database row ID.
- **ACME account** - a `Client` row with `client_kind='acme'` (`TECHNICAL_REFERENCE.md`'s Section 2.7.3), created by a third-party ACME client's `new-account` call - the ACME-protocol equivalent of a traditional registered client, identified by its RFC 7638 JWK thumbprint instead of a `client_id`/keypair pair.
- **RFC 7638 JWK thumbprint** - a deterministic hash of an ACME account's public key, used as its canonical identity for out-of-band verification before `cltmanager.py acme_confirm` (`TECHNICAL_REFERENCE.md`'s Section 2.7.4 / Section 9.10) - the ACME-protocol equivalent of the traditional protocol's public-key fingerprint (`TECHNICAL_REFERENCE.md`'s Section 2.3.4).

---

## 2. Requirements

### 2.1. Supported Operating Systems

Linux is the only supported and tested target platform, and for the server component specifically, the only one it can run on at all: `server.py`'s configuration-file live-reload feature (`TECHNICAL_REFERENCE.md`'s Section 2.6) uses the Linux `inotify` API directly (via a small `ctypes` wrapper, not a portable library), so `scs-server` will fail to start its file watcher on any non-Linux OS. Two installation paths are currently provided for Linux hosts:

- **Debian/Ubuntu**, via the native `.deb` packages (Section 4.1) - the primary, actively-maintained distribution mechanism, including a `systemd` service unit and dedicated system user setup.
- **Any other Linux distribution**, via the distribution-agnostic tarballs built by `build-tarballs.py` (Section 4.2) - plain Python source plus a `requirements.txt`, no `dpkg`/`rpm` involved.

The client (`client.py`) has no Linux-specific code of its own, and could plausibly run on another POSIX-like system, but this isn't tested or packaged - its default configuration/data paths (`/etc/sslcrtsrv`, `/opt/sslcrtsrv`) and its file-permission model (`chmod`-based, `TECHNICAL_REFERENCE.md`'s Section 2.3.5) both assume a Unix-style filesystem. Windows is not currently supported (anybody wish to help out is welcome ...).

### 2.2. Python Version and Runtime Dependencies

SSLCrtSrv requires **Python 3.9 or newer** (`setup.cfg`'s `python_requires`). Dependencies are split so that a client host never has to install the heavier server-only libraries:

| Package | Required by | Purpose |
|---|---|---|
| `cryptography` | client and server | RSA keypairs, signing, encryption, PEM parsing |
| `rich` | server; **optional** on the client | Formatted console/table output |
| `sqlalchemy` | server only | ORM access to the database (`TECHNICAL_REFERENCE.md`'s Section 3) |
| `alembic` | server only | Schema migrations, used only by `scs-dbmigrate` (Section 6.8) |
| `textual` | server only | `admintui`'s terminal dashboard |
| `pytz` | server only | Timezone handling in certificate validity calculations |
| `PyMySQL` | server only, **optional** | Only needed if the `mysql` database backend is configured (`TECHNICAL_REFERENCE.md`'s Section 3.5) |
| `psycopg2` | server only, **optional** | Only needed if the `postgresql` database backend is configured (`TECHNICAL_REFERENCE.md`'s Section 3.5) |
| `josepy` | server only, **optional** | Only needed to run `scs-acme-server` (`TECHNICAL_REFERENCE.md`'s Section 2.7 / Section 4.6) - JWK/JWS handling for the RFC 8555 protocol. `setup.cfg`'s `acme` extra / Debian's `python3-josepy` `Suggests:`. |
| `maxminddb` | server only, **optional** | Only needed if `geoip_backend` is `"maxmind"` (the default) and `geoip_database_path` is configured (Section 9.13) - reads MaxMind DB (`.mmdb`) files. `setup.cfg`'s `maxmind` extra / Debian's `python3-maxminddb` `Suggests:`. |
| `IP2Location` | server only, **optional** | Only needed if `geoip_backend` is `"ip2location"` and `geoip_database_path` is configured (Section 9.13) - reads IP2Location `.BIN` files. `setup.cfg`'s `ip2location` extra; **no Debian package exists for this one** - install it with `pip` into whatever environment `scs-server`/`scs-acme-server` run in, even on a `.deb` install. |

No external database server is required for the SQLite default - all server-side state lives in a single file, accessed through SQLAlchemy (`TECHNICAL_REFERENCE.md`'s Section 3); MySQL/MariaDB and PostgreSQL are also supported (`TECHNICAL_REFERENCE.md`'s Section 3.5) for deployments that already run one. No minimum version is pinned for `textual` beyond what pip resolves; the admin dashboard's code is deliberately written to also tolerate the older `textual` releases Debian/Ubuntu package (several call sites in `admintui` explicitly work around API differences between old and new `textual` versions), so it's expected to work with either the `python3-textual` Debian package or a newer one from PyPI.

`crtmanager.py`/`cltmanager.py`/`admintui` (all server-side) require `rich` unconditionally. `client.py` is the one exception: it imports `rich` in a `try`/`except` and falls back to plain fixed-width text for its `listcerts`/`info` tables if `rich` isn't installed, so a client host genuinely only needs `cryptography` (Section 2.5) - `rich` there is a nicer-output nicety, not a requirement.

### 2.3. External Tools

#### 2.3.1. acme.sh

[`acme.sh`](https://github.com/acmesh-official/acme.sh) is the third-party ACME client `crtrequest.py` shells out to for actual certificate issuance and renewal. It is **only** needed if you intend to use ACME automation at all - certificates added manually via `crtmanager.py addlocal`/`update` never touch `acme.sh`, and neither does the client/server protocol itself.

`acme.sh` is not packaged for Debian and must be installed separately (it's listed only as a `Recommends:` on the `sslcrtsrv-server` package, not a hard dependency). `crtrequest_config.json`'s `ACME_SH_PATH` setting points at it if it isn't already on `PATH`.

#### 2.3.2. dig / dnsutils

The `dig` command-line tool is needed for `crtrequest.py`'s DNS delegation check (`TECHNICAL_REFERENCE.md`'s Section 2.5.2), which shells out to it to verify DNS delegation - on by default before every issuance/renewal attempt, and also usable standalone via `--check-dns-only`. If `--no-check-dns` is always passed (`TECHNICAL_REFERENCE.md`'s Section 2.5.2), `dig` isn't needed at all. On Debian/Ubuntu it's provided by the `bind9-dnsutils` package (also only a `Recommends:`, not a hard dependency, on `sslcrtsrv-server`).

#### 2.3.3. DNS Backend (e.g. PowerDNS)

If you plan to use ACME DNS-01 automation, you need a DNS server `acme.sh` can update programmatically to satisfy the challenge. `acme.sh` itself ships dozens of DNS provider hooks (Cloudflare, Route53, and many others), but `crtrequest.py` currently wires up and has only ever been tested against exactly one of them: **PowerDNS** (or something exposing a compatible HTTP API) - it hardcodes `acme.sh`'s `dns_pdns` hook (`--dns dns_pdns`) and expects `crtrequest_config.json`'s `DNS_PROVIDER_CONFIG` to supply exactly `PDNS_Url`, `PDNS_ServerId`, and `PDNS_Token` as the corresponding environment variables. This is a current implementation/testing limitation, not an architectural one - wiring up a different `acme.sh` hook would mean making the hook name and its expected environment variables configurable instead of the hardcoded `dns_pdns`/`PDNS_*` values, a fairly contained code change (`crtrequest.py`'s `request_new_certificate()`) rather than a redesign, but as shipped today, PowerDNS is the only supported and tested option.

This does **not** need to be your domains' actual primary/authoritative DNS server - `TECHNICAL_REFERENCE.md`'s Section 2.5 describes a CNAME-delegation design specifically for organizations whose primary DNS can't accept dynamic updates or is operated at a different organization, where the PowerDNS instance only ever manages a small, dedicated delegated subzone.

### 2.4. Server Host Requirements

- A Linux host (Section 2.1), ideally with `systemd` if you want to use the provided service unit.
- Python 3.9+ with the server dependency set installed (Section 2.2) - handled automatically by the `sslcrtsrv-server` Debian package.
- The `adduser` utility (used once, at package-install time, to create a dedicated `sslcrtsrv` system user/group) - a hard `Depends:` of the Debian package.
- Writable `/etc/sslcrtsrv` and `/opt/sslcrtsrv` (or wherever `--config`/`--datadir`/`--certdir` are pointed instead) - created automatically by `scs-server init`.
- An inbound TCP port (default `5514`) reachable from every client host that will register against this server.
- If using ACME automation: outbound connectivity to the ACME CA's endpoint and to the DNS backend's API (Section 2.3.3).
- If running `scs-acme-server` (`TECHNICAL_REFERENCE.md`'s Section 2.7 / Section 4.6): a TLS-terminating reverse proxy in front of it, reachable by whichever third-party ACME clients will use it, and the `python3-josepy` package installed.
- If using GeoIP access control (Section 9.13): the `python3-maxminddb` package installed (or `IP2Location` via `pip`, if using that backend instead), and a GeoIP database file you provide yourself - neither is bundled.
- If using admin notifications (Section 10): outbound connectivity to whatever each configured notifier actually talks to - an SMTP server for `email`, or HTTPS to the relevant API for anything else (`webhook` and everything built on it, Pushover, Pushsafer, Gotify, ntfy).
- **Syslog logging (Section 10.6)** works out of the box with no extra requirements - if nothing is configured, it just needs a local syslog daemon listening on `/dev/log` (already true on effectively every mainstream Linux distribution/init system); if `syslog_host` is set, outbound UDP connectivity to that host/port instead. Neither is required - a host with no local syslog daemon at all (e.g. some minimal containers) still starts and runs normally, falling back to console-only logging with one warning.

### 2.5. Client Host Requirements

- Python 3.9+ with `cryptography` installed (Section 2.2) - no database engine or terminal-UI library needed. `rich` is optional: install it too for styled `listcerts`/`info` tables, or leave it out for a plain-text fallback.
- Outbound TCP connectivity to the server's host and port.
- A writable location for `client_config.json` and for whatever key/certificate/intermediate file paths are given to `client.py retrieve`.
- If `client_config.json` has a `notifiers`/`notification_routing` entry configured (Section 10.3.1): outbound connectivity to whatever that notifier actually talks to, same as the server-side note in Section 2.4 - this is a completely separate notifier configuration from the server's own, and the client host doesn't otherwise need SMTP/HTTPS access to anything.

Client hosts are intentionally lightweight: there is no local database, no admin dashboard, and no ACME client involved on the client side at all - a client host only ever needs to speak the client/server protocol (`TECHNICAL_REFERENCE.md`'s Section 2.2).

### 2.6. Optional Components

#### 2.6.1. systemd

The `sslcrtsrv-server` Debian package ships a `sslcrtsrv-server.service` unit, but it is **not enabled by default** - it requires `scs-server init` to have already produced a working configuration file first (the unit's `ConditionPathExists` checks for `server_config.json` before it will even attempt to start). Once enabled, `systemd` restarts the service automatically on failure (`Restart=on-failure`, `RestartSec=5`).

`systemd` is a convenience, not a requirement: the configuration-file live-reload feature (`TECHNICAL_REFERENCE.md`'s Section 2.6) already makes `scs-server` restart itself in place when its config file changes, independent of any process supervisor, and `scs-server` can equally well be run directly, or under a different supervisor (e.g. a container runtime's own restart policy), on any Linux host.

---

---

## 3. Architecture and Technical Design

This section - the network protocol wire format, the encryption/security model, the certificate lifecycle internals, the DNS-01 delegation design, and the ACME server's own architecture - has moved to `TECHNICAL_REFERENCE.md` Section 2. It's background material for understanding *how* the system works internally; nothing in the rest of this manual requires reading it first.

---

## 4. Installation and Deployment

### 4.1. Debian Packages

The source tree builds two binary packages from one `dpkg-buildpackage` run - there is no pre-built package repository; building from source (or from a release tarball of this repository) is the distribution mechanism.

To build: from the repository root, with the Build-Depends installed (`debhelper-compat (= 13)`, `dh-python`, `python3-all`, `python3-setuptools`),

```
dpkg-buildpackage -us -uc -b
```

produces `../sslcrtsrv-client_<version>-1_all.deb` and `../sslcrtsrv-server_<version>-1_all.deb`. `debian/rules` refuses to build at all if `debian/changelog`'s version doesn't match `sslcrtsrv.__version__` (`TECHNICAL_REFERENCE.md`'s Section 2.6), so a code version bump and a missing changelog entry can't silently ship together.

#### 4.1.1. sslcrtsrv-server

Depends on `sslcrtsrv-client` (installing it pulls the client package in too, since the server package only ships what's *additional* to the client - see Section 8.1 for exactly which files live in which package), plus `python3-sqlalchemy`, `python3-textual`, `python3-pytz`, `python3-rich`, and `adduser`. `python3-rich` is listed here (not on `sslcrtsrv-client`) because `crtmanager.py`/`cltmanager.py`/`admintui` need it unconditionally, unlike `client.py` (Section 2.2). Recommends (not hard dependencies) `acme.sh` and `bind9-dnsutils` (Section 2.3). Installing it:

- Creates a dedicated `sslcrtsrv` system user and group (`adduser --system --group`).
- Creates `/etc/sslcrtsrv` and `/opt/sslcrtsrv` if they don't already exist, owned `root:sslcrtsrv`, mode `0750`.
- Ships (but does not enable or start) the `sslcrtsrv-server.service` systemd unit (Section 4.4).
- Installs `scs-server`, `scs-crtmanager`, `scs-cltmanager`, `scs-crtrequest`, and `scs-admintui`.

Nothing is usable yet at this point - `scs-server init` (Section 4.3.1) still has to be run once.

#### 4.1.2. sslcrtsrv-client

Depends only on `python3-cryptography` - no database engine, no terminal-UI library. `python3-rich` is a `Recommends:`, not a hard dependency (Section 2.2): `scs-client` falls back to plain-text output for `listcerts`/`info` without it. Installs the `scs-client` console script and the shared `sslcrtsrv`/`sslcrtsrv.common` Python package both packages are built from. Install this alone on any host that only needs to register with a server and retrieve certificates, never `sslcrtsrv-server`.

### 4.2. Generic (Distribution-Agnostic) Tarballs

For any Linux host that isn't Debian/Ubuntu-based (Section 2.1), `build-tarballs.py` (run from the repository root, on any host with the source checked out) produces plain-source archives instead of `.deb` packages:

```
python3 build-tarballs.py [--output-dir DIR]
```

writes `sslcrtsrv-client-<version>-generic.tar.gz` and `sslcrtsrv-server-<version>-generic.tar.gz` into `DIR` (default `dist/`). Everything in each archive is *derived* from the same sources of truth the Debian packaging uses - `debian/*.install` for the file split, `setup.cfg` for dependencies, console-script names, and their target modules, `sslcrtsrv.__version__` for the version - so the two packaging paths can't drift apart from each other. Each archive contains the `sslcrtsrv/` package (importable in place - no install step of its own), a `requirements.txt`, a `bin/` directory of wrapper scripts (see below), and a `USAGE.txt` listing the commands that archive actually ships.

To use one: extract it, create a virtual environment, and install its dependencies -

```
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./bin/scs-server init ...
```

`bin/` holds one small shell wrapper per console command the archive ships (`scs-server`, `scs-client`, `scs-crtmanager`, ... - the same names, and the same behavior, as the equivalent Debian package installs to `/usr/bin`, so a script written against one runs unmodified against the other). Each wrapper resolves its own location, uses `./venv/bin/python3` if a venv was created right alongside it (as in the setup steps above), otherwise falls back to whatever `python3` is on `PATH`, and then runs `python3 -m sslcrtsrv.<module> "$@"` - equivalent to, and a drop-in replacement for, invoking that `-m` form directly. Either add `bin/` to `PATH`, or invoke wrappers by their full/relative path (`./bin/scs-client ...`) - both work identically, from any working directory, since the wrapper computes the archive's own location rather than relying on the caller's `cwd`. There is still no systemd unit, no dedicated system user, and no automatic directory/permission setup here - all of that (`TECHNICAL_REFERENCE.md`'s Section 2.3.5) has to be done by hand if wanted.

### 4.3. Initial Setup Walkthrough

This walkthrough assumes the Debian packages; for a tarball install, every `scs-<name>` command below works unmodified via that archive's `bin/scs-<name>` wrapper (Section 4.2, e.g. `./bin/scs-server init ...` instead of `sudo scs-server init ...` - drop the `sudo` too, unless deliberately running as a matching system user), and create `/etc/sslcrtsrv`/`/opt/sslcrtsrv` (or whatever paths are passed to `--config`/`--datadir`/`--certdir`) yourself first.

#### 4.3.1. Server Initialization

1. **Create the configuration** (as `root`, or a user that already owns `/etc/sslcrtsrv` - see `TECHNICAL_REFERENCE.md`'s Section 2.3.5):

   ```
   sudo scs-server init --registration-secret <secret> \
       [--listen 0.0.0.0] [--port 5514] \
       [--default-acme-provider letsencrypt] \
       [--notifier admin-email:email:notification_recipient=admin@example.com,smtp_host=mail.example.com \
        --notify-on registration:admin-email --notify-on certificate_request:admin-email]
   ```

   Generates the server's identity keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.1) and writes `server_config.json`. If `--registration-secret` is omitted, one is generated and printed once - copy it down immediately, since it is never shown again and has to be distributed to client administrators out-of-band (can be read from the `server_config.json` file of course). Re-running `init` against an existing config file prompts to either overwrite it entirely (new keypair) or update just the given options while keeping the existing keypair and registration secret.

2. **Generate the database-encryption keypair** (one-time, also needed before any certificate can actually be added or issued - `TECHNICAL_REFERENCE.md`'s Section 2.3.3):

   ```
   sudo scs-crtmanager init-db-key
   ```

3. **Start the server** and confirm it comes up cleanly:

   ```
   sudo scs-server
   ```

   (Section 4.4 covers running this under `systemd` instead of in the foreground.)

At this point the server is reachable, but has no clients and no certificates yet.

#### 4.3.2. Client Initialization and Registration

On each host that needs certificates:

1. **Initialize the client**, pointing it at the server:

   ```
   scs-client init --server-host <server-host-or-ip> [--client-id <id>] [--server-port 5514]
   ```

   Generates the client's own identity keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.1) and writes `client_config.json`. `--client-id` defaults to the host's own FQDN if not given.

2. **Register with the server**:

   ```
   scs-client register
   ```

   On success, this prints both the client's and the server's public-key fingerprints. **Write these down or compare them out-of-band before the next step** - this is the one point where a compromised or mistaken registration secret would otherwise go unnoticed (`TECHNICAL_REFERENCE.md`'s Section 2.3.4).

3. **Confirm the registration, on the server side**, after verifying the fingerprints match:

   ```
   sudo scs-cltmanager confirm <client-id>
   ```

   (`scs-cltmanager` with no arguments lists unconfirmed registrations first, if the exact client ID isn't already known.)

The client can now request certificates (`TECHNICAL_REFERENCE.md`'s Section 2.4.2):

```
scs-client request www.example.com,mail.example.com
```

which the server administrator then approves:

```
sudo scs-cltmanager assign <client-id> www.example.com,mail.example.com
```

Once a certificate has actually been issued for that FQDNs set (`TECHNICAL_REFERENCE.md`'s Section 2.4.3), the client retrieves it:

```
scs-client retrieve www.example.com,mail.example.com --key /etc/ssl/private/www.key --cert /etc/ssl/certs/www.crt --exec "systemctl reload nginx"
```

### 4.4. systemd Service Management

```
sudo systemctl enable --now sslcrtsrv-server
```

enables and starts the `sslcrtsrv-server.service` unit shipped by the Debian package (Section 4.1.1) - it will refuse to start at all until `server_config.json` exists (`scs-server init` has been run). `systemctl status sslcrtsrv-server` / `journalctl -u sslcrtsrv-server` show its state and log output; it restarts itself automatically on failure (`Restart=on-failure`, `RestartSec=5`), independent of the config-file live-reload behavior described in `TECHNICAL_REFERENCE.md`'s Section 2.6.

The unit runs as a dedicated, unprivileged `sslcrtsrv` system user (Section 4.1.1) rather than `root` - the package's postinstall script makes that user the actual owner of `/etc/sslcrtsrv`/`/opt/sslcrtsrv` (not just a group member) specifically so the server can create and manage its own files there (`keysrv.db`, each certificate's `cert-<id>` directory, ...) without needing root.

**If you relocate any path away from its default** (`--datadir`/`data_dir`, `--certdir`/`cert_home_dir`, or `--config` itself pointed somewhere other than `/etc/sslcrtsrv/server_config.json`): both shipped units also set `ProtectSystem=strict` with `ReadWritePaths=/opt/sslcrtsrv /etc/sslcrtsrv` (Section 9.14) - anything the server needs to write that now lives *outside* those two paths becomes read-only to it, and startup/writes will fail. Add the new path with a drop-in override rather than editing the packaged unit file directly (which a package upgrade would otherwise overwrite):
```
sudo systemctl edit sslcrtsrv-server
```
and add
```ini
[Service]
ReadWritePaths=/opt/sslcrtsrv /etc/sslcrtsrv /your/custom/path
```
(repeat for `sslcrtsrv-acme-server` too, if it's also affected - it shares the same `data_dir`/`BASE_CONFIG_DIR`). The DB-encryption keypair is the one thing that's *never* relocatable (always under `/etc/sslcrtsrv` regardless of `--datadir`, Section 5.1's note) - it never needs a separate entry here.

### 4.5. Upgrading

- **Debian packages**: build the new version's `.deb`s (Section 4.1) and install them with `dpkg -i` (or `apt install ./sslcrtsrv-*.deb`, which also resolves any newly-added dependencies). Existing configuration, database, and certificates under `/etc/sslcrtsrv`/`/opt/sslcrtsrv` are untouched by a package upgrade - only the installed Python code and console scripts change. If the new version's release notes mention a schema change, run `scs-dbmigrate upgrade-schema` once before starting the server again (Section 6.8 / `TECHNICAL_REFERENCE.md`'s Section 3.5) - every other tool refuses to start against a database whose schema predates it, with a clear error pointing back here, rather than failing confusingly partway through.
- **Generic tarballs**: there is no in-place upgrade mechanism for the server or the admin tools - build and extract the new version's tarball (Section 4.2) over (or alongside) the old one, and reinstall its `requirements.txt` into the virtual environment if the dependency versions changed.
- **Clients specifically** can also upgrade themselves without any of the above, if the server has a newer client package published in its catalog (`TECHNICAL_REFERENCE.md`'s Section 2.2.2):

  ```
  scs-client update --update-package <name> [--update-command "dpkg -i /tmp/downloaded.deb"]
  ```

  which checks the server's catalog, downloads the package only if it's actually newer than the running client's own `sslcrtsrv.__version__`, and (if `--update-command` is given) runs it afterward to actually install what was downloaded.

### 4.6. ACME Server Setup and Reverse Proxy

`scs-acme-server` (`TECHNICAL_REFERENCE.md`'s Section 2.7 / Section 6.9) is installed by the `sslcrtsrv-server` package (Section 4.1.1) but not enabled by default - it needs the `acme` extra's one additional dependency, `python3-josepy` (a `Suggests:`, not a hard `Depends:`, on the Debian package - Section 2.2/8.4 of `ACME_SERVER_DESIGN.md`), and two config fields before it will start at all.

1. **Install `python3-josepy`** (Debian: `apt install python3-josepy`; tarball/pip install: `pip install sslcrtsrv[acme]`, or just `pip install josepy` into the same virtual environment).

2. **Enable it in `server_config.json`**, either via `scs-server init`:

   ```
   sudo scs-server init --acme-enabled --acme-external-url https://ca.example.com/acme \
       [--acme-listen 127.0.0.1] [--acme-port 5580]
   ```

   or via `admintui`'s Config tab (Section 7.6). `--acme-external-url` is required the moment `--acme-enabled` is given - it's the externally-visible base URL every ACME resource URL in every response is built from (never from request headers - see the reverse-proxy note below), so it must exactly match whatever a real ACME client will actually reach. `--acme-listen`/`--acme-port` (defaults `127.0.0.1`/`5580`) are the *local* address `scs-acme-server` itself binds to, behind the reverse proxy - almost never the same as the public host/port in `--acme-external-url`.

3. **Put a reverse proxy in front of it - this is mandatory, not optional.** `scs-acme-server` speaks plain HTTP and expects to be reached only through a TLS-terminating reverse proxy that forwards its ACME path prefix straight through, unmodified. A minimal nginx example, matching `--acme-external-url https://ca.example.com/acme` and the defaults above:

   ```nginx
   location /acme/ {
       proxy_pass http://127.0.0.1:5580/acme/;
       proxy_set_header Host $host;
       # Do NOT set X-Forwarded-Proto/X-Forwarded-Host - scs-acme-server
       # deliberately never trusts these for URL reconstruction (`TECHNICAL_REFERENCE.md`'s Section 2.7.2's
       # "never from request headers" note); acme_external_url is the only
       # source of truth for the URLs it returns.
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_read_timeout 30s;
       proxy_buffering off;
       # A JWS-wrapped CSR (especially a multi-SAN order) is small by web
       # standards but larger than a typical API call:
       client_max_body_size 128k;
   }
   ```

   The essential requirements this configuration must preserve, whichever proxy software is actually used: the request method and `Content-Type: application/jose+json` must reach `scs-acme-server` byte-for-byte unmodified (POST-as-GET's zero-length body included), every response's `Replay-Nonce`/`Link`/`Retry-After` headers must reach the client unmodified, and response caching must stay disabled (`scs-acme-server` already sends `Cache-Control: no-store` on every response, but a misconfigured shared cache in front of it could still serve a stale, already-consumed nonce without this).

   `X-Forwarded-For` is set above for two purposes, both optional and both gated the same way: IP-pinning (`TECHNICAL_REFERENCE.md`'s Section 2.7.4 / Section 9.10) and the access log's own source-IP column. Neither has any effect at all unless `acme_trusted_proxy_ip` (Section 5.1) is also set to this reverse proxy's own address - with that unset (the default), `scs-acme-server` never reads this header regardless of what the proxy sends, and every log line/pin check shows the proxy's own (often docker-internal) address instead of the real client.

4. **Rate-limit `new-account`, `new-order`, and `finalize` at the reverse-proxy layer** (e.g. nginx `limit_req`) - `new-account` is intentionally open (any key can self-register, exactly like the traditional protocol's own registration is open to any key - `TECHNICAL_REFERENCE.md`'s Section 2.3.4), so this is the layer that actually bounds abuse; `scs-acme-server` itself has no built-in per-endpoint rate limiting. Two automatic cleanup mechanisms complement this at the application level, both run for free as part of `crtrequest.py`'s existing cron pass (Section 9.3/6.5) rather than needing a separate scheduled job: unconfirmed ACME accounts older than `acme_unconfirmed_account_retention_days` (default 30) are deleted, and expired orders are invalidated with their processing locks released.

5. **Start (or restart) `scs-acme-server`**:

   ```
   sudo systemctl enable --now sslcrtsrv-acme-server
   ```

   - a separate systemd unit from `sslcrtsrv-server.service` (Section 4.4), since these are two independent processes with independent lifecycles; same `ConditionPathExists=server_config.json` gate, same "not enabled by default" posture, same `Restart=on-failure`. Running the tarball install instead: `./bin/scs-acme-server` (or `python3 -m sslcrtsrv.acme_server`), same `--config` semantics as every other tool (Section 4.2).

`scs-acme-server` shares `server_config.json`'s live-reload behavior (`TECHNICAL_REFERENCE.md`'s Section 2.6) - editing `acme_*` fields (or anything else in the file) restarts the process in place automatically, exactly like the traditional server does, and independently of it (each process watches and reloads on its own).

### 4.7. RPM Packages

For RPM-based distributions (Fedora, RHEL/CentOS/Rocky/AlmaLinux and similar), `packaging/rpm/sslcrtsrv.spec` builds the same `sslcrtsrv-client`/`sslcrtsrv-server` split as the Debian packages (Section 4.1) - install whichever matches this host's role, with `sslcrtsrv-server` depending on `sslcrtsrv-client` for the shared code, exactly like `sslcrtsrv-server`'s Debian `Depends:` does. Built with:

```
rpmbuild --define "version <version>" -ba packaging/rpm/sslcrtsrv.spec
```

(needs `rpm-build`, `python3-devel`, `python3-setuptools`, and `python3-rpm-macros` installed first - a source tarball named `sslcrtsrv-<version>.tar.gz` must already be in `~/rpmbuild/SOURCES/`, e.g. via `git archive --prefix=sslcrtsrv-<version>/ -o ~/rpmbuild/SOURCES/sslcrtsrv-<version>.tar.gz HEAD`). Pre-built `.rpm`s for each tagged release are attached to that release's GitHub page automatically (see below), alongside the `.deb`s and the plain tarballs (Section 4.2) - building from the spec by hand is only needed for an unreleased/local build.

Same systemd units, same dedicated `sslcrtsrv` system user/group, same `/etc/sslcrtsrv`/`/opt/sslcrtsrv` layout, and the same "installed but not enabled/started" posture as the Debian package (Sections 4.4/4.1.1) - `sslcrtsrv-server`'s `%pre` scriptlet creates the user, matching `debian/sslcrtsrv-server.postinst`.

**Automated builds:** `.github/workflows/release.yml` builds the `.deb`s, this RPM spec, the generic tarballs (Section 4.2), and a plain source tarball, then attaches all of them to the GitHub Release for every pushed `v<version>` tag (the same tag `internal/tools/publish_public_repo.py` creates when publishing a new version) - nothing needs to be built or uploaded by hand for a tagged release.

---

## 5. Configuration Reference

All three configuration files are plain JSON, read and rewritten as a whole (not merged field-by-field by anything other than the tools documented here) - hand-editing is safe as long as the result is still valid JSON, but any of the `init`/`admintui` writes will happily overwrite hand-added fields they don't know about.

### 5.1. Server Configuration (server_config.json)

Written by `scs-server init` (Section 4.3.1), and by `admintui`'s Config tab. Contains the server's own identity keypair, so it should stay at the group-shared, non-world-readable mode described in `TECHNICAL_REFERENCE.md`'s Section 2.3.5.

| Field | Type | Default | Notes |
|---|---|---|---|
| `listen_address` | string | `0.0.0.0` | `--listen` |
| `port` | integer | `5514` | `--port` |
| `bind_also` | array of strings | *(absent if none configured)* | `["HOST:PORT", ...]` - one entry per `--bind-also HOST:PORT` given to `init` (repeatable; each call adds one more entry on top of any already configured, none are replaced/removed). Each entry opens one additional listener, handled identically to the primary `listen_address`/`port` one (both the signed/encrypted protocol and the plain-HTTP download path) - see `TECHNICAL_REFERENCE.md`'s Section 2.1. An IPv6 host must be bracketed (`[::1]:5514`). A malformed entry, or one that fails to bind (e.g. already in use), is logged and skipped at startup without preventing the primary listener or any other `bind_also` entry from starting. |
| `allowed_networks` / `denied_networks` | arrays of strings | *(absent - no restriction)* | Netblock/subnet access control for `scs-server`'s own port(s) - bare IPs or CIDR ranges (e.g. `"10.0.0.0/8"`, `"203.0.113.5"`, IPv4 or IPv6), checked against the direct TCP peer address before anything else happens with a newly-accepted connection (Section 9.13). Hand-edit only. |
| `geoip_backend` | string | `"maxmind"` | `"maxmind"` or `"ip2location"` - which library/file format `geoip_database_path` is read with (Section 9.13). Shared by both servers. Hand-edit only. |
| `geoip_database_path` | string | *(absent - GeoIP checks disabled)* | Path to a user-provided MaxMind DB (`.mmdb`) or IP2Location (`.BIN`) database, depending on `geoip_backend`. Shared by both servers; a missing/unreadable/corrupt file disables country checks (logged and notified) without affecting the netblock ACL or startup (Section 9.13). Hand-edit only. |
| `allowed_countries` / `denied_countries` | arrays of strings | *(absent - no restriction)* | GeoIP country-level access control for `scs-server`'s own port(s) - ISO 3166-1 alpha-2 codes (e.g. `"DE"`), matched case-insensitively against the direct TCP peer's resolved country (Section 9.13). Hand-edit only. |
| `access_control_default` | string | `"allow"` | What `scs-server` falls back to when neither the netblock nor the GeoIP ACL has an opinion about a given address: `"allow"` (no restriction) or `"deny"` (access requires an explicit allow from one or both) (Section 9.13). An unrecognized value is treated as `"allow"`. Hand-edit only. |
| `private_key` / `public_key` | PEM strings | *(generated)* | The server's identity keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.1) - never regenerated by re-running `init` unless "overwrite" is explicitly chosen. |
| `registration_secret` | string | *(generated, printed once)* | `--registration-secret` (`TECHNICAL_REFERENCE.md`'s Section 2.3.4). |
| `default_acme_provider` | string | `letsencrypt` | `--default-acme-provider`; overridable per-certificate via `crtmanager.py set-provider`. |
| `data_dir` | string | `/opt/sslcrtsrv` | `--datadir`; relocates `keysrv.db` (see the note below) - does **not** move the DB-encryption keypair, which always stays under `/etc/sslcrtsrv`. |
| `cert_home_dir` | string | `/opt/sslcrtsrv/certs` | `--certdir`; base directory for every certificate's own `cert-<id>` `acme.sh` working directory (`TECHNICAL_REFERENCE.md`'s Section 2.4.3). |
| `log_dir` | string | `/opt/sslcrtsrv/logs` | Directory for every tool's own rotating log file (`<tool>.log`, Section 10.6) - hand-edit only. Set to `""` or `false` to disable file logging entirely. |
| `log_max_bytes` | integer | `10485760` (10 MiB) | Rotate a tool's log file once it reaches this size. Hand-edit only. |
| `log_backup_count` | integer | `5` | How many rotated-out backups to keep per tool, alongside the active log file. Hand-edit only. |
| `syslog_host` | string | *(absent - logs to the local syslog daemon via `/dev/log`)* | `--syslog-host`; send every tool's log output to a remote syslog server instead (Section 10.6). |
| `syslog_port` | integer | `514` | `--syslog-port`; only used if `syslog_host` is set. |
| `syslog_facility` | string | `daemon` | `--syslog-facility`; one of Python's `logging.handlers.SysLogHandler` facility names (`daemon`, `local0`-`local7`, `user`, `mail`, ...) - applies whether logging locally or remotely. |
| `client_packages` | object | *(absent if none configured)* | `name -> {"path", "version", "description"}`, one entry per `--client-package NAME:PATH:VERSION[:DESCRIPTION]` given to `init` (repeatable; each call upserts one entry, existing ones are left alone). Served over HTTP (`TECHNICAL_REFERENCE.md`'s Section 2.2.2). |
| `notifiers` | object | *(absent if none configured)* | `name -> {"type", ...type fields}` - one entry per `--notifier NAME:TYPE:key=value[,...]` given to `init` (repeatable, upserts one entry), or via `admintui`'s Notifiers tab (Section 7.8). See Section 10.2. |
| `notification_routing` | object | *(absent if none configured)* | `event -> [notifier names]` - one entry per `--notify-on EVENT:NAME[,NAME...]` given to `init` (repeatable, upserts one event's routing), or via `admintui`'s Notifiers tab. See Section 10.3. |
| `notification_rate_limit` | object | `{"max_notifications": 10, "window_seconds": 300}` | Global default cap on notifications-per-window, applied to every notifier with no more specific override. `--notification-rate-limit`/`--notification-rate-limit-window`. See Section 10.7. |
| `notification_rate_limits` | object | *(absent if none configured)* | `name -> {"max_notifications", "window_seconds"}` - per-notifier-**name** override of the global default above; either field may be given alone. One entry per `--notification-rate-limit-for NAME:MAX[:WINDOW]` given to `init` (repeatable, upserts one named override). See Section 10.7. |
| `database` | object | *(absent - sqlite/`data_dir` default)* | `{"backend": "sqlite"\|"mysql"\|"postgresql", "mysql"/"postgresql": {"host", "port", "user", "password", "database"}}` - see `TECHNICAL_REFERENCE.md`'s Section 3.5. `--db-backend`/`--db-host`/`--db-port`/`--db-user`/`--db-password`/`--db-name`, or `admintui`'s Config tab. |
| `acme_enabled` | boolean | `false` | `--acme-enabled`/`--no-acme-enabled` (Section 4.6/6.9) - `scs-acme-server` refuses to start unless this is `true` **and** `acme_external_url` is also set. |
| `acme_external_url` | string | *(absent)* | `--acme-external-url` - the externally-visible base URL (behind the mandatory reverse proxy, Section 4.6) every ACME resource URL in every response is built from. Required once `acme_enabled` is `true`. |
| `acme_listen` | string | `127.0.0.1` | `--acme-listen` - the local address `scs-acme-server` itself binds to, behind the reverse proxy. |
| `acme_port` | integer | `5580` | `--acme-port` - the local port `scs-acme-server` itself binds to. |
| `acme_nonce_ttl_seconds` | integer | `3600` | How long an issued-but-unused ACME nonce (`TECHNICAL_REFERENCE.md`'s Section 3.6) stays valid. No `init`/`admintui` field for this - hand-edit the file. |
| `acme_order_ttl_days` | integer | `7` | How long an order may stay `pending`/`processing` before the cleanup pass (Section 4.6 point 4) invalidates it and releases its processing lock. Hand-edit only. |
| `acme_finalize_retry_after_seconds` | integer | `300` | The `Retry-After` value sent on a `finalize` response while the order is still `processing` (`TECHNICAL_REFERENCE.md`'s Section 2.7.2) - i.e. roughly how often an ACME client should be expected to poll. Hand-edit only. |
| `acme_max_issuance_attempts` | integer | `20` | How many failed `crtrequest.py` issuance attempts (Section 6.3/9.10) an order tolerates before being invalidated and its lock released, with capped exponential backoff between attempts. Hand-edit only. |
| `acme_unconfirmed_account_retention_days` | integer | `30` | How long an unconfirmed ACME account may sit before the cleanup pass deletes it (Section 4.6 point 4/8.5 of `ACME_SERVER_DESIGN.md`). Hand-edit only. |
| `acme_trusted_proxy_ip` | string | *(absent - `X-Forwarded-For` never trusted)* | The reverse proxy's own address - `X-Forwarded-For` is trusted for both IP-pinning enforcement and the access log's source-IP column (Section 9.10) only when a request's direct TCP peer matches this exactly; otherwise ignored regardless of what a client sends. Hand-edit only. |
| `acme_allowed_networks` / `acme_denied_networks` | arrays of strings | *(absent - no restriction)* | Netblock/subnet access control for `scs-acme-server`'s own port, same syntax and semantics as `allowed_networks`/`denied_networks` above (Section 9.13) - by default checked against the direct TCP peer (normally the reverse proxy itself, not the real ACME client), unless `acme_access_control_use_forwarded_ip` is also set. Hand-edit only. |
| `acme_allowed_countries` / `acme_denied_countries` | arrays of strings | *(absent - no restriction)* | GeoIP country-level access control for `scs-acme-server`'s own port, same syntax/semantics as `allowed_countries`/`denied_countries` above (Section 9.13), resolved against the same address `acme_allowed_networks`/`acme_denied_networks` checks (native peer, or forwarded if `acme_access_control_use_forwarded_ip` is set). Hand-edit only. |
| `acme_access_control_use_forwarded_ip` | boolean | `false` | When `true`, `acme_allowed_networks`/`acme_denied_networks`/`acme_allowed_countries`/`acme_denied_countries` are all checked against the real client's address (via the same trusted-`acme_trusted_proxy_ip`/`X-Forwarded-For` resolution IP-pinning already uses) instead of the direct TCP peer - only makes a difference once `acme_trusted_proxy_ip` is also set (Section 9.13). Hand-edit only. |
| `acme_access_control_default` | string | `"allow"` | Same as `access_control_default` above, for `scs-acme-server`'s own `acme_allowed_networks`/`acme_denied_networks`/`acme_allowed_countries`/`acme_denied_countries` (Section 9.13). Independent of the traditional server's setting. Hand-edit only. |

**Note:** setting `data_dir` (via `--datadir`) relocates the SQLite database to `<data_dir>/keysrv.db` - every server-side tool (`scs-server`, `scs-crtmanager`, `scs-cltmanager`, `scs-crtrequest`, `scs-admintui`) reads `data_dir` back out of `server_config.json` at startup and follows it. This does **not** move the DB-encryption keypair (`/etc/sslcrtsrv/db_encryption_*.pem`), which is intentionally always under `/etc/sslcrtsrv` regardless of `data_dir`.

### 5.2. Client Configuration (client_config.json)

Written by `scs-client init` (Section 4.3.2), and updated in place after a successful `register`. Contains the client's own private key - keep this file owner-only (the strict default in `TECHNICAL_REFERENCE.md`'s Section 2.3.5, never the group-shared mode).

| Field | Type | Default | Notes |
|---|---|---|---|
| `client_id` | string | the host's own FQDN | `--client-id`. |
| `server_host` | string | `localhost` | `--server-host` - almost always needs to be set explicitly. |
| `server_port` | integer | `5514` | `--server-port`. |
| `private_key` / `public_key` | PEM strings | *(generated)* | The client's identity keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.1). |
| `registration_secret` | string | *(prompted for interactively if `--registration-secret` is omitted, to avoid it appearing in shell history)* | Consumed once, at `register` time (`TECHNICAL_REFERENCE.md`'s Section 2.3.4). |
| `server_public_key` | PEM string | *(absent until after a successful `register`)* | Added automatically once registration succeeds; every subsequent message is encrypted against this key (`TECHNICAL_REFERENCE.md`'s Section 2.2.3). |
| `data_dir` | string | `/opt/sslcrtsrv` | `--datadir`. Written but currently unused by any client code path. |
| `notifiers` | object | *(absent if none configured)* | Same shape as `server_config.json`'s own `notifiers` (Section 10.2) - `name -> {"type", ...type fields}`, including `type: "email"` (Section 10.1's field names, just nested under a name here too). **No `client.py init` flag writes this** (unlike `server.py init --notifier`) - hand-edit the file directly. |
| `notification_routing` | object | *(absent if none configured)* | Same shape as `server_config.json`'s own `notification_routing` (Section 10.3), but with client-specific event names: `client_registered`, `client_certificate_requested`, `client_certificate_retrieved`, `client_update_downloaded`, `client_update_installed`, and the generic `error` (Section 10.3.1). Also hand-edited directly; no CLI flag writes it. Consulted automatically on every subcommand except `init` (Section 6.2/10.3.1) - with neither this nor `notifiers` configured, nothing is read or sent, the same no-op behavior as an unconfigured `server_config.json`. |
| `notification_rate_limit` / `notification_rate_limits` | object | Same defaults as `server_config.json` | Same shape and meaning as `server_config.json`'s own fields (Section 10.7) - applies to any notification `client.py` sends. Hand-edited directly; no `client.py init` flag writes either one. Largely academic in practice: each `client.py` invocation is a separate, short-lived process with its own empty rate-limit counters, and already sends at most one notification per run (Section 10.3) regardless. |
| `update_package` | string | *(absent)* | A literal, hardcoded catalog package name for `update` to use when `--update-package` isn't given (`TECHNICAL_REFERENCE.md`'s Section 2.2.2 / Section 9.9) - takes precedence over `update_package_base` below. No `client.py init` flag writes this; hand-edit the file, matching the `notifiers` precedent above. |
| `update_package_base` | string | *(absent)* | Combined with this install's auto-detected package type (`TECHNICAL_REFERENCE.md`'s Section 2.2.2) into `<base>-<type>` when neither `--update-package` nor `update_package` is given - e.g. `"sslcrtsrv-client"` + detected type `"deb"` -> `"sslcrtsrv-client-deb"`. Only takes effect if this install actually has a detectable package type (a `.deb`/tarball build - a `pip install -e .` development checkout has none). |
| `update_command` | string | *(absent)* | Preset for `--update-command` (Section 9.9) - the shell command `update` runs after downloading a newer package, only if one was actually downloaded. |

### 5.3. Certificate Request Configuration (crtrequest_config.json)

Not created by any `init` command - copy `src/crtrequest_config.json.dist` to `/etc/sslcrtsrv/crtrequest_config.json` (mode `0600`) and fill in real values by hand. Only read by `crtrequest.py`; the client and the main server process never touch it.

| Field | Type | Notes |
|---|---|---|
| `DNS_PROVIDER_CONFIG.PDNS_Url` | string | The PowerDNS API URL (Section 2.3.3). |
| `DNS_PROVIDER_CONFIG.PDNS_ServerId` | string | PowerDNS server ID (typically `localhost`). |
| `DNS_PROVIDER_CONFIG.PDNS_Token` | string | PowerDNS API token - a genuine secret, hence this file being hand-copied and owner-only rather than generated into a group-shared location. |
| `CHALLENGE_ALIAS` | string | The delegation target every domain's CNAME entry points at (`TECHNICAL_REFERENCE.md`'s Section 2.5.1) - **not** prefixed with `_acme-challenge.` here; `crtrequest.py` adds that prefix itself when computing the expected CNAME target. |
| `ACME_SH_PATH` | string | Bare command (looked up on `PATH`) or absolute path to `acme.sh`, if it isn't already on `PATH`. Defaults to the bare command `acme.sh`. |

### 5.4. Configuration File Locations Summary

| Path | Contents | Written by |
|---|---|---|
| `/etc/sslcrtsrv/server_config.json` | Server identity, network, ACME/notification/client-package settings | `scs-server init`, `admintui` |
| `/etc/sslcrtsrv/client_config.json` | Client identity, server address, registration secret | `scs-client init`/`register` |
| `/etc/sslcrtsrv/crtrequest_config.json` | DNS provider credentials, `CHALLENGE_ALIAS`, `acme.sh` path | Hand-created from `src/crtrequest_config.json.dist` |
| `/etc/sslcrtsrv/db_encryption_private.pem` | DB-encryption private key (`TECHNICAL_REFERENCE.md`'s Section 2.3.3) - owner-only, always | `crtmanager.py init-db-key` |
| `/etc/sslcrtsrv/db_encryption_public.pem` | DB-encryption public key - world-readable (`0644`); not sensitive | `crtmanager.py init-db-key` |
| `<data_dir>/keysrv.db` | The database, if using the sqlite backend (the default - `TECHNICAL_REFERENCE.md`'s Section 3.5) | `server.py`/any tool, on first use |
| `<data_dir>/certs/cert-<id>/` | One certificate's own `acme.sh` working directory | `crtrequest.py`, on first issuance attempt |

All of the above are defaults, with `<data_dir>` defaulting to `/opt/sslcrtsrv`; `--config`/`--datadir`/`--certdir` (and, for `crtrequest_config.json`, a `--config` passed to `crtrequest.py` itself) can relocate all of them **except** the DB-encryption keypair paths, which are fixed constants under `/etc/sslcrtsrv` regardless of `--datadir` (see the note in Section 5.1).

---

## 6. Tool and Script Reference

Every tool accepts `-h`/`--help` (overall or per-subcommand) and `--version`. Options are grouped by subcommand where a tool has them; a bare option with no subcommand table applies to the tool as a whole. Each command below also installs a man page (`man scs-client`, etc.) covering the same subcommands and flags in the standard Unix reference format.

### 6.1. server.py (scs-server)

```
scs-server [init | test-notifier] [options]
```

Run with the `init` positional argument to create or update `server_config.json`; run with `test-notifier` to send a real test message through one configured notifier (Section 10.4); run with no arguments at all to actually start listening (`TECHNICAL_REFERENCE.md`'s Section 2.1/2.2).

| Option | Applies to | Meaning |
|---|---|---|
| `--config PATH` | all | Config file path. Default `/etc/sslcrtsrv/server_config.json`. |
| `--listen ADDR` | `init` | Listen address written to the config. Default `0.0.0.0`. |
| `--port N` | `init` | Listen port written to the config. Default `5514`. |
| `--bind-also HOST:PORT` | `init` | Repeatable; adds one more entry to `bind_also` (Section 5.1) - an additional address/port the server also listens on, handled identically to the primary one. Use `[HOST]:PORT` for IPv6, e.g. `--bind-also [::1]:5514`. |
| `--datadir PATH` | `init` | Stored as `data_dir`; relocates the SQLite database to `<PATH>/keysrv.db` (Section 5.1). Default `/opt/sslcrtsrv`. |
| `--certdir PATH` | `init` | Stored as `cert_home_dir`, genuinely used at runtime (`TECHNICAL_REFERENCE.md`'s Section 2.4.3). Default `/opt/sslcrtsrv/certs`. |
| `--syslog-host` / `--syslog-port` / `--syslog-facility` | `init` | Log the running server process to a remote syslog server instead of the local one (Section 10.6). Defaults: no host (local `/dev/log`), port `514`, facility `daemon`. |
| `--registration-secret SECRET` | `init` | Sets the shared registration secret explicitly, instead of generating one. |
| `--default-acme-provider NAME` | `init` | Default `letsencrypt`. |
| `--client-package NAME:PATH:VERSION[:DESCRIPTION]` | `init` | Repeatable; upserts one entry into `client_packages` (`TECHNICAL_REFERENCE.md`'s Section 2.2.2). |
| `--notifier NAME:TYPE:key=value[,key=value...]` | `init` | Repeatable; upserts one entry into `notifiers` (Section 10.2) - TYPE `email` included, e.g. `--notifier admin-email:email:notification_recipient=admin@example.com,smtp_host=mail.example.com`. |
| `--notify-on EVENT:NAME[,NAME...]` | `init` | Repeatable; upserts one event's routing in `notification_routing` (Section 10.3). |
| `--notification-rate-limit MAX` | `init` | Global cap on notifications-per-window for every notifier with no more specific override (Section 10.7). Default `10`; `0` or less disables the cap entirely. |
| `--notification-rate-limit-window SECONDS` | `init` | Global rate-limit window length (Section 10.7). Default `300`. |
| `--notification-rate-limit-for NAME:MAX[:WINDOW]` | `init` | Repeatable; upserts one named override into `notification_rate_limits` (Section 10.7) - `WINDOW` is optional, inheriting the global window if omitted. |
| `--notifier-name NAME` | `test-notifier` | Which configured notifier (by name) to send a test message through. |
| `--db-backend {sqlite,mysql,postgresql}` | `init` | Database backend (`TECHNICAL_REFERENCE.md`'s Section 3.5). Omit to keep the sqlite/`--datadir` default - no other `--db-*` flag is needed in that case. |
| `--db-host` / `--db-port` / `--db-user` / `--db-password` / `--db-name` | `init` | `mysql`/`postgresql` connection details, upserted into `database`'s matching sub-section. `--db-port` defaults to 3306/5432 respectively if omitted. |

Re-running `init` against an existing config file prompts interactively to either overwrite it completely (generating a new identity keypair) or update just the given options while keeping the existing keypair, registration secret, and any options not mentioned this time.

At the moment, no command to remove a client package, notifier, or event route is provided via the CLI - remove or update in the config, or use `admintui`'s Notifiers tab (Section 7.8), if so desired.

### 6.2. client.py (scs-client)

```
scs-client <init|register|request|listcerts|info|retrieve|checkversion|listpackages|update> [options]
```

Every subcommand except `init` takes `--config PATH` (default `/etc/sslcrtsrv/client_config.json`). There is no `--notify` flag: every subcommand except `init` automatically attempts an admin notification on completion, purely driven by whether `client_config.json`'s own `notifiers`/`notification_routing` route anything for the outcome (Section 10.3/10.3.1) - with neither key configured, nothing is read or sent.

| Subcommand | Positional args | Options | Purpose | Notification event(s) |
|---|---|---|---|---|
| `init` | - | `--client-id`, `--server-host` (default `localhost`), `--server-port` (default `5514`), `--datadir`, `--registration-secret` (prompted for if omitted), `--config` | Create `client_config.json` and the client's identity keypair. | *(none - never wrapped)* |
| `register` | - | `--config` | Register with the server (`TECHNICAL_REFERENCE.md`'s Section 2.4.1). | `client_registered` on success |
| `request` | `domains` (one or more, space- or comma-separated) | `--config` | Register interest in a new FQDNs set (`TECHNICAL_REFERENCE.md`'s Section 2.4.2). | `client_certificate_requested` on success |
| `listcerts` | - | `--config` | List every FQDNs set this client is currently authorized (`status=1`) for. | *(read-only - `error` only)* |
| `info` | `fqdns` (one or more) | `--config` | Read-only metadata for an already-authorized, already-issued certificate. | *(read-only - `error` only)* |
| `retrieve` | `fqdns` (one or more) | `--key`, `--cert`, `--intermediate`, `--combined`, `--all`, `--exec`, `--config` | Fetch and save certificate data (`TECHNICAL_REFERENCE.md`'s Section 2.4.4). Exits `10` specifically when an existing, still-valid file was left untouched rather than overwritten - not treated as a failure, and fires no success-event notification either (Section 10.3.1). | `client_certificate_retrieved` only when a file was actually written/replaced |
| `checkversion` | - | `--config` | Compare this client's version against the server's (`TECHNICAL_REFERENCE.md`'s Section 2.2.3). Exits `0` if they match or this client is newer, `1` if the server is newer. | *(read-only - `error` only, including the "server is newer" case)* |
| `listpackages` | - | `--config` | Fetch and print the server's `/client-packages` catalog (name/version/description) - no download, just a look (`TECHNICAL_REFERENCE.md`'s Section 2.2.2 / Section 9.9). | *(read-only - `error` only)* |
| `update` | - | `--update-package NAME`, `--update-command CMD`, `--config` | Self-update (`TECHNICAL_REFERENCE.md`'s Section 2.2.2 / Section 9.9). Neither flag is required any more - see the resolution order in `TECHNICAL_REFERENCE.md`'s Section 2.2.2. | `client_update_downloaded` (downloaded, not installed) or `client_update_installed` (downloaded and installed); none if already up to date |

Every subcommand's failure path (any exit code other than `0`, or `10` for `retrieve`) fires the generic `error` event, regardless of the table above.

`request`/`info`/`retrieve`'s positional arguments accept either one comma-separated argument (`www.example.com,mail.example.com`) or several separate ones (`www.example.com mail.example.com`) - both are joined into the same comma-separated FQDNs string before being sent.

### 6.3. crtmanager.py (scs-crtmanager)

```
scs-crtmanager <command> [options]
```

Running it with no subcommand at all prints help and exits `1`.

| Subcommand | Positional args | Options | Purpose |
|---|---|---|---|
| `list` | - | `--requested` (only pending/unissued), `--clients` (also show which clients have access) | The certificate inventory (`TECHNICAL_REFERENCE.md`'s Section 2.4). |
| `addlocal` | `key_file cert_file [intermediate_file]` | - | Add a certificate from existing PEM files - no `acme.sh` involved (`TECHNICAL_REFERENCE.md`'s Section 2.4.3). FQDNs are extracted from the certificate itself. |
| `update` | `key_file cert_file [intermediate_file]` | - | Replace an existing certificate's files in place, keeping every reference to it (client permissions) intact. |
| `delete` | `identifier` (FQDNs or database row ID) | - | Delete a certificate and its `acme.sh` working directory, after an interactive yes/no confirmation (`TECHNICAL_REFERENCE.md`'s Section 2.3.3's cleanup notes apply). |
| `delete-invalid` | - | - | List and (after confirmation) bulk-delete every expired certificate. |
| `warn-stale-downloads` | - | `--days N` (default 21) | Per-client report of active certificate assignments whose last *downloaded* copy is expiring within `N` days, already superseded by a renewal, or never downloaded at all (`TECHNICAL_REFERENCE.md`'s Section 2.4.4's download-tracking note). |
| `set-provider` | `identifier provider` | - | Change which ACME provider a certificate uses, or set it to `manual` to permanently exclude it from `crtrequest.py`'s automation (`TECHNICAL_REFERENCE.md`'s Section 2.4.3). |
| `init-db-key` | - | `--overwrite` (dangerous - orphans every already-encrypted row unless re-encrypted first) | One-time: generate the DB-encryption keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.3). |
| `migrate-encrypt-keys` | - | `--dry-run` | One-time: encrypt any legacy plaintext private keys already in the database. |

### 6.4. cltmanager.py (scs-cltmanager)

```
scs-cltmanager <command> [options]
```

Running it with no subcommand lists unconfirmed client registrations (the README's original "getting started" example). A top-level `--config PATH` option (default `/etc/sslcrtsrv/server_config.json`, same as every other tool) is only relevant if the server it's managing runs with a non-default `--config` - it's what `confirm` reads to compute the server's own fingerprint for the identity-verification step, and what relocates the database lookup to that config's `data_dir` if one is set.

| Subcommand | Positional args | Purpose |
|---|---|---|
| `listall` | - | Short overview of every client. |
| `list` | `[client_id]` | Every client and their certificate permissions, or just one client's if given. |
| `registration_command` | `[client_id] [--server-host HOST] [--server-port PORT]` | Print the `scs-client init`/`register` command lines to run on a new client host (Section 9.1), built from this server's own `registration_secret`/`port`. `--server-host` is required unless `listen_address` is already a concrete, non-wildcard address. |
| `confirm` | `client_id` | Confirm a pending registration (`TECHNICAL_REFERENCE.md`'s Section 2.4.1) - prompts for interactive yes/no after showing both public-key fingerprints. |
| `acme_confirm` | `client_id` | Confirm a pending ACME account (`TECHNICAL_REFERENCE.md`'s Section 2.7.4 / Section 9.10) - a `client_kind='acme'` row registered via `scs-acme-server`'s `new-account` endpoint, rather than `scs-client register`. Prompts for interactive yes/no after showing the account's RFC 7638 JWK thumbprint only (there is no server-side fingerprint to compare it against, unlike `confirm` above). |
| `revoke` | `client_id` | Un-confirm an already-confirmed client entirely (`TECHNICAL_REFERENCE.md`'s Section 2.4.1) - **not** the same as `revoke_permission` below. Works identically for an ACME account. |
| `delete` | `client_id` | Delete a client entry outright, after confirmation. |
| `assign` | `client_id fqdns [--valid-until DATETIME]` | Grant (or approve) a client's access to a certificate/FQDNs set (`TECHNICAL_REFERENCE.md`'s Section 2.4.2) - `status=1`, whether or not the client ever requested it itself. `--valid-until` optionally makes the grant expire automatically; omit for one that never expires. |
| `revoke_permission` | `client_id fqdns` | Revoke a specific certificate grant, or every grant for that client if `fqdns` is `all` (`TECHNICAL_REFERENCE.md`'s Section 2.4.2). |
| `set_expiry` | `client_id fqdns <DATETIME\|never>` | Change an already-granted permission's expiry date without touching its status (`TECHNICAL_REFERENCE.md`'s Section 2.4.2). |
| `clean_requests` | `[client_id]` | Bulk-delete pending (`status=0`) requests, for one client or every client, after confirmation. |
| `set_allowed_ip` | `client_id {IP-OR-CIDR\|none}` | Set or clear an optional IP-pinning restriction (Section 9.10) - only takes effect for ACME accounts; the traditional protocol never consults it. Validated as a real IP address or CIDR network before being stored. |
| `acme_cancel_order` | `order_id` | Cancel (invalidate) a stuck/dead ACME order and release its processing lock, unblocking that fqdns for a new order without waiting for the order's own expiry. |
| `acme_create_eab_grant` | `--label NAME --allowed-fqdns PATTERN [--expires DATETIME\|never]` | Create a pre-shared RFC 8555 External Account Binding credential for a trusted ACME client (Section 9.11) - prints the generated key ID/HMAC key exactly once. |
| `acme_create_contact_token_grant` | `--label NAME --allowed-fqdns PATTERN [--expires DATETIME\|never] [--domain DOMAIN]` | Create a pre-shared contact-field-token credential for a trusted ACME client with no EAB support at all (Section 9.11) - prints the exact plus-addressed contact string exactly once. |
| `acme_list_trust_grants` | - | List every ACME trust grant (never the raw secret, which isn't recoverable from what's stored). |
| `acme_revoke_trust_grant` | `grant_id` | Revoke a trust grant - stops it auto-approving anything new immediately, without touching accounts/permissions it already granted. |

### 6.5. crtrequest.py (scs-crtrequest)

```
scs-crtrequest [options]
```

No subcommands - behavior is selected entirely by flags. Typically run unattended (e.g. from cron) with no `--cert-name`, processing every approved certificate in one pass.

| Option | Meaning |
|---|---|
| `--config PATH` | Server config file to read `cert_home_dir`/`default_acme_provider` from. Default `/etc/sslcrtsrv/server_config.json`. |
| `--cert-name FQDNS` | Act on one specific FQDNs set instead of every approved one (e.g. `admintui`'s "Issue now"). |
| `--staging` | Request from the CA's staging/test environment (`TECHNICAL_REFERENCE.md`'s Section 2.4.5). |
| `--force` | Allow a staging certificate to overwrite an existing valid production one. |
| `--debug-acme` | Add `acme.sh`'s own `--debug` flag to every invocation. |
| *(default, no flag)* | DNS delegation is checked before every issuance/renewal attempt; a certificate whose delegation isn't in place is skipped with a warning instead of letting `acme.sh` fail on it (`TECHNICAL_REFERENCE.md`'s Section 2.5.2). |
| `--no-check-dns` | Disable that default DNS check entirely, restoring the old unconditional behavior. |
| `--check-dns-only` | Pure diagnostic: check DNS delegation and report, never call `acme.sh` or touch the database (`TECHNICAL_REFERENCE.md`'s Section 2.5.2). |
| `--force-dns-refresh` | Force a real re-issuance to push a freshly rotated DNS-provider token into `acme.sh`'s saved state immediately (`TECHNICAL_REFERENCE.md`'s Section 2.4.5). Consumes a real issuance per domain touched - not for routine use. |
| `--notify` | If this run finishes with one or more failures, also send an admin notification via `server_config.json`'s `notifiers`/`notification_routing` (`error` event, Section 10.3) - a single message summarizing every error logged during the run. Off by default; not passed by `admintui`'s own DNS-check/issue-now actions, which already show errors live in their progress modal. Meant for unattended runs (cron) where nobody's watching stdout/`crtrequest.log`. |

### 6.6. admintui (scs-admintui)

```
scs-admintui
```

Takes no arguments beyond `-h`/`--version`. Launches the full-screen terminal dashboard described in detail in Section 7 - `q` quits, `F5` refreshes the active tab.

### 6.7. build-tarballs.py

```
python3 build-tarballs.py [--output-dir DIR]
```

Repository-root helper, not installed as a console script (it's a packaging tool, not part of the product itself - Section 4.2). `--output-dir` defaults to `dist/`.

### 6.8. dbmigrate.py (scs-dbmigrate)

```
scs-dbmigrate <upgrade-schema | migrate> [options]
```

Database schema upgrades and cross-backend data migration (`TECHNICAL_REFERENCE.md`'s Section 3.5) - deliberately the only tool in this project that touches schema DDL or copies data between backends; every other tool only ever creates a fresh, up-to-date, empty schema on first run.

| Subcommand | Options | Purpose |
|---|---|---|
| `upgrade-schema` | `--config PATH` | Bring the currently configured backend's schema up to date in place (e.g. adding `certificates.id` to a pre-existing installation). Safe to run repeatedly - a no-op once already current, and a no-op against a brand-new database (nothing to upgrade yet). Run this once after upgrading `sslcrtsrv` past a version that changed the schema, before starting any other tool. |
| `migrate` | `--to-backend {sqlite,mysql,postgresql}` (required), `--host`, `--port`, `--user`, `--password`, `--database`, `--config PATH` | Copy every client/certificate/permission row to a freshly created target backend, then repoint `server_config.json` at it. Prompts interactively for any connection detail not given as a flag. Leaves the source backend/data untouched. A `client_certificate_relations` row referencing a client/certificate no longer present in the source (SQLite never enforces this FK, so such rows can silently accumulate - `fixed-issues.md`) is skipped and printed, not treated as fatal. A missing driver (`PyMySQL`/`psycopg2`) or an unreachable target reports a plain, actionable error instead of a raw traceback. |

### 6.9. acme_server.py (scs-acme-server)

```
scs-acme-server [--config PATH]
```

The RFC 8555 protocol server (`TECHNICAL_REFERENCE.md`'s Section 2.7). No subcommands - it does one thing: read `acme_*` settings from `server_config.json` (default `/etc/sslcrtsrv/server_config.json`, same `--config` convention as every other tool) and start listening. Refuses to start with a clear, actionable error if `acme_enabled` isn't `true`, or if `acme_enabled` is `true` but `acme_external_url` is missing (Section 4.6). Requires the `acme` extra's `josepy` dependency to even import - a clear `ImportError`-based message names the missing package if it isn't installed, rather than an opaque traceback.

Like `server.py`, it watches `server_config.json` for changes and re-execs itself in place to pick them up (`TECHNICAL_REFERENCE.md`'s Section 2.6) - entirely independently of whether the traditional `server.py` process is even running, since these are two unrelated processes that merely happen to share one config file and one database.

No `init`/`test-notifier` subcommands of its own - account/order administration is `cltmanager.py`'s job (Section 6.4/9.10), and admin notifications for ACME events reuse the same `notifiers`/`notification_routing` configuration the traditional server already has (Section 10).

---

## 7. admintui Dashboard Guide

`scs-admintui` has no login or access-control layer of its own, and no network listener - it's a local-terminal application whose security is entirely delegated to OS-level access control (whoever can obtain a shell as the right Unix user, typically via local console or SSH, has full access to every action it exposes: revoke, delete, confirm, etc.). This is a deliberate design choice for its intended local/SSH-only use, not an oversight (`internal/security/SECURITY_FINDINGS.md` finding #25) - restrict who can log into this host as that user accordingly.

### 7.1. Navigation, Layout, and Keybindings

`scs-admintui` opens a full-screen dashboard: a header, a row of tabs, the active tab's content, and a footer showing that tab's key bindings. Click a tab to switch to it, or move focus to the tab bar and use `Left`/`Right`. Within a tab, `Tab`/`Shift+Tab` move focus between widgets (filter buttons, the data table, etc.) as usual.

Two bindings apply everywhere:

| Key | Action |
|---|---|
| `q` | Quit |
| `F5` | Refresh the currently active tab's data |

Every tab also refreshes its own data automatically whenever it becomes the active tab (so switching to Clients after approving something in Onboarding always shows current state) - `F5` is only needed to refresh a tab you're already looking at. Every list-like tab follows the same per-row convention: select a row with the cursor (or double-click, where noted) and use that tab's own key bindings, shown in its footer.

### 7.2. Onboarding Tab

The default tab on launch, and the one place that combines client confirmation and certificate approval into a single workflow. It lists every client that needs attention: not yet confirmed, and/or holding at least one pending (`status=0`) certificate request (`TECHNICAL_REFERENCE.md`'s Sections 2.4.1/2.4.2) - a client with neither simply doesn't appear here at all.

Selecting a row (`Enter`, or double-click) opens a combined detail dialog:

- If the client isn't confirmed yet, it shows both the client's and the server's public-key fingerprints (`TECHNICAL_REFERENCE.md`'s Section 2.3.4) and requires checking "I have compared this fingerprint out-of-band and it matches" before "Approve selected" is even enabled.
- A checklist of the client's pending FQDNs sets, each selected by default - deselect any that shouldn't be granted.
- **Approve selected**: confirms the client (if not already) and grants (`status=1`) every checked FQDNs set, in one action.
- **Reject selected**: discards the checked pending requests instead (deletes those relations outright - they'd have to be requested again to reappear).
- **Delete client**: removes the client entirely, after a confirmation prompt.

This tab is a UI-only convenience - everything it does is a direct composition of the same primitives `cltmanager.py confirm`/`assign`/`revoke_permission` use (Section 6.4), just presented as one combined action instead of several separate commands.

### 7.3. Certificates Tab

Every certificate that actually exists in the database (`TECHNICAL_REFERENCE.md`'s Section 2.4), with a filter bar (All / Expiring soon / Expired) and, toggleable, a "Clients" column showing which clients have access to each one.

| Key | Action |
|---|---|
| `a` | Add a certificate from local key/cert(/intermediate) files - `crtmanager.py addlocal` (`TECHNICAL_REFERENCE.md`'s Section 2.4.3) |
| `u` | Update an existing certificate's files in place |
| `p` | Change a certificate's ACME provider, or mark it `manual` |
| `i` | Issue/renew now via `acme.sh` (streams live output; `TECHNICAL_REFERENCE.md`'s Section 2.4.3) |
| `D` | Delete the selected certificate (and its `acme.sh` working directory), after confirmation |
| `d` | Check DNS delegation for the selected certificate (`TECHNICAL_REFERENCE.md`'s Section 2.5.2) |
| `c` | Toggle the "Clients" column |

Double-clicking a row opens a read-only list of every client with access to that certificate, including each grant's own "Permission Expires" date (`client_certificate_relations.permission_valid_until`, `TECHNICAL_REFERENCE.md`'s Section 3.3) alongside its status - independent of, and generally different from, the certificate's own expiry shown in the main table.

### 7.4. Requests Tab

Certificate requests not yet issued (`crtmanager.py list --requested` - `TECHNICAL_REFERENCE.md`'s Section 2.4.2), independent of whether they're already approved (`status=1`, e.g. approved but not yet processed by `crtrequest.py`) or still pending (`status=0`).

| Key | Action |
|---|---|
| `i` | Issue now via `acme.sh` for the selected FQDNs set (same live-output modal as the Certificates tab) |
| `d` | Check DNS delegation for the selected FQDNs set |

### 7.5. Clients Tab

Every client, with a filter bar (All / Pending / Confirmed) and per-client certificate counts (valid / invalid-or-unissued / requested) - a certificate whose own permission has passed its expiry (`TECHNICAL_REFERENCE.md`'s Section 2.4.2) counts as invalid here too, even if the certificate itself is still perfectly valid. The "Last IP" column shows the source address of that client's most recent successful connection/request (`TECHNICAL_REFERENCE.md`'s Section 3.1) - for an ACME account behind the mandatory reverse proxy, this is the real client's resolved address, not the proxy's own, the same resolution `acme_access_control_use_forwarded_ip` uses (Section 9.13).

Each row is colored to flag clients needing attention: **red** for a client that isn't confirmed yet, or that has never been seen active at all; **yellow** for a confirmed client that hasn't been seen active in the last two months (an approximate threshold, not calendar-exact). "Seen active" means different things per client kind, since they authenticate completely differently: a traditional (`client_kind='custom'`) client's last successful signed-message verification, or an ACME account's most recent order (of any status, including a failed/expired one - still evidence the account did something) - an ACME account's own last-connection field is never populated at all, since it authenticates via JWS rather than the traditional protocol's signed messages.

| Key | Action |
|---|---|
| `c` | Confirm the selected client |
| `R` (Shift+R) | Un-confirm (revoke) the selected client - `TECHNICAL_REFERENCE.md`'s Section 2.4.1, not to be confused with revoking a certificate permission |
| `d` | Delete the selected client, after confirmation |
| `Enter` | Open the client's permissions detail (also reachable by double-clicking a row) |

The permissions detail dialog shows the client's fingerprint (re-checkable at any time, not just during onboarding) and every certificate permission it holds - including its own expiry, separate from the certificate's - with buttons to assign a new domain (optionally with its own expiry), set or change the expiry on a selected permission, revoke one selected permission, or revoke all of them at once (`cltmanager.py assign`/`set_expiry`/`revoke_permission` - Section 6.4). A permission past its expiry is marked "(expired)" and highlighted the same way an expired certificate is.

### 7.6. Config Tab

A form editor for every `server_config.json` field (Section 5.1) except the server's own identity keypair - regenerating that is a much bigger, disruptive operation (every already-registered client would need the new public key redistributed) than a routine settings form should trigger, so it's deliberately left out here - and except admin notifications, which live entirely on the Notifiers tab (Section 7.8) instead. Includes a "Generate new" button for the registration secret and "Reload from disk"/"Save" actions.

The Storage section's "Database backend" selector (sqlite/mysql/postgresql, `TECHNICAL_REFERENCE.md`'s Section 3.5) shows the matching connection-detail fields for whichever backend is selected; saving merges onto whatever's already on disk, so switching backends and back never drops the other backend's saved connection details. Changing the backend here only edits the config - it does not itself perform any schema upgrade or data migration (Section 6.8's `scs-dbmigrate` handles that).

An "ACME server" section covers `scs-acme-server`'s four core settings (Section 4.6/5.1): an "Enabled" checkbox, "External URL", "Listen address", and "Port". Saving with the checkbox on but "External URL" blank is rejected with an inline error, matching `scs-acme-server`'s own startup check. "Listen address"/"Port" can be left blank to fall back to `scs-acme-server`'s own defaults (`127.0.0.1`/`5580`) rather than writing an explicit value. The five finer-grained tuning fields (`acme_nonce_ttl_seconds` and friends, Section 5.1's table) have no form fields here - hand-edit `server_config.json` for those.

Like every other way of editing `server_config.json`, once the config file is updated/overwritten, the server will use its live-reload feature, meaning any changes are automatically and immediately activated without needing a manual restart.

### 7.7. Maintenance Tab

One-time or rare administrative operations, deliberately kept off the daily tabs:

- **DB encryption key**: generate the keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.3), or overwrite an existing one (requires typing `OVERWRITE` to confirm - this permanently orphans every already-encrypted certificate private key unless re-encrypted under the new key first).
- **Legacy plaintext key migration**: preview or actually run `crtmanager.py migrate-encrypt-keys`.
- **Bulk cleanup**: delete every expired certificate, or clean up every stale (`status=0`) pending request across all clients.
- **DNS delegation**: "Check DNS (all tracked certificates)" - the bulk form of `TECHNICAL_REFERENCE.md`'s Section 2.5.2's `--check-dns-only`.

### 7.8. Notifiers Tab

Every configured admin notifier (Section 10.2), regardless of type - the general-purpose replacement for the Config tab's old, fixed-name single-email section. A table lists each notifier's name, type, which event(s) it's routed to (Section 10.3), and its rate-limit override if it has one (Section 10.7, "default" otherwise).

| Key | Action |
|---|---|
| `a` | Add a new notifier |
| `u` / `Enter` / double-click | Edit the selected notifier |
| `D` | Delete the selected notifier, after confirmation |

The add/edit form has a Name field (fixed once created - renaming isn't supported here; delete and re-add under a new name instead) and a Type dropdown that switches which further fields are shown to match that type's actual requirements (the same fields documented in Section 10.2's table, e.g. `notification_recipient`/`smtp_host`/... for `email`, `api_token`/`user_key` for `pushover`). Below that, a checkbox per event (`registration`/`certificate_request`/`error`) controls routing, and two optional fields let you override the notification rate limit for just this notifier - leave both blank to inherit the global default (Section 10.7).

A "Test" button sends one real test message through whatever's currently typed into the form - not necessarily saved yet - via the same `send_test_notification_for()` the `test-notifier` CLI command uses (Section 10.4), so it works identically for every notifier type, not just email. It runs in a background worker thread so the network call (SMTP, or an HTTP request) never freezes the dashboard.

Like the Config tab, changes here only take effect the next time the server process restarts (or, since `server_config.json` uses the same live-reload mechanism either way, automatically and immediately via `TECHNICAL_REFERENCE.md`'s Section 2.6).

---

## 8. Data Storage Reference

### 8.1. Directory Layout

#### 8.1.1. /etc/sslcrtsrv

Configuration and keys (Section 5.4). Owner-only (`0600`/`0700`) by default; `server_config.json` and the DB-encryption keypair use the wider group-shared mode instead (`TECHNICAL_REFERENCE.md`'s Section 2.3.5).

| File | Contents |
|---|---|
| `server_config.json` | Server identity, network, and feature settings (Section 5.1) |
| `client_config.json` | Client identity and server address (Section 5.2) - only present on client hosts |
| `crtrequest_config.json` | DNS provider credentials and `CHALLENGE_ALIAS` (Section 5.3) - only present where `crtrequest.py` runs |
| `db_encryption_private.pem` / `db_encryption_public.pem` | The DB-encryption keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.3) |

#### 8.1.2. /opt/sslcrtsrv

Runtime data.

| Path | Contents |
|---|---|
| `keysrv.db` | The database, if using the sqlite backend (the default - `TECHNICAL_REFERENCE.md`'s Section 3.5) |
| `certs/` | Base directory for every certificate's own working directory (`cert_home_dir`, Section 5.1) |
| `cltpkg/` | Base directory for any files to be provided by the server process via HTTP requests |

#### 8.1.3. Per-Certificate acme.sh Working Directories

Each certificate gets its own directory, `cert_home_dir/cert-<id>` (`<id>` being that certificate's own `certificates.id`, `TECHNICAL_REFERENCE.md`'s Section 3.2 - see `TECHNICAL_REFERENCE.md`'s Section 2.4.3/`fixed-issues.md` for what happens to this once a certificate is deleted), passed to `acme.sh` as `--home`. Almost everything inside it is `acme.sh`'s own internal state (its account configuration, CA metadata, and its own per-domain working files) - not something this project reads, writes, or needs to understand. The three files this project *does* read back, because they're what `acme.sh` was explicitly told to write there (`--cert-file`/`--key-file`/`--ca-file`), are:

| File | Contents |
|---|---|
| `ssl.cer` | The issued certificate |
| `ssl.key` | Its private key |
| `intermed.cer` | The CA's intermediate certificate |

These three are read into the database (`TECHNICAL_REFERENCE.md`'s Section 2.4.3) immediately after a successful issuance; nothing continues to read them from disk afterward. `acme.sh` itself, on the next renewal, reads and rewrites them as part of its own normal operation against this same `--home`. Manually adding, editing, or removing anything in a `cert-<id>` directory is unsupported - leave these directories alone entirely and let `crtrequest.py`/`acme.sh` manage them.

### 8.2. Database Schema

The full table-by-table schema reference (`clients`, `certificates`, `client_certificate_relations`, `used_nonces`, the pluggable-backend details, and the ACME tables) has moved to `TECHNICAL_REFERENCE.md` Section 3.

---

## 9. Administration Workflows

Each of these is a synthesis of material already covered in detail elsewhere - this section is meant to be read task-first ("I need to do X"), not as new information.

### 9.1. Onboarding a New Client

The `admintui` Onboarding tab (Section 7.2) does this in one combined step; the equivalent by hand:

1. On the client host: `scs-client init --server-host <server>`, then `scs-client register`.
2. Compare the printed public-key fingerprints with the client's administrator, out-of-band (`TECHNICAL_REFERENCE.md`'s Section 2.3.4).
3. On the server: `sudo scs-cltmanager confirm <client-id>`.

`sudo scs-cltmanager registration_command` (Section 6.4), run on the server first, prints step 1's exact `init`/`register` command lines (with this server's own address/port/registration secret already filled in) and a reminder of step 3 - paste its output onto the new client host instead of typing the sequence above by hand.

### 9.2. Requesting and Approving Certificates

1. Client requests: `scs-client request <fqdns>` (`TECHNICAL_REFERENCE.md`'s Section 2.4.2) - or an admin can skip this and go straight to step 2.
2. Admin approves: `sudo scs-cltmanager assign <client-id> <fqdns>`.
3. Issuance happens separately (Section 9.3) - approving does not call `acme.sh` by itself.

The Onboarding tab combines steps 1-2 into one dialog when a client has both an unconfirmed registration and pending requests at once.

### 9.3. Renewing Certificates

`crtrequest.py` with no `--cert-name` renews every approved certificate within 14 days of expiry (`TECHNICAL_REFERENCE.md`'s Section 2.4.5) - **nothing runs this automatically**; no cron job or systemd timer is installed by either packaging path. Set one up, e.g.:

```
# /etc/cron.d/sslcrtsrv - daily renewal check
0 3 * * * root scs-crtrequest --notify
```

DNS delegation is checked before every certificate by default (`TECHNICAL_REFERENCE.md`'s Section 2.5.2) - no flag needed for an unattended job to get that safety net; it costs a couple of DNS lookups per certificate and turns a DNS misconfiguration into a clearly logged skip instead of a confusing `acme.sh` failure. Add `--no-check-dns` only if that's genuinely not wanted (e.g. `dig` isn't installed). To renew (or issue) just one certificate immediately instead of waiting for the schedule, use `--cert-name`, or `admintui`'s "Issue now" (Certificates/Requests tabs).

No output redirect is needed in the crontab line itself - `crtrequest.py` already writes its own rotating log file (`log_dir`/`crtrequest.log`, Section 10.6) regardless of how or from where it's invoked; add one only if you specifically want cron's own separate copy too. `--notify` (Section 6.5/10.3) is what makes a cron job like this one actually worth having admin notifications configured for - without it, a failed unattended renewal is only visible by reading that log file.

### 9.4. Diagnosing and Resolving DNS/Issuance Failures

1. Run `scs-crtrequest --check-dns-only --cert-name <fqdns>` (or `admintui`'s per-row/bulk "Check DNS") first - `TECHNICAL_REFERENCE.md`'s Section 2.5.2. If it reports a missing or wrong CNAME, fix the DNS entry and re-check before touching anything else.
2. If DNS checks out but issuance still fails, re-run with `--debug-acme` to get `acme.sh`'s own verbose output, and check that `crtrequest_config.json`'s `DNS_PROVIDER_CONFIG` credentials are still valid (Section 5.3) - an expired/rotated PowerDNS API token is a common cause and won't show up in a DNS *delegation* check, since the CNAME itself can be perfectly correct while the API token behind it has gone stale.
3. A certificate that failed mid-issuance never leaves a stale placeholder behind (`TECHNICAL_REFERENCE.md`'s Section 2.4.3) - it's safe to just fix the underlying problem and try again; there's no cleanup step needed first.

### 9.5. Rotating the Registration Secret

```
sudo scs-server init --registration-secret <new-secret>
```

against an existing config updates just the secret (choose "update" at the prompt), leaving the server's identity keypair and every other setting untouched. This only affects **future** registrations - already-registered clients never re-prove the secret again after their initial `register` call, so rotating it does not disrupt anyone already onboarded. Distribute the new secret to client administrators out-of-band, same as the first time (`TECHNICAL_REFERENCE.md`'s Section 2.3.4).

### 9.6. Rotating DNS Provider Tokens

1. Update `PDNS_Token` (and `PDNS_Url`/`PDNS_ServerId` if those changed too) in `crtrequest_config.json` (Section 5.3).
2. Run `scs-crtrequest --force-dns-refresh` (all certificates) or `--force-dns-refresh --cert-name <fqdns>` (one) to push the new token into `acme.sh`'s own saved state immediately (`TECHNICAL_REFERENCE.md`'s Section 2.4.5), rather than waiting for each certificate's natural renewal window. This consumes a real certificate issuance per domain touched - it's meant for this deliberate situation, not routine use.

### 9.7. Manually Adding or Updating Certificates

For certificates that don't go through ACME at all (`TECHNICAL_REFERENCE.md`'s Section 2.4.3):

```
sudo scs-crtmanager addlocal /path/to/key.pem /path/to/cert.pem [/path/to/intermediate.pem]
```

FQDNs are extracted from the certificate itself - no need to type them out. To replace the files for a certificate already in the database (e.g. a manually-renewed commercial certificate) while keeping every client's existing permission intact, use `update` with the same syntax instead of `delete` + `addlocal`. Once added, request/approve/retrieve work exactly the same as for an ACME-issued certificate (Sections 9.1-9.2, `TECHNICAL_REFERENCE.md`'s Section 2.4.4).

### 9.8. Deleting Certificates and Clients

- **A certificate**: `sudo scs-crtmanager delete <fqdns-or-id>` (or `admintui`'s Certificates tab, `Shift+D`) - also removes its `acme.sh` working directory (`TECHNICAL_REFERENCE.md`'s Section 2.4.3). This does **not** touch the client permissions that pointed at it.
- **A client's access to one certificate**: `sudo scs-cltmanager revoke_permission <client-id> <fqdns>` (or `all`) - the certificate itself is untouched (`TECHNICAL_REFERENCE.md`'s Section 2.4.2).
- **A client's confirmed status**: `sudo scs-cltmanager revoke <client-id>` - reverts to unconfirmed; its certificate permissions are untouched (`TECHNICAL_REFERENCE.md`'s Section 2.4.1).
- **A client entirely**: `sudo scs-cltmanager delete <client-id>` (or `admintui`, with confirmation) - also removes every one of its `client_certificate_relations` rows (active and pending alike); the certificates themselves, and any other client's relations to them, are untouched.

### 9.9. Distributing and Updating the Client Package

1. Build the client package (Section 4.1.2/4.2) for whatever target format(s) client hosts need - `.deb`, generic tarball, etc.
2. Publish it, naming it `<base>-<type>` (`deb`/`tarball`) to enable auto-detection (`TECHNICAL_REFERENCE.md`'s Section 2.2.2) - `sudo scs-server init --client-package sslcrtsrv-client-deb:<path-on-server>:<version>[:<description>]` (repeatable, one per format).
3. On each client host, either:
   - One-time setup, then a short command forever after: add `"update_package_base": "sslcrtsrv-client"` (and, optionally, `"update_command": "<install command>"`) to `client_config.json` (Section 5.2), then just `scs-client update` - the install's detected package type (`TECHNICAL_REFERENCE.md`'s Section 2.2.2) combines with the base automatically; or
   - No config changes: `scs-client update --update-package sslcrtsrv-client-deb --update-command "<install command>"` every time.

Either way, `update` downloads and installs only if the server's published version is actually newer than the client's own. Run `scs-client listpackages` first (or any time) to see exactly what the server currently offers, without downloading anything.

Repeat step 2 whenever a new client version is built; step 3 can be run on a schedule (e.g. cron) on client hosts to keep them current without manual intervention on each one - if `client_config.json` on that host has `notifiers`/`notification_routing` configured (Section 10.3/10.3.1), a failed unattended update (or a successful one, via `client_update_downloaded`/`client_update_installed`) is reported automatically with no extra flag needed. The same applies to any other `client.py` subcommand run unattended, e.g. a `retrieve` cron job keeping a certificate file in sync.

### 9.10. Managing ACME Accounts and Orders

This is the ACME-protocol mirror of Sections 9.1-9.2 - the same underlying admin actions (`confirm`/`assign`), applied to accounts and orders that arrived via `scs-acme-server` (`TECHNICAL_REFERENCE.md`'s Section 2.7) instead of `scs-client`. There is no `admintui` equivalent yet (Onboarding/Certificates/Requests tabs only show traditional-protocol clients and requests) - everything below is `cltmanager.py`-only for now.

1. **A third-party ACME client self-registers** (its own `certbot register`/`acme.sh --register-account` equivalent, pointed at `acme_external_url`) - this creates an unconfirmed `client_kind='acme'` row, visible via `cltmanager.py listall`/`list` alongside traditional clients.
2. **Confirm the account**, after verifying its thumbprint out-of-band with whoever controls that ACME client (`TECHNICAL_REFERENCE.md`'s Section 2.7.4):

   ```
   sudo scs-cltmanager acme_confirm <client-id>
   ```

   The `client-id` here is the numeric database ID or the `acme:<thumbprint>`-shaped identifier `cltmanager.py listall` shows - not anything the ACME client itself is aware of.
3. **The ACME client places an order** (`new-order`, e.g. `certbot certonly --standalone -d www.example.com` pointed at this server's directory URL, or the DNS-01-style invocation its own documentation describes - from this server's point of view, only the identifiers requested matter, not which challenge type the client thinks it's doing).
4. **Approve it**, exactly like a traditional certificate request (`TECHNICAL_REFERENCE.md`'s Section 2.4.2 / Section 9.2):

   ```
   sudo scs-cltmanager assign <client-id> <fqdns>
   ```

   Once approved, the ACME client's own `finalize` call (submitting its CSR) succeeds and the order becomes visible to `crtrequest.py`'s next scheduled pass (`TECHNICAL_REFERENCE.md`'s Section 2.4.3 / Section 6.3) - no separate ACME-specific cron job is needed; the existing one (Section 9.3) now also drains `acme_orders` in the same run, guarded by `acme_enabled`.
5. **The ACME client polls and downloads** the certificate itself once issuance completes - nothing further is needed on this server's side. `cltmanager.py list <client-id>` (or `listall`) shows the account and its permissions the same way it does for a traditional client.

**Revoking or deleting an ACME account** uses the exact same commands as a traditional client (Section 9.8) - `cltmanager.py revoke <client-id>` un-confirms it, `cltmanager.py delete <client-id>` removes it entirely, cascading through its orders/certificates/locks first (`TECHNICAL_REFERENCE.md`'s Section 3.6). There is no ACME-specific `revoke`/`delete` variant, and none is needed.

**Pinning an account to a known, fixed source IP** (`TECHNICAL_REFERENCE.md`'s Section 2.7.4) - optional, and worth doing specifically for a known appliance/firewall's own ACME client that always requests from the same address:

```
sudo scs-cltmanager set_allowed_ip <client-id> 203.0.113.5
```

or a CIDR network (`203.0.113.0/24`) for a small, known range. `sudo scs-cltmanager set_allowed_ip <client-id> none` clears it again. Once set, every request for that account - not just `new-order`, every kid-authenticated endpoint - is checked against the request's source IP; a mismatch is rejected with the same response as an unconfirmed account (`TECHNICAL_REFERENCE.md`'s Section 2.7.4), so don't be alarmed if pinning a currently-active account and testing from the "wrong" address looks identical to a confirmation problem - that's deliberate. This has no effect at all on the traditional protocol or on a `client_kind='custom'` client - only on ACME accounts. If `scs-acme-server` sits behind a reverse proxy (the normal, required deployment - Section 4.6), also set `acme_trusted_proxy_ip` to that proxy's own address, or every request will appear to come from the proxy itself and no real client IP will ever match a pin - and, independently of pinning, the access log will show the proxy's own (often docker-internal) address for every request instead of the real client.

**Diagnosing a stuck order**: `crtrequest.py --debug-acme` (Section 6.5/9.4) surfaces the same `acme.sh` output for the CSR-relay path as it does for the traditional one - an order stuck in `processing` past its expected `Retry-After` is almost always a DNS/`acme.sh` issue diagnosable the same way (Section 9.4/11.5), not something specific to the ACME protocol layer itself.

**Reproducing an RSA account's RFC 7638 thumbprint independently**, to actually verify what `cltmanager.py acme_confirm` shows (`TECHNICAL_REFERENCE.md`'s Section 2.7.4) rather than trusting it on faith - needs only `openssl` and a plain `python3` (no `josepy`/`cryptography` required on the ACME client operator's own host, verified byte-for-byte against this server's own computed value for the same key):

- **certbot** (account key already JWK-shaped, at `/etc/letsencrypt/accounts/<ca-host>/directory/private_key.json`):

  ```
  python3 -c "
  import json, hashlib, base64
  with open('/etc/letsencrypt/accounts/<ca-host>/directory/private_key.json') as f:
      jwk = json.load(f)
  public = {k: jwk[k] for k in ('e', 'kty', 'n')}
  canonical = json.dumps(public, separators=(',', ':'), sort_keys=True)
  print(base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b'=').decode())
  "
  ```

- **acme.sh** (PEM account key, at `~/.acme.sh/ca/<ca-host>/account.key` - one extra step to derive the JWK fields via `openssl` first):

  ```
  python3 -c "
  import subprocess, hashlib, base64, json, re
  key = '$HOME/.acme.sh/ca/<ca-host>/account.key'
  modulus_hex = subprocess.run(['openssl', 'rsa', '-in', key, '-noout', '-modulus'],
                                capture_output=True, text=True, check=True).stdout.strip().split('=')[1]
  text = subprocess.run(['openssl', 'rsa', '-in', key, '-noout', '-text'],
                         capture_output=True, text=True, check=True).stdout
  exponent_hex = re.search(r'publicExponent:\s*\d+\s*\(0x([0-9a-fA-F]+)\)', text).group(1)
  if len(exponent_hex) % 2:
      exponent_hex = '0' + exponent_hex
  def b64url(hexstr):
      b = bytes.fromhex(hexstr).lstrip(b'\x00') or b'\x00'
      return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
  public = {'e': b64url(exponent_hex), 'kty': 'RSA', 'n': b64url(modulus_hex)}
  canonical = json.dumps(public, separators=(',', ':'), sort_keys=True)
  print(base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b'=').decode())
  "
  ```

Both produce the exact same base64url string `cltmanager.py acme_confirm`/`common/fingerprint_words.py`'s word list represents (`TECHNICAL_REFERENCE.md`'s Section 2.3.4's word-rendering applies identically here) - compare it against what the admin console shows before confirming, the same out-of-band-verification discipline as the traditional protocol's own fingerprint comparison (`TECHNICAL_REFERENCE.md`'s Section 2.4.1). Both recipes assume an RSA account key (the default for both clients); an ECDSA account key needs a different JWK shape (`crv`/`x`/`y` instead of `e`/`n`, `kty: "EC"`) not covered here.

### 9.11. Trusted-Client Auto-Approval (Skipping Manual Confirm/Assign)

Sections 9.10's `acme_confirm`/`assign` steps exist so a human decides, once per account and once per fqdns, that a given ACME client is legitimate. For a small set of devices the admin already trusts and controls directly (e.g. a firewall appliance's own built-in ACME client), that manual step can be skipped entirely via an **ACME trust grant** - a pre-shared credential the admin generates ahead of time, out-of-band, that both auto-confirms the account and auto-approves any fqdns matching an admin-chosen pattern, with no further action needed per device. This is a deliberate, explicit reduction in security posture (`TECHNICAL_REFERENCE.md`'s Section 2.7.5) - use it only for devices you already trust, never as the default onboarding path.

Two credential types, since not every ACME client supports the standards-based one:

- **RFC 8555 External Account Binding (EAB)** - the standard mechanism, works with any spec-compliant ACME client that exposes EAB configuration (a key ID and an HMAC key, presented as a signed object alongside `new-account`):

  ```
  sudo scs-cltmanager acme_create_eab_grant --label "fw1" --allowed-fqdns "*.fw.example.com" --expires 2027-01-01
  ```

  Prints a key ID and HMAC key **exactly once** - copy both into the ACME client's own EAB configuration immediately; they cannot be retrieved again afterward (only an encrypted form is kept). `--expires` is optional (omit, or `never`, for a grant that doesn't expire on its own).

- **Contact-field token** - a fallback for clients with no EAB support at all, encoding the credential as a plus-addressed token in the ACME account's ordinary `contact`/Email field instead:

  ```
  sudo scs-cltmanager acme_create_contact_token_grant --label "fw1-legacy" --allowed-fqdns "*.fw.example.com" --domain yourdomain.example
  ```

  Prints a string like `provisioning+7K3f9...@yourdomain.example` - paste it verbatim into the ACME client's Email/contact field (it never needs to be a real, deliverable mailbox). The client's `new-account` request is otherwise completely normal; the server recognizes the embedded token and auto-confirms accordingly.

`--allowed-fqdns` is a comma-separated glob pattern list (e.g. `"*.fw.example.com,*.other.example.com"`) matched against every fqdns the trusted account later requests via `new-order` - a `*` matches across dots too (more permissive than a TLS wildcard certificate's single-label rule), so `*.example.com` matches both `a.example.com` and `a.b.example.com`. Only fqdns matching the pattern are auto-approved; anything else from that same account still lands in the normal pending state, needing a manual `assign` like any other client.

Grants are reusable (the same grant can bootstrap several devices, or the same device re-registering with a new key) until revoked or their optional expiry passes:

```
sudo scs-cltmanager acme_list_trust_grants
sudo scs-cltmanager acme_revoke_trust_grant <grant-id>
```

Revoking a grant stops it approving anything new immediately, but never retroactively touches an account or fqdns permission it already granted - exactly like revoking a normal `assign` never un-approves a certificate already issued. An admin still gets a registration notification (Section 10) for every trust-granted account, worded to say it was auto-confirmed rather than "waiting to be confirmed" - if an unexpected device shows up this way, revoke the grant immediately.

There is no `admintui` support for managing trust grants yet - `cltmanager.py`-only, matching Section 9.10's own current scope.

### 9.12. Device-Specific ACME Client Configuration Examples

A growing, verified-working catalog of how to point a specific real-world device's own built-in ACME client at this server - Sections 9.10/9.11 describe the admin-side mechanics in the abstract; this section is concrete, copy-pasteable device configuration. Each device gets its own numbered subsection (9.12.1, 9.12.2, ...) so a new one can always be appended without renumbering the others.

Every device example covers **two independent variants**, since which one applies depends entirely on how much you trust the specific device and whether its ACME client supports EAB (Section 9.11):

- **Variant A: Pre-confirmed (trust grant, zero-touch).** The admin generates a trust grant ahead of time (Section 9.11); the device's own ACME client is configured with the resulting credential (an EAB key ID/HMAC key, or a contact-field token, whichever that device supports); registration, confirmation, and certificate-permission approval all happen automatically the moment the device first talks to this server - no admin step per device, ever.
- **Variant B: On-demand (manual authorization).** The device's ACME client is configured with nothing special - a plain contact email, no grant involved. It self-registers exactly like any other ACME client (Section 9.10); an admin then runs `cltmanager.py acme_confirm` and `assign` once, out-of-band, the same as onboarding any other new client.

Neither variant is "more correct" than the other - Variant A trades a small amount of security posture (Section 9.11's own caveat about accepting a pre-shared credential's risk) for zero-touch onboarding of a device you already trust; Variant B keeps the full manual-verification step for a device you want a human to explicitly approve, at the cost of that one-time admin action per device.


#### 9.12.1. acme.sh

Not to be confused with `crtrequest.py`'s own, entirely separate use of `acme.sh` to talk to an *upstream* real CA (Section 6.5/9.3) - this is `acme.sh` running on some *other*, downstream host, used as an ordinary ACME client pointed *at* this server, exactly like the FortiGate example above. Point it at `acme_external_url`'s directory as a custom/private CA server; no special build or plugin is needed.

Unlike FortiGate ≤7.4, `acme.sh` has native, direct support for RFC 8555 External Account Binding - prefer it over the contact-token fallback (Section 9.11) for Variant A below.

##### Variant A: Pre-confirmed via EAB trust grant

1. **Admin: create the grant**, scoped to the fqdns this host should be allowed to request:

   ```
   sudo scs-cltmanager acme_create_eab_grant --label "acme-sh-host1" --allowed-fqdns "host1.example.com"
   ```

2. **acme.sh: register the account**, using the printed key ID/HMAC key:

   ```
   acme.sh --register-account \
     --server https://ca.example.com/acme/directory \
     -m admin@example.com \
     --eab-kid '<key ID from step 1>' \
     --eab-hmac-key '<HMAC key from step 1>'
   ```

3. **acme.sh: issue the certificate**:

   ```
   acme.sh --issue -d host1.example.com --server https://ca.example.com/acme/directory
   ```

4. **Verify**: `acme_list_trust_grants`' `Uses`/`Last used` incremented, and the certificate issues with no admin action needed at any point.

##### Variant B: On-demand with manual authorization

1. **acme.sh: register plainly**, no EAB:

   ```
   acme.sh --register-account --server https://ca.example.com/acme/directory -m admin@example.com
   ```

2. **acme.sh: attempt to issue** - this will not succeed yet:

   ```
   acme.sh --issue -d host1.example.com --server https://ca.example.com/acme/directory
   ```

3. **Admin: confirm and approve**, once (Section 9.10):

   ```
   sudo scs-cltmanager acme_confirm <client-id>
   sudo scs-cltmanager assign <client-id> host1.example.com
   ```

4. **acme.sh: retry** `--issue` (or let its own cron-driven `--renew` pick it up).

**A caveat specific to Variant B, worth reading before relying on it in production**: this server's authorization is admin-approval-based, not a real DNS-01/HTTP-01 challenge (Section 9.11/`TECHNICAL_REFERENCE.md`'s Section 2.7.4) - the authorization simply becomes valid once `assign` runs, with nothing actually solved over the wire. Whether `acme.sh`'s own challenge-selection logic tolerates polling an authorization that's still pending admin approval (rather than erroring out on an unrecognized challenge type) has **not been verified end-to-end** in this project - this is the same open question `ACME_SERVER_DESIGN.md`'s own risk list already flags for real ACME clients generally. Variant A sidesteps the question entirely, since the fqdns is already approved before `acme.sh` ever asks. If you rely on Variant B with `acme.sh`, test the exact sequence yourself first.

#### 9.12.2. FortiGate (FortiOS up to 7.4)

FortiOS versions before 7.6.3 have no EAB support in their ACME configuration. **Only the contact-token method applies for Variant A on this version range**.

##### Variant A: Pre-confirmed via contact-token trust grant

1. **Admin: create the grant**, scoped to the fqdns pattern this specific FortiGate should ever be allowed to request:

   ```
   scs-cltmanager acme_create_contact_token_grant --label SOME_HOST_ID --allowed-fqdns "host1.example.com"
   ```

2. **FortiGate: configure the ACME enrollment**, using the exact `provisioning+<token>@...` string the command above printed as the Email field:

   ```
    edit "ACME-TEST"
        set enroll-protocol acme2
        set acme-ca-url "https://ca.example.com/acme/directory"
        set acme-domain "host1.example.com"
        set acme-email "<code from scs-cltmanager>"
    next
   ```
  **Please note: While sslcrtsrv will happily provide you with multi-domain/wildcard certificates, this way of configuring FortiGate for certificate requests will only allow specific, single host-certificates.**

3. **Verify**: the device's certificate request should complete with no `cltmanager.py acme_confirm`/`assign` step needed at all - confirm via `scs-cltmanager acme_list_trust_grants` that `Uses`/`Last used` incremented, and `scs-crtmanager list --requested` (or `listall`) shows the fqdns already `requested`/approved rather than `unassigned`.

##### Variant B: On-demand with manual authorization

1. **FortiGate: configure the ACME enrollment**, with a plain, ordinary contact email (no token, no special formatting):

   ```
    edit "ACME-TEST"
        set enroll-protocol acme2
        set acme-ca-url "https://ca.example.com/acme/directory"
        set acme-domain "host1.example.com"
        set acme-email "<some email address, not checked>"
    next
   ```

2. **Admin: confirm and approve**, once, the same as any other new ACME client (Section 9.10):

   ```
   sudo scs-cltmanager acme_confirm <client-id>
   sudo scs-cltmanager assign <client-id> <fqdns>
   ```

3. **Verify**: the FortiGate's next `finalize`/renewal attempt succeeds once `crtrequest.py`'s next scheduled pass (Section 9.3) picks up the now-approved order.

---

### 9.13. Netblock and GeoIP Access Control

Both `scs-server` and `scs-acme-server` support an optional netblock/subnet allow-list and deny-list, and an optional GeoIP country-level allow-list and deny-list, gating which source IPs may reach their listening port(s) at all - independent of, and checked *before*, both servers' own authentication (registration proof/message signatures on the traditional protocol, JWS verification on ACME) and the existing per-account ACME IP-pinning feature (Section 9.10). These are coarse, admin-configured perimeter controls, not a replacement for either - and GeoIP country matching specifically is trivially bypassed by anyone connecting through a VPN or proxy exit point in an allowed country. Treat it as a way to reduce exposure to bulk, region-targeted traffic (opportunistic scanning, credential-stuffing botnets concentrated in certain regions), not as a defense against a targeted attacker.

**Configuration** (Section 5.1): `allowed_networks`/`denied_networks` for `scs-server`, `acme_allowed_networks`/`acme_denied_networks` for `scs-acme-server`. Each is a list of bare IPs or CIDR ranges, IPv4 or IPv6 (e.g. `["10.0.0.0/8", "203.0.113.5", "2001:db8::/32"]`). All four default to absent/empty, meaning no restriction - this feature is entirely opt-in. There is no `init`/`admintui` flag for any of them yet; hand-edit `server_config.json` and either server picks up the change automatically (both already watch their config file for changes and restart themselves to apply edits - the same mechanism `bind_also`/`acme_trusted_proxy_ip` already rely on).

**Matching order** (standard firewall-ACL semantics, applied identically to both servers):
1. If the source address matches any entry in the deny list, the connection/request is rejected - always, even if it would also match the allow list.
2. Otherwise, if the allow list is non-empty, the connection/request is permitted only if the address matches an entry in it.
3. Otherwise (no allow list configured, not denied), it's permitted.

A malformed entry in either list is logged and skipped individually at check time, rather than blocking startup or breaking the rest of the list - the same lenient-per-entry handling `bind_also` already uses for a bad `HOST:PORT` string. This "matching order" describes the netblock ACL on its own; see below for how it combines with GeoIP once both are configured together.

**GeoIP configuration** (Section 5.1): `geoip_backend` (`"maxmind"`, the default, or `"ip2location"`) and `geoip_database_path` are shared by both servers - there is only ever one GeoIP database file to provision. `allowed_countries`/`denied_countries` for `scs-server` and `acme_allowed_countries`/`acme_denied_countries` for `scs-acme-server` each take a list of ISO 3166-1 alpha-2 country codes (e.g. `["DE", "AT", "CH"]`), matched case-insensitively. The database itself is never bundled - provide a MaxMind DB (`.mmdb`) Country or City database (MaxMind's own GeoLite2-Country, a commercial GeoIP2 database, or a `.mmdb` export from another provider such as DB-IP or IPinfo all work identically under the `"maxmind"` backend, since they share the same file format) or an IP2Location `.BIN` database under the `"ip2location"` backend.

**Installing the backend library** (neither is installed by default - see Section 2.2):

1. **For `"maxmind"` (the default):** `apt install python3-maxminddb` on Debian/Ubuntu, or `pip install sslcrtsrv[maxmind]` (tarball/pip installs) or just `pip install maxminddb` into the same virtual environment. Then provide a `.mmdb` file yourself - e.g. a free MaxMind GeoLite2-Country database (requires a free MaxMind account and license key, see MaxMind's own documentation for `geoipupdate`) or a commercial GeoIP2 database; a `.mmdb` export from DB-IP or IPinfo works identically.
2. **For `"ip2location"`:** there is no Debian package for this one - `pip install sslcrtsrv[ip2location]` or `pip install IP2Location` into the same environment `scs-server`/`scs-acme-server` run in, even on an otherwise `.deb`-based install. Then provide an IP2Location `.BIN` database (free LITE databases are available from IP2Location's own site, or a commercial subscription for more frequently updated/accurate data).

Either way, set `geoip_database_path` to wherever the file ends up and (if using `"ip2location"`) `geoip_backend` to `"ip2location"` - `scs-server`/`scs-acme-server` pick this up on the next restart or config-file change like any other setting. If the library for the configured `geoip_backend` isn't actually installed, loading the database fails exactly like a missing/corrupt file would (see below) - logged and notified, not a startup crash.

**Combining netblock and GeoIP checks.** Each address is decided by the first of these that applies:
1. Matches an entry in `allowed_networks` -> **permitted**, final (GeoIP never consulted).
2. Matches an entry in `denied_networks` -> **denied**, final.
3. Its resolved country matches `allowed_countries` -> **permitted**, final.
4. Its resolved country matches `denied_countries` -> **denied**, final.
5. None of the above matched -> `access_control_default`/`acme_access_control_default` decides.

Steps 1 and 2 are a genuine *match* against a listed IP/CIDR - a more precise, deliberate signal than a best-effort country lookup, so either one is final and skips GeoIP entirely. A non-empty `allowed_networks` that simply doesn't *cover* a given address is different: on its own that's not a denial, and GeoIP still gets a chance to permit it via step 3. But if GeoIP has no opinion either (not configured, or the address's country matches neither `allowed_countries` nor `denied_countries`), that non-matching `allowed_networks` reverts to denying the address after all, rather than falling through to `access_control_default` - an admin who configured `allowed_networks` with no GeoIP involved made a deliberate "only these addresses" decision, and `access_control_default` (commonly `"allow"`) must not silently let everything else through just because GeoIP was never actually consulted. (The same order applies within `scs-acme-server`'s own `acme_` fields, independently of the traditional server's.)

**`access_control_default`/`acme_access_control_default`** only applies when nothing above had any opinion at all (no lists configured, or `allowed_networks` genuinely empty and nothing else matched): `"allow"` (the default - no restriction configured at all means no restriction, this feature's original behavior) or `"deny"` (access requires an explicit allow from the netblock ACL, the GeoIP ACL, or both). An unrecognized value is treated as `"allow"` with a logged warning, rather than an unrecognized typo silently locking out every client.

**Deny log detail**, mentioned above, reflects whichever step actually decided: `denied_networks`/`allowed_networks` with the matched (or non-matching) subnet for steps 1/2, `denied_countries`/`allowed_countries` with the resolved country for steps 3/4, or `access_control_default=deny` for step 5.

**If the GeoIP database fails to load** (missing path, unreadable file, wrong format for the configured `geoip_backend`, or an unrecognized `geoip_backend` value), country-based checks are disabled - the netblock ACL (if configured) is unaffected, and neither server refuses to start or stop serving over a GeoIP problem. This is never silent: a load failure always triggers an admin notification (Section 10) through whatever notifiers are configured, in addition to a server log entry, specifically so a corrupted or not-yet-provisioned database doesn't quietly leave `denied_countries`/`acme_denied_countries` unenforced without anyone noticing. An admin relying solely on GeoIP lists with no netblock lists configured should understand that this failure mode means "no country restriction" until the database is fixed, not "server unreachable."

The database file is watched for replacement the same way `server_config.json` itself is - swapping in an updated file (e.g. via a monthly `geoipupdate`/DB-IP cron job) triggers the same automatic restart-to-apply behavior as a config edit, with no manual intervention needed.

**Protect the database file like any other config-adjacent file:** it isn't confidential, but a locally-writable `.mmdb`/`.BIN` file is a tampering vector - a local user able to overwrite it could manipulate which countries resolve as allowed. Keep it owner-only-writable (e.g. root-owned, not world-writable), the same discipline already used for `server_config.json`.

**Where the check happens, and what a rejected caller sees:**
- `scs-server`: checked immediately after `accept()`, before the connection is handed off for any protocol handling - a denied source has its socket closed immediately, with nothing sent back at all (indistinguishable from nothing listening on that port).
- `scs-acme-server`: checked before route matching, before the request body is even read, and before a database session is opened - covering every endpoint, including the unauthenticated `directory`/`new-nonce`/`intermediate` ones. A denied source gets a bare `403 Forbidden` with no body (not an ACME "problem document"), so it can't be used to fingerprint this as specifically an ACME server versus a port with nothing behind it.

**Native vs. forwarded address for `scs-acme-server`:** since `scs-acme-server` normally sits behind a mandatory reverse proxy (Section 4.6), the address actually seen at the TCP layer is usually the proxy's own, not the real ACME client's. By default, `acme_allowed_networks`/`acme_denied_networks` check that direct (native) peer address - the right choice if the goal is restricting *which hosts may reach the ACME port at all* (e.g. only the reverse proxy itself, or an internal management network that also has a path to it). Set `acme_access_control_use_forwarded_ip` to `true` to instead check the real client's address, reusing the same trusted-proxy/`X-Forwarded-For` resolution IP-pinning already relies on (Section 9.10) - this only produces a different result than the native address once `acme_trusted_proxy_ip` (Section 5.1) is also configured to the proxy's actual address; with it unset, `X-Forwarded-For` is never trusted regardless of this setting, exactly like IP-pinning's own behavior. `acme_allowed_countries`/`acme_denied_countries` resolve the country of this exact same address - there is no separate GeoIP-specific forwarding setting - so enabling `acme_access_control_use_forwarded_ip` makes the GeoIP check inherit the identical `X-Forwarded-For` spoofing exposure already documented for the netblock ACL (`internal/security/SECURITY_FINDINGS.md` finding #18): a reverse proxy that doesn't strip/validate an inbound `X-Forwarded-For` header lets a client lie about both its network address and its country.

**Example:** restrict the traditional protocol to clients in Germany/Austria/Switzerland by country, with one explicit exception for a known-good address outside that region (e.g. an admin's travel laptop) that's allowed regardless of where it geolocates; and separately, restrict ACME to only the reverse proxy's own address (defense in depth - the proxy is expected to be the only thing that ever talks to `scs-acme-server` directly), independent of country entirely. Note that `allowed_networks`/`acme_allowed_networks` and `allowed_countries`/`acme_allowed_countries` aren't simply combined here - see the priority rule above for why `acme_allowed_countries` would have no effect if it were also set alongside `acme_allowed_networks`:
```json
{
  "geoip_database_path": "/etc/sslcrtsrv/GeoLite2-Country.mmdb",
  "allowed_countries": ["DE", "AT", "CH"],
  "allowed_networks": ["203.0.113.50/32"],
  "acme_allowed_networks": ["10.20.0.5"]
}
```

---

### 9.14. systemd Hardening

Both shipped units (`sslcrtsrv-server.service`, `sslcrtsrv-acme-server.service`) set the following `[Service]` directives, on top of already running as the dedicated unprivileged `sslcrtsrv` user (Section 4.4):

| Directive | Effect |
|---|---|
| `NoNewPrivileges=true` | The process (and anything it execs) can never gain new privileges, e.g. via a setuid binary. |
| `ProtectSystem=strict` | The entire filesystem is read-only to the process except `/tmp`/`/dev`/etc. and whatever `ReadWritePaths` explicitly lists. |
| `ProtectHome=true` | `/home`, `/root`, and `/run/user` are inaccessible. |
| `PrivateTmp=true` | A private `/tmp` isolated from the rest of the system. |
| `ReadWritePaths=/opt/sslcrtsrv /etc/sslcrtsrv` | The two paths this process actually needs to write - see the callout below if you've relocated either. |
| `CapabilityBoundingSet=` | No Linux capabilities at all - neither process ever needs one (both bind unprivileged ports). |

**If you've relocated `data_dir`/`cert_home_dir`/`--config` away from their defaults** (Section 5.1), `ReadWritePaths` needs the new location added too, or `ProtectSystem=strict` will make it read-only and startup/writes will fail - see Section 4.4's callout for exactly how (a `systemctl edit` drop-in, not editing the packaged unit file). Run `systemd-analyze security sslcrtsrv-server`/`sslcrtsrv-acme-server` to see the resulting exposure score.

---
## 10. Notifications

Three separate tools can raise a notification, each reading its own, independently-configured set of notifiers - the server process (`server_config.json`, events `registration`/`certificate_request`/`error`), `crtrequest.py --notify` (also `server_config.json`, `error` only), and `client.py` (*`client_config.json`* - a completely different file, typically a different host/admin entirely - `client_registered`/`client_certificate_requested`/`client_certificate_retrieved`/`client_update_downloaded`/`client_update_installed`/`error`, Section 10.3.1). All three share the exact same underlying mechanism and notifier types, described in this section: whichever config file is in play, the admin can be alerted through one or more independently-named **notifiers** - email, a generic webhook (with built-in support for Slack/Discord/Telegram/Pushbullet/Simplepush/Bark/Pushcut, Section 10.2.2), or a specific natively-supported push service (Pushover, Pushsafer, Gotify, ntfy) - with each applicable **event** routed to whichever notifier(s) should fire for it.

Setting most of this up is config-file/CLI-driven: `scs-server init`/`test-notifier` (Section 6.1) for the server side, a plain `--notify` flag for `crtrequest.py` (Section 6.5); `client.py` (Section 6.2) has no such flag at all - it always attempts a notification, purely based on what `client_config.json`'s `notifiers`/`notification_routing` route. `admintui` has no client-side equivalent at all, since it only ever runs on the server. `admintui`'s Notifiers tab (Section 7.8) is the server-side UI for all of this - every notifier type, event routing, and per-notifier rate limits from one place; the Config tab (Section 7.6) has no notification-related fields at all.

### 10.1. Email Notifications

Email is just one more notifier `type` (10.2) - `{"type": "email", "notification_recipient": ..., "smtp_host": ..., ...}` - with no special-cased handling anywhere in the code or the config schema. Set one up the same way as any other notifier: `scs-server init --notifier admin-email:email:notification_recipient=admin@example.com,smtp_host=mail.example.com` (Section 6.1), or via `admintui`'s Notifiers tab (Section 7.8).

| Field | Default | Notes |
|---|---|---|
| `notification_recipient` | *(required)* | The admin address to notify. |
| `smtp_host` | *(required)* | SMTP server hostname. |
| `smtp_security` | `starttls` | `none` (plain, unencrypted SMTP), `starttls` (upgrade after connecting - typically port `587`), or `ssl` (implicit TLS from the start - typically port `465`). |
| `smtp_port` | `587` | Only used as a fallback if `smtp_host` is set but `smtp_port` isn't. |
| `smtp_user` / `smtp_password` | *(none)* | Only used if the SMTP server requires authentication - omit both for an open relay. |
| `notification_sender` | `sslcrtsrv@<this host's FQDN>` | The "From" address. |
| *(send timeout)* | 10 seconds | Not exposed by any CLI flag or `admintui` field - a `smtp_timeout` field can be added to the notifier by hand if a slower SMTP server needs longer, but nothing generates or edits it for you. |

### 10.2. Multiple Named Notifiers

Configured under a `notifiers` key - a map of an admin-chosen name to `{"type": ..., ...type-specific fields}`. This schema is identical wherever it's used: `server_config.json` (the server process, `crtrequest.py --notify`) or `client_config.json` (`client.py`, Section 5.2) - only the file differs, never the shape (10.2.1 has a worked `client_config.json` example). An email-type notifier uses exactly the field names in 10.1's table, in both files.

| Type | Required fields | Optional fields | Notes |
|---|---|---|---|
| `email` | `notification_recipient`, `smtp_host` | `notification_sender`, `smtp_port`, `smtp_security`, `smtp_user`, `smtp_password` | Same fields/semantics as 10.1's table. |
| `webhook` | `url` | `method` (default `POST`), `headers` (a dict - JSON-only, not settable via `--notifier`), `auth_header` (a single `"Header-Name: value"` string, e.g. for a bearer token), `body_template` (a dict - JSON-only; Section 10.2.2) | Generic JSON POST: `{"event": ..., "subject": ..., "message": ...}` by default, or a custom shape via `body_template`. Covers any service whose whole API is "POST this JSON to a URL" - see 10.2.2 for seven of them by name. |
| `pushover` | `api_token`, `user_key` | `priority`, `sound` | [pushover.net/api](https://pushover.net/api). |
| `pushsafer` | `private_key` | `device`, `icon`, `sound`, `priority` | [pushsafer.com/en/pushapi](https://www.pushsafer.com/en/pushapi) - form-encoded, not JSON, unlike everything else here - the one service natively supported that genuinely needed its own sender rather than fitting `webhook` + `body_template`. |
| `gotify` | `server_url`, `app_token` | `priority` (default `5`) | [gotify.net/api-docs](https://gotify.net/api-docs) - a self-hosted server. |
| `ntfy` | `topic` | `server_url` (default `https://ntfy.sh`), `auth_token`, `priority` | [docs.ntfy.sh/publish](https://docs.ntfy.sh/publish/). |

Add or update one notifier via `scs-server init --notifier NAME:TYPE:key=value[,key=value...]` (repeatable - each call upserts just that named entry, existing ones are left alone, same pattern as `--client-package`, Section 6.1):

```
sudo scs-server init --notifier ops-pushover:pushover:api_token=<token>,user_key=<key>
sudo scs-server init --notifier ops-pushsafer:pushsafer:private_key=<key>
sudo scs-server init --notifier ops-gotify:gotify:server_url=https://gotify.example.com,app_token=<token>
```

A `webhook` notifier's `headers`/`body_template` dicts aren't expressible through this flat CLI shorthand (only the single-string `auth_header` convenience field is) - edit `server_config.json` directly for anything using either (which, per 10.2.2, is most of the services `webhook` covers).

A notifier configured but not routed to anything (see 10.3) does nothing - it simply never fires.

#### 10.2.1. Example: One of Each Type

The exact shape of `server_config.json`'s `notifiers` key, showing every natively supported type at once (a real config would typically have far fewer):

```json
{
  "notifiers": {
    "admin-email": {
      "type": "email",
      "notification_recipient": "admin@example.com",
      "notification_sender": "sslcrtsrv@example.com",
      "smtp_host": "mail.example.com",
      "smtp_port": 587,
      "smtp_security": "starttls",
      "smtp_user": "sslcrtsrv-notify@example.com",
      "smtp_password": "hunter2"
    },
    "generic-hook": {
      "type": "webhook",
      "url": "https://example.com/hooks/sslcrtsrv",
      "method": "POST",
      "auth_header": "Authorization: Bearer xyz123",
      "headers": {
        "X-Extra-Header": "some-value"
      }
    },
    "ops-pushover": {
      "type": "pushover",
      "api_token": "azGDORePK8gMaC0QOYAMyEEuzJnyUi",
      "user_key": "uQiRzpo4DXghDmr9QzzfQu27cmVRsG",
      "priority": 1,
      "sound": "siren"
    },
    "ops-pushsafer": {
      "type": "pushsafer",
      "private_key": "ZDp5xY3vQeRt7uKq",
      "device": "a",
      "sound": "2",
      "priority": 1
    },
    "ops-gotify": {
      "type": "gotify",
      "server_url": "https://gotify.example.com",
      "app_token": "AQZ8vPh.KRvIw3q",
      "priority": 5
    },
    "ops-ntfy": {
      "type": "ntfy",
      "server_url": "https://ntfy.sh",
      "topic": "sslcrtsrv-alerts-a1b2c3",
      "auth_token": "tk_AgQdq7mVBoFEGH",
      "priority": 4
    }
  },
  "notification_routing": {
    "registration": ["admin-email", "ops-pushover"],
    "certificate_request": ["admin-email"],
    "error": ["admin-email", "ops-gotify", "ops-ntfy"]
  }
}
```

Notes on the fields that most often need explaining:

- **`admin-email`**: `notification_sender`/`smtp_port`/`smtp_security`/`smtp_user`/`smtp_password` are all optional (10.1's table lists their defaults) - a minimal entry needs only `type`, `notification_recipient`, and `smtp_host`.
- **`generic-hook`**: `method`, `auth_header`, and `headers` are all optional - a minimal entry needs only `type` and `url`, and gets a plain unauthenticated `POST` of `{"event", "subject", "message"}` as JSON. `auth_header` and `headers` can both be set at once (as above) - `auth_header` is just a convenience for the single most common case (one auth header) and is merged into whatever `headers` already contains.
- **`ops-pushover`**: [pushover.net](https://pushover.net/) issues `api_token` per *application* you register and `user_key` per *user/device group* - both are required. `priority`/`sound` are optional (Pushover's own defaults apply if omitted); `priority: 1` here means "high priority" per Pushover's own API.
- **`ops-pushsafer`**: [pushsafer.com](https://www.pushsafer.com/) issues one `private_key` (or an "alias key" scoped to fewer devices) - the only required field. `device`/`icon`/`sound`/`priority` are all optional (Pushsafer's own defaults apply if omitted - `device` unset reaches every device on the account).
- **`ops-gotify`**: `server_url` is your own [Gotify](https://gotify.net/) server (Gotify is always self-hosted, unlike Pushover/Pushsafer/ntfy's public cloud services above), `app_token` comes from that server's "Apps" admin page. `priority` is optional (shown here at its default, `5`).
- **`ops-ntfy`**: `topic` is the only required field - [ntfy.sh](https://ntfy.sh/) needs no account at all for its public instance, a topic name is the entire "subscription." `server_url` defaults to the public instance (`https://ntfy.sh`) if omitted - set it to point at a self-hosted ntfy server instead. `auth_token`/`priority` are optional and only meaningful if the topic/server actually enforces auth or supports ntfy's priority levels (`1`-`5`).

**`client.py`'s `client_config.json`** uses this exact same `notifiers`/`notification_routing` schema (Section 10.3.1) - only the file differs, not the shape. A client that only ever wants `error` notifications (the only event that applies to it) can drop the `registration`/`certificate_request` keys entirely:

```json
{
  "notifiers": {
    "ops-ntfy": {"type": "ntfy", "topic": "client-host-alerts-x7y8z9"}
  },
  "notification_routing": {
    "error": ["ops-ntfy"]
  }
}
```

#### 10.2.2. Example: Slack, Discord, Telegram, and More, via `webhook`

Several popular services turn out to just be "POST a small JSON object to a URL" once you read their actual API docs - not different enough from each other, or from the generic case, to justify a dedicated type each. For those, `webhook`'s `body_template` field (a dict, JSON-only - not settable via `--notifier`) replaces the default `{"event", "subject", "message"}` payload with a custom one of your choosing: any string value inside it may contain the placeholders `{{event}}`, `{{subject}}`, and `{{message}}`, substituted in before the whole thing is serialized to JSON. The double braces are deliberate - they can't collide with JSON's own single-brace object syntax, so nothing in a template ever needs escaping. Substitution happens on the underlying dict/list *structure*, not on already-serialized text, so a subject/message containing quotes, newlines, or backslashes is still escaped correctly by the time it's actually sent - no broken JSON, regardless of what a client ID or error message happens to contain.

Everything below is a real, verified shape for that service's actual API (endpoint, auth mechanism, required JSON fields) - not a guess:

**Slack** ([Incoming Webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)) - the webhook URL Slack gives you *is* the entire authentication mechanism, so no `auth_header` is needed:

```json
"ops-slack": {
  "type": "webhook",
  "url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
  "body_template": {"text": "*{{subject}}*\n{{message}}"}
}
```

**Discord** ([Webhook Resource](https://docs.discord.com/developers/resources/webhook)) - same pattern as Slack, the URL alone authenticates:

```json
"ops-discord": {
  "type": "webhook",
  "url": "https://discord.com/api/webhooks/123456789012345678/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "body_template": {"content": "**{{subject}}**\n{{message}}"}
}
```

**Telegram** ([Bot API `sendMessage`](https://core.telegram.org/bots/api#sendmessage)) - the bot token lives in the URL path itself (from [@BotFather](https://t.me/BotFather)); `chat_id` is whichever chat/channel/group the bot has been added to (numeric ID, or `@channelusername` for a public channel):

```json
"ops-telegram": {
  "type": "webhook",
  "url": "https://api.telegram.org/bot123456789:AAExampleTokenExampleTokenExample/sendMessage",
  "body_template": {"chat_id": "987654321", "text": "{{subject}}: {{message}}"}
}
```

**Pushbullet** ([API docs](https://docs.pushbullet.com/#create-push)) - needs `type: "note"` fixed in the template (Pushbullet's own required field, not this project's), plus the account's access token as a header:

```json
"ops-pushbullet": {
  "type": "webhook",
  "url": "https://api.pushbullet.com/v2/pushes",
  "auth_header": "Access-Token: o.ExampleAccessTokenExampleToken12",
  "body_template": {"type": "note", "title": "{{subject}}", "body": "{{message}}"}
}
```

**Simplepush** ([API docs](https://simplepush.io/api)) - `key` is the six-digit code shown the first time the app is opened, no account/registration needed:

```json
"ops-simplepush": {
  "type": "webhook",
  "url": "https://api.simplepush.io/send",
  "body_template": {"key": "HuxgBB", "title": "{{subject}}", "msg": "{{message}}"}
}
```

**Bark** ([Finb/Bark](https://github.com/Finb/Bark)) - `device_key` comes from the Bark app on the target iOS device; `server_url` here defaults to the public `api.day.app` instance the app itself uses, or point it at a self-hosted `bark-server`:

```json
"ops-bark": {
  "type": "webhook",
  "url": "https://api.day.app/push",
  "body_template": {"title": "{{subject}}", "body": "{{message}}", "device_key": "ExampleDeviceKey1234567890"}
}
```

**Pushcut** ([Web API](https://www.pushcut.io/webapi)) - the notification *name* (created in the Pushcut app beforehand) is part of the URL, not the body; `title`/`text` override that notification's own configured content for this one send:

```json
"ops-pushcut": {
  "type": "webhook",
  "url": "https://api.pushcut.io/v1/notifications/ServerAlert",
  "auth_header": "API-Key: ExamplePushcutApiKey123",
  "body_template": {"title": "{{subject}}", "text": "{{message}}"}
}
```

### 10.3. Event Routing

A `notification_routing` key maps each event to the list of notifier names that should fire for it: `{"registration": [...], "certificate_request": [...], "error": [...]}` - same schema in both `server_config.json` and `client_config.json` (10.2's note applies here too), though `client_config.json` uses its own client-specific event names instead of `registration`/`certificate_request` (see the `client.py` table in Section 6.2, and the bullet below for `error`). In `server_config.json`, set it via `scs-server init --notify-on EVENT:NAME[,NAME...]` (repeatable - each call replaces just that event's routing, other events are left alone); `client_config.json` has no equivalent CLI flag (Section 5.2) - hand-edit it directly.

```
sudo scs-server init --notify-on registration:ops-pushover,ops-gotify --notify-on error:ops-gotify
```

- **`registration`** - a new client registered and is waiting to be confirmed (`TECHNICAL_REFERENCE.md`'s Section 2.4.1). Fired from a background thread inside `handle_registration()`, specifically so a slow/unreachable notifier can never delay the registration response back to the client - by the time any notifier is even attempted, the client has already been durably saved and told registration succeeded. Includes the client ID and its public-key fingerprint, and a reminder to verify that fingerprint out-of-band before confirming (`TECHNICAL_REFERENCE.md`'s Section 2.3.4). A new **ACME account** self-registering via `scs-acme-server` (`TECHNICAL_REFERENCE.md`'s Section 2.7.4 / Section 9.10) fires this same event, from `scs-acme-server`'s own process (reading the same `notifiers`/`notification_routing` from `server_config.json`) - the message instead includes the account's RFC 7638 JWK thumbprint and points at `cltmanager.py acme_confirm` rather than `confirm`.
- **`certificate_request`** - a confirmed client requested a new certificate (`request_type=certificates`, `TECHNICAL_REFERENCE.md`'s Section 2.2.3/2.4.2) - same background-thread reasoning as `registration`. Includes the client ID, the requested FQDNs, and the `cltmanager.py assign` command to approve it.
- **`error`** - a genuine operational problem, from three independent sources sharing this one event/routing *mechanism* (each still configured separately - see the note below):
  - The long-running server process: its identity keypair failed to load from config, the listening socket failed to bind, `accept()` on it started failing repeatedly (e.g. file-descriptor exhaustion - repeat notifications for this specific condition are suppressed for 5 minutes so an ongoing problem doesn't turn into one message per failed loop iteration), the config-file watcher failed to start, or the server process is about to exit due to an unhandled exception. **Deliberately not wired into per-client-request failures** (a malformed message from one client, a failed certificate lookup, ...) - only server-wide conditions, to avoid turning routine, expected failures (a port scan, one flaky client) into a notification storm.
  - `crtrequest.py`, but **only when invoked with `--notify`** (Section 6.5) - a separate, deliberate opt-in on top of routing `error` to at least one notifier, since `crtrequest.py` is a short-lived script run either interactively/via `admintui` (where errors are already visible directly, so a notification would be redundant) or unattended via cron (where `--notify` is what makes them visible at all). One notification per run, summarizing every error logged during that run - not per-certificate, so a run touching many certificates that all fail for the same underlying reason (e.g. the DNS provider is down) still produces exactly one message.
  - `client.py`, unconditionally, for every subcommand except `init` (Section 6.2) - same one-notification-per-run behavior as `crtrequest.py`, but using a **completely separate notifier/routing configuration**: `client.py` reads `notifiers`/`notification_routing` from *`client_config.json`*, not `server_config.json` - the client and server are often different hosts/admins entirely, so there's no shared config to route through even if both happen to run on the same machine.

  **Never enabled by default** - `error` is not routed anywhere unless explicitly set here (and, for `crtrequest.py` specifically, until `--notify` is also added to however it's invoked; `client.py` has no such flag to add - it's unconditional, gated only by whether anything is actually routed).

A route that names an unknown notifier, or a notifier of an unknown `type`, is skipped with a warning printed to the console/log of whichever process (server, `crtrequest.py`, or `client.py`) evaluated it - it never raises or prevents any other configured notifier from firing.

Every delivery attempt is best-effort: a failure (unreachable service, bad token, timeout, DNS failure, ...) is only ever logged to the triggering process's own stdout (visible via `journalctl -u sslcrtsrv-server` under `systemd` for the server, Section 4.4), never surfaced back to whoever/whatever performed the triggering action.

### 10.3.1. `client.py`: How Notifications Are Captured

Unlike the server process and `crtrequest.py` (both of which already use Python's `logging` module, so a summary can be built by attaching a temporary log-record-collecting handler), `client.py` prints directly to stdout throughout. Every subcommand except `init` is therefore wrapped in a "tee" that duplicates everything printed both to the real console (so an interactive/foreground run - or output redirected to a log file by cron - still sees everything live, exactly as an unwrapped run would) and into an in-memory buffer, used as the body of whichever notification (if any) ends up being sent:

- If the subcommand's exit code indicates a real failure, the generic `error` event fires with that buffer as the body. `retrieve`'s exit code `10` ("certificate not replaced, nothing to do" - `TECHNICAL_REFERENCE.md`'s Section 2.4.4) is explicitly excluded from "real failure" here, same as everywhere else this exit code appears in this manual - only `0` and `10` are non-failures.
- Otherwise, if the subcommand reports one of the named success events from Section 6.2's table (e.g. `client_certificate_retrieved` for a `retrieve` that actually replaced a file, `client_update_installed` for an `update` that actually ran its install command), that event fires with the same captured output as the body.
- Otherwise (a read-only command's success, `retrieve`'s exit `10`, or `update`'s "already up to date" outcome) - nothing is sent at all.

In every case, whether anything actually gets delivered still depends entirely on `client_config.json`'s own `notifiers`/`notification_routing` routing that particular event to at least one notifier (Section 5.2) - there is no flag to enable or disable this behavior, only routing to configure.

One completeness gap worth knowing: this only captures what `client.py`'s own Python code prints - if `retrieve --exec <command>` runs a subprocess that prints directly to its own inherited stdout, that output still reaches the real console/log (nothing is lost), but it isn't included in the notification body, since `--exec`'s subprocess writes to file descriptor 1 directly rather than going through anything `client.py` can intercept at the Python level.

### 10.4. Testing a Notifier

```
scs-server test-notifier --notifier-name <name>
```

Sends one real test message through the named notifier, using whatever's currently saved in `server_config.json` (unlike `admintui`'s Notifiers tab Test button in 10.5, this always reads from disk, not from an in-progress edit). Exits `0` on success, `1` otherwise (including "no such notifier configured").

**There is no `client.py` equivalent.** A `client_config.json` notifier (Section 5.2) can only be exercised by actually triggering `client.py`'s notification path for real - e.g. run any subcommand against a deliberately wrong `--config`/server address (to trigger `error`), or a real `retrieve`/`update` that actually changes something (to trigger the matching success event) - and checking that the configured notifier actually received it.

### 10.5. admintui's Notifiers Tab Test Button

`admintui`'s Notifiers tab (Section 7.8) has a "Test" button on the add/edit form that sends a real test message using whatever's currently in the *form* - **not necessarily what's saved to `server_config.json` yet** - so a new setting (e.g. an SMTP password, or a Pushover token) can be verified before committing to it with "Save". It runs in a background worker thread so the network call (SMTP, or an HTTP request for every other type) never freezes the dashboard, and reports success or failure as a toast notification. It works identically for every notifier type - the same `send_test_notification_for()` function `test-notifier` (10.4) uses.

### 10.6. Logging

A separate, complementary mechanism to everything else in this section - not event-driven admin alerts, but ordinary operational logging (connections, registrations, admin actions, errors). **Every tool** in this project shares one setup (`common/logging_utils.py`'s `setup_tool_logging()`) and the same three possible destinations.

**Console** - always on, for every tool that has one (`admintui`'s Textual UI is the one exception - see below): `2026-01-01 12:00:00 - INFO - ...`, visible via `journalctl -u sslcrtsrv-server`/`sslcrtsrv-acme-server` under `systemd` (Section 4.4) for the two long-running server processes.

**A local rotating log file** - on by default for every tool, one file per tool under `log_dir` (`server_config.json`, Section 5.1 - default `/opt/sslcrtsrv/logs/`, e.g. `crtrequest.log`, `cltmanager.log`, `acme_server.log`), capped at `log_max_bytes` (default 10 MiB) with `log_backup_count` (default 5) rotated-out backups kept. Set `log_dir` to `""` or `false` to disable file logging entirely without touching console/syslog. A directory that can't be created/written (permission trouble, e.g. a non-standard install) degrades to a warning and console/syslog-only logging, never a hard failure. One absolute, configurable, rotated file per tool, the same regardless of what directory a cron job/`admintui`'s subprocess bridge/a manual shell invocation happened to be run from.

**Syslog** - optional, `server_config.json`'s `syslog_host`/`syslog_port`/`syslog_facility`: by default (no `syslog_host` set) logs to the **local syslog daemon** via the standard `/dev/log` Unix domain socket; set `syslog_host` (or `--syslog-host` on `scs-server init`, Section 6.1 - server.py/scs-acme-server only) to log to a **remote** syslog server instead, in which case `syslog_port`/`--syslog-port` (default `514`) applies. `syslog_facility`/`--syslog-facility` (default `daemon`) applies either way - any of Python's `logging.handlers.SysLogHandler` facility names (`daemon`, `local0` through `local7`, `user`, `mail`, `cron`, ...); an unrecognized name falls back to `daemon` with a one-time warning. If the configured destination isn't reachable - no local syslog daemon running (common in minimal containers), or a remote hostname that doesn't resolve - the tool logs one warning and continues with console/file-only output, rather than failing to start over a logging problem. Remote delivery is UDP, matching traditional syslog - "reachable" here only means the hostname resolved, not that anything is actually listening on that port; a remote syslog server that's down or wrong fails silently at the packet level, same as any other UDP-based syslog client. Syslog messages carry a `sslcrtsrv-<tool>[<pid>]:` prefix ahead of the level and message (e.g. `sslcrtsrv-acme_server[1234]: INFO ...`) identifying which tool logged it - Python's `SysLogHandler` doesn't add this itself, unlike the C `syslog()` API's `openlog()` "ident" parameter, so it's added explicitly here for the same effect; the console/file copy of the same messages is timestamped instead, since syslog itself already timestamps entries on arrival.

**`admintui` is the one tool that never logs to console** - its Textual UI owns the terminal, and a stray write to stdout from a log record would corrupt the screen exactly like a stray `print()` already would (Section 7's `util/capture.py` note). It still gets file/syslog logging normally; this is also what gives an admin action taken *from the TUI* (assign/revoke/confirm/etc., via the exact same underlying functions the CLI tools call) the same persistent audit trail a CLI invocation of the identical command already has.

Setup happens once per process, as early as each tool's own config is available - for the two servers, inside their own startup (`Server.__init__()`/`AcmeServer.__init__()`); for `crtrequest.py`/`cltmanager.py`/`crtmanager.py`/`dbmigrate.py`/`admintui`, near the top of each one's `main()`. A config file that fails to load at all (unreadable, invalid JSON) has no logging settings to read, so that one specific startup failure is only ever visible on the console (or, for `admintui`, not at all beyond the printed startup error) - every other error whether that config loaded or not.

### 10.7. Notification Rate Limiting

Caps how many notifications any one *notifier* (by name) may actually send within a rolling time window, so a burst of triggering events - many registrations or certificate requests in a short time, or a genuinely repeating `error` condition not already covered by Section 10.3's separate per-`error_key` 5-minute cooldown, since that one only suppresses repeats of the *same* error, not overall volume - can't flood whatever's on the other end of a notifier: an inbox, a phone, a paid push API with its own quota. This is a distinct, independent mechanism from that per-`error_key` cooldown; both can apply to the same `error` notification.

Configured via two optional `server_config.json`/`client_config.json` keys:

| Field | Type | Default | Notes |
|---|---|---|---|
| `notification_rate_limit` | object | `{"max_notifications": 10, "window_seconds": 300}` | The global default, applied to every notifier that has no more specific override below. `--notification-rate-limit`/`--notification-rate-limit-window` (Section 6.1). |
| `notification_rate_limits` | object | *(absent if none configured)* | `name -> {"max_notifications": N, "window_seconds": W}` - a per-notifier-name override (not per type or event, since the actual rate-limited resource is one specific account/endpoint - two different Pushover notifiers can have two different limits). Either field may be given alone; the other still falls back to the *global* default above, not this module's own hardcoded default, so a custom global window is honored by every override that doesn't set its own. `--notification-rate-limit-for` (Section 6.1, repeatable, upserts one named override). |

The window is a fixed window per notifier, not a sliding one: the first notification after a notifier has been quiet (or has just been created) starts a new window: `window_seconds` later, the count resets to zero regardless of how many notifications landed in between. Within one window, the `max_notifications`-th notification actually sent gets one extra paragraph appended to its body:

> Note: notifier 'NAME' has reached its notification rate limit for the current window - additional notifications may be waiting and will be suppressed until the window resets.

Every notification after that, until the window resets, is suppressed entirely (not sent at all, not queued for later delivery) - only a one-line warning is printed to the server's own console/log for each suppressed attempt. Setting `max_notifications` to `0` or less - globally, or for one specific notifier via `notification_rate_limits` - disables the cap entirely for whatever it applies to.

**Scope**: this is purely in-memory, per-process state, same as Section 10.3's per-`error_key` cooldown - meaningful for the long-running server process (which can accumulate many notifications over its lifetime), but not across separate `crtrequest.py --notify`/`client.py` invocations, each a fresh process starting with empty counters. This isn't a practical gap for those two callers specifically, since each already sends at most one notification per run (Section 10.3) regardless of this feature.

#### 10.7.1. Example

```json
{
  "notification_rate_limit": {"max_notifications": 10, "window_seconds": 300},
  "notification_rate_limits": {
    "ops-pushover": {"max_notifications": 2, "window_seconds": 600},
    "admin-email": {"max_notifications": 0}
  }
}
```

Every notifier defaults to at most 10 notifications per 5 minutes, except `ops-pushover` (at most 2 per 10 minutes - a tighter limit, e.g. for a paid API with its own quota) and `admin-email` (uncapped - email is cheap and an admin may want every single one).

---

## 11. Troubleshooting

### 11.1. Common Error Messages

Exact text, from the actual source - useful for grepping logs.

| Message | Where | Meaning / fix |
|---|---|---|
| `Configuration file <path> not found. Please run 'init' command first.` | `server.py`, `client.py` | The `--config` path doesn't exist yet. Run the tool's `init` (Section 6.1/6.2) before anything else. |
| `Warning: no 'registration_secret' set in server_config.json - client registration will be refused...` | `server.py`, on startup | `server_config.json` predates the registration-secret feature, or was hand-edited without one. Run `scs-server init --registration-secret <secret>` (Section 9.5). |
| `Registration is not enabled on this server` | Server, to a registering client | Same cause as above, seen from the client side. |
| `Invalid registration credentials` | Server, to a registering client | Deliberately the *same* message for every distinct failure - missing fields, a timestamp outside the accepted window, a bad proof, or a replayed nonce (`TECHNICAL_REFERENCE.md`'s Section 2.3.4) - so a would-be attacker can't tell which check failed. Check that the client's `registration_secret` actually matches the server's, and that the client and server clocks aren't far apart. |
| `Client already registered` | Server, to a registering client | That `client_id` already has a public key on file. Pick a different `--client-id`, or resolve the conflict on the server (`cltmanager.py delete`, Section 9.8) first. |
| `Client not registered` / `Client must be confirmed to ...` / `Access denied: Client does not have permission for this certificate` | Server, to any post-registration request | The three access-control layers in order (`TECHNICAL_REFERENCE.md`'s Section 2.4): not registered at all; registered but not confirmed (`cltmanager.py confirm`, Section 9.1); confirmed but not granted this specific FQDNs set - deliberately the same message whether the permission was never granted, was revoked, or has simply passed its own `permission_valid_until` (`TECHNICAL_REFERENCE.md`'s Section 3.3), so as not to hand out extra state to the requesting client. Check `cltmanager.py list <client-id>`/`admintui`'s permissions table for the actual reason (`cltmanager.py assign`/`set_expiry`, Section 9.2). |
| `Could not load DB encryption public/private key from <path>: ... Run 'crtmanager.py init-db-key' once...` | Anything that needs to encrypt/decrypt a certificate private key (`DbKeyMissing`) | The DB-encryption keypair (`TECHNICAL_REFERENCE.md`'s Section 2.3.3) hasn't been generated yet, or this host is missing the half it needs. Run `crtmanager.py init-db-key` where it's missing, or copy the public key file to a host that only ever encrypts (Section 5.4). |
| `Error: no server public key on file for this client - refusing to send this request unencrypted` | `client.py` (`list`/`request`/`info`/`retrieve`) | `client_config.json` doesn't have a `server_public_key` yet - registration was never completed successfully. Run `client.py register` first (`TECHNICAL_REFERENCE.md`'s Section 2.4.1); the client deliberately refuses rather than sending the request unencrypted (`TECHNICAL_REFERENCE.md`'s Section 2.3.2). |
| `Error: no client private key loaded - cannot sign this request` | `client.py` (same commands) | `client_config.json` is missing or missing its `private_key` field - re-run `client.py init`. |
| `'dig' command not found - install the dnsutils (Debian/Ubuntu: bind9-dnsutils) package...` | `crtrequest.py`'s default DNS check, or `--check-dns-only` | Section 2.3.2 - install `bind9-dnsutils`, or pass `--no-check-dns` if the default check genuinely isn't wanted. |
| `DNS check failed for <domain>: no CNAME record found at <name> - add one pointing to <target>` | Same | The CNAME described in `TECHNICAL_REFERENCE.md`'s Section 2.5.1 is missing. Add it and re-check. |
| `CHALLENGE_ALIAS not found in certificate request config - cannot verify DNS delegation` | Same | `crtrequest_config.json` is missing or incomplete (Section 5.3). |
| `acme.sh reported success for <fqdns>, but no certificate file was found in <dir> - treating this as a failure` | `crtrequest.py`, normal issuance | `acme.sh` exited `0` without actually producing `ssl.cer` (Section 8.1.3) - re-run with `--debug-acme` to see what `acme.sh` itself thinks happened. |
| Exit code `10` | `client.py retrieve` | Not an error - the existing certificate file was already as new or newer than the one retrieved, so nothing was overwritten (`TECHNICAL_REFERENCE.md`'s Section 2.4.4). |
| `Could not open GeoIP database '<path>' (backend=<backend>): No module named 'maxminddb'` (or `'IP2Location'`) | `scs-server`/`scs-acme-server`, on startup | The library for the configured `geoip_backend` isn't installed (Section 2.2/9.13) - this does **not** crash the server, unlike a missing `josepy` for `scs-acme-server`; it's logged and notified, and country-based access control is simply disabled until the package is installed and the server restarted. Install `python3-maxminddb` (Debian) or `pip install sslcrtsrv[maxmind]`/`sslcrtsrv[ip2location]`, matching whichever `geoip_backend` is configured. |

### 11.2. Diagnosing DNS and ACME Failures

Follow Section 9.4's order: DNS delegation first (`--check-dns-only`), then `acme.sh` itself (`--debug-acme`), then the DNS provider credentials in `crtrequest_config.json`. A few additional things worth checking specifically:

- **A certificate that "was working, now suddenly fails"** on every renewal attempt, with DNS checking out fine, usually means the PowerDNS API token rotated or expired (Section 9.6) - a DNS delegation check can't detect this, since the CNAME itself is still perfectly correct; only the API behind it has stopped accepting the configured credentials.
- **A wildcard certificate specifically failing** while its paired base domain succeeds (or vice versa) - re-check the *exact* CNAME name for each (`TECHNICAL_REFERENCE.md`'s Section 2.5.1): the wildcard one is `*._acme-challenge.<domain>`, not the stripped-`*.` name a plain, non-delegated DNS-01 setup would expect.
- **`acme.sh`'s own state getting confused after switching staging/production** - `TECHNICAL_REFERENCE.md`'s Section 2.4.5's `force_reissue` logic exists specifically to handle this; if a production request still isn't overwriting an old staging certificate as expected, confirm the certificate's `is_staging` flag actually reflects reality (`crtmanager.py list` shows it) rather than assuming the request's own `--staging` flag alone determines it.

### 11.3. Diagnosing Connectivity Issues

- **Client can't connect at all** (`Error connecting to server: ...`): confirm the server is actually listening (`scs-server` running, correct `--listen`/`--port`), that the client's `server_host`/`server_port` in `client_config.json` are correct, and that nothing in between (firewall, security group) blocks the port. There is no automatic retry (`TECHNICAL_REFERENCE.md`'s Section 2.2.3's note on the unused `retry_with_backoff` helper) - a single failed attempt just fails; wrap it in your own retry loop (e.g. cron's own re-run schedule) if that's needed.
- **Connects, but registration/requests silently fail**: use Section 11.1's table - the server always sends back a specific `message` field in its response, which every `client.py` subcommand prints.
- **A `curl` download of a client package "succeeds" but the file is garbage**: almost always a typo'd package name hitting the plain-text overview page instead of the real file (`TECHNICAL_REFERENCE.md`'s Section 2.2.2) - always use `curl -f`, which fails loudly on that instead of saving the overview page as if it were the real download. Alternatively, downloading via any other HTTP-capable tool, or a browser, is also possible.
- **Nothing happens at all, not even a connection attempt in the server's log**: check whether the connection is actually being misidentified as HTTP or vice versa (`TECHNICAL_REFERENCE.md`'s Section 2.2.1's peek-based protocol multiplexing) - this would only happen from a proxy/load balancer rewriting the very first byte of the connection, which is not a supported deployment topology for this protocol.

### 11.4. Logs and Debug Options

There is no unified logging system - each tool's output behaves differently:

- **The running server process** (`server.py` with no subcommand - i.e. the actual `Server` class, not `init`/`test-notifier`) uses Python's `logging` module: timestamped lines (`2026-01-01 00:00:00 - INFO - ...`) to stdout, plus syslog by default (local `/dev/log`, or a remote server if configured - Section 10.6). Under `systemd`, `journalctl -u sslcrtsrv-server` still shows the same console copy as before (Section 4.4) - syslog is an addition, not a replacement.
- **`server.py init`/`test-notifier`, `crtmanager.py`, `cltmanager.py`, `admintui`, `client.py`**: plain `print()` statements to stdout/stderr, no timestamps, no log file, no syslog. Under `systemd`, this is what `journalctl -u sslcrtsrv-server` shows for anything printed before the server process actually starts listening; run any of these directly in a terminal otherwise.
- **`crtrequest.py`** uses the same unified logging every other tool uses (Section 10.6): timestamped lines sent to console, a fixed rotating log file (`log_dir`/`crtrequest.log`, default `/opt/sslcrtsrv/logs/crtrequest.log`), and syslog if configured - regardless of the current working directory a cron job/`admintui`'s subprocess bridge/a manual shell invocation happened to run it from.
- **`--debug-acme`** (`crtrequest.py`) adds `acme.sh`'s own `--debug` flag, which is by far the most detailed source of information for a genuine ACME/DNS-hook failure - most of what it prints is `acme.sh`'s own, not this project's.

### 11.5. ACME Server-Specific Troubleshooting

- **`scs-acme-server` won't start at all**: check for the two startup checks it performs before anything else (Section 4.6) - `acme_enabled` must be `true`, and `acme_external_url` must be set; both print a specific, actionable message naming exactly which is missing. A separate `ImportError`-based message means the `acme` extra (`python3-josepy`) isn't installed (Section 2.2/4.6).
- **An ACME client's `new-account`/`new-order`/`finalize` request fails with a JSON `urn:ietf:params:acme:error:...` body**: this is RFC 8555's standard problem-details format (`TECHNICAL_REFERENCE.md`'s Section 2.7.4's `verify_acme_jws()`) - the `type`/`detail` fields in the response body name the exact reason (bad nonce, unauthorized, malformed, ...) far more precisely than anything logged server-side; most ACME client libraries print this body directly on failure.
- **`new-order` (or `finalize`) fails with a custom, non-`urn:ietf:...` error `type`**: this project's own error types (as opposed to RFC 8555's standard ones) use plain HTTPS-shaped `type` URLs instead - e.g. an `orderConflict` for a second `finalize` attempt against an FQDNs set another order is already `processing` for (`TECHNICAL_REFERENCE.md`'s Section 2.7.3/3.6's `acme_processing_locks` note).
- **An order stays `processing` far longer than `acme_finalize_retry_after_seconds`**: confirm `crtrequest.py` is actually running on schedule (Section 9.3) and that `acme_enabled` is `true` in whatever `server_config.json` it's reading (Section 6.5's `--config` note) - `crtrequest.py`'s ACME issuance pass is entirely skipped if that flag is unset, exactly like the cleanup pass (Section 4.6 point 4) is. If it is running, treat this exactly like Section 9.4/11.2's DNS/`acme.sh` troubleshooting - `--debug-acme` shows the same underlying `acme.sh --signcsr` invocation the CSR-relay path uses.
- **A real ACME client's own request/retry timeout is shorter than this deployment's `crtrequest.py` cron interval**: some ACME client implementations have a hardcoded client-side timeout on `finalize` shorter than what `Retry-After` alone would suggest is needed (`ACME_SERVER_DESIGN.md` §11 risk 3) - the practical fix is running `crtrequest.py` frequently enough that most clients' own retry succeeds within their patience, not a server-side setting.
- **An ACME client itself refuses to proceed past the `authz`/`chall` step**, reporting an unrecognized challenge `type`: this is the single highest-priority open risk this design carries (`TECHNICAL_REFERENCE.md`'s Section 2.7.4/`ACME_SERVER_DESIGN.md` §11 risk 1) - the authorization object is schema-correct but describes admin approval, not a real challenge, and whether a given client's JSON handling tolerates an unrecognized `type` string even when `status` is already `valid` is untested against every real client. If this happens, it's a genuine architectural limitation of this v1 design, not a misconfiguration - there is no workaround on this server's side today.
- **`cltmanager.py acme_confirm`/`listall` shows an account, but no orders ever appear for it**: confirm the account is actually confirmed (`status='confirmed'`, not `'registered'`) - an unconfirmed account's `new-order` calls are rejected the same way an unconfirmed traditional client's requests are (`TECHNICAL_REFERENCE.md`'s Section 2.4.1's access-control layers apply identically here).
- **A confirmed account suddenly gets `403`/"Account is not yet confirmed" on every request**: check whether it has an IP pin set (`cltmanager.py list <client-id>`, Section 9.10) - a pin mismatch is deliberately indistinguishable from "not confirmed" in the response itself. If it's genuinely coming from behind the reverse proxy, also check `acme_trusted_proxy_ip` (Section 4.6/5.1) is set to that proxy's actual address - otherwise every request appears to originate from the proxy, never matching a pin set to the real client's address.
- **`new-order` fails with `malformed` and a message about a specific identifier value**: basic syntax validation (`TECHNICAL_REFERENCE.md`'s Section 2.7.2's endpoint table) rejected it before an order was ever created - whitespace/control characters, a misplaced or duplicated wildcard, an empty label (a stray double dot), an over-length label/value, or a value that's actually an IP address literal rather than a domain name (`type: "dns"` requires a real DNS name - there is no support for IP-identifier orders at all). The `detail` field names the exact reason.

---

## 12. Appendices

### A. Command-Line Quick Reference

```
scs-server [init | test-notifier] [options]
scs-client <init|register|request|listcerts|info|retrieve|checkversion|listpackages|update> [options]
scs-crtmanager <list|addlocal|update|delete|delete-invalid|warn-stale-downloads|set-provider|init-db-key|migrate-encrypt-keys> [options]
scs-cltmanager <listall|list|registration_command|confirm|acme_confirm|revoke|delete|assign|revoke_permission|set_expiry|clean_requests|set_allowed_ip> [options]
scs-crtrequest [--cert-name FQDNS] [--staging] [--force] [--debug-acme]
               [--no-check-dns | --check-dns-only] [--force-dns-refresh] [--notify] [--config PATH]
scs-admintui
scs-dbmigrate <upgrade-schema | migrate> [options]
scs-acme-server [--config PATH]
python3 build-tarballs.py [--output-dir DIR]
```

Full option/subcommand details: Section 6. Every command also accepts `-h`/`--help` and `--version`.

### B. Exit Codes

| Tool | `0` | `1` | Other |
|---|---|---|---|
| `server.py` | Config exists and was loaded / server shut down normally (`Ctrl+C`) | Missing/invalid config file | `test-notifier`: `0`/`1` for whether the test message actually sent successfully |
| `client.py` | Success; `checkversion`: also `0` if the server is the same version or older | Missing config, connection failure, or any subcommand-reported failure; `checkversion`: **`1`** specifically means the server is newer than this client, not a communication failure | `retrieve`: **`10`** - an existing, still-valid certificate file was left untouched rather than overwritten (`TECHNICAL_REFERENCE.md`'s Section 2.4.4) - not an error |
| `crtmanager.py` | Success (including a bare invocation with no subcommand printing help - see below) | Any reported failure | No subcommand given actually exits `1` (after printing help), the one exception to the "0 on no-op" pattern in this row |
| `cltmanager.py` | The requested operation actually succeeded | Any reported failure - not found, invalid input, or the user declined an interactive yes/no prompt | - |
| `crtrequest.py` | Every certificate processed ended up in a good state | Any certificate failed, or an unhandled exception occurred | - |
| `acme_server.py` | Server shut down normally (`Ctrl+C`) | Missing/invalid `server_config.json`, `acme_enabled` not `true`, `acme_external_url` missing, or the `acme` extra (`josepy`) not installed | - |

Declining an interactive `confirm`/`revoke`/`delete` prompt with "no" exits `1` (nothing was done, same as any other failure) - `crtmanager.py`'s own `delete` command instead treats a declined confirmation as `0`, so the two tools aren't perfectly consistent on this one specific point; `cltmanager.py clean_requests`'s own declined-confirmation path does exit `0`, matching `crtmanager.py`.

---

### C. Status Codes and Constants Glossary

Moved to `TECHNICAL_REFERENCE.md` Section 4.

---

### D. Changelog / Version History

Not duplicated here - `debian/changelog` (Debian's standard format) is the authoritative, actively-maintained history, and `sslcrtsrv.__version__` always matches its topmost entry's upstream version (`TECHNICAL_REFERENCE.md`'s Section 2.6 explains why that's enforced at build time, not just a convention). Read it directly, or `dpkg-parsechangelog` if working from an installed package's source. The public GitHub mirror also carries a generated `CHANGELOG.md` at its root - the same content rendered as plain Markdown, for anyone who'd rather not parse the Debian format directly; `internal/tools/publish_public_repo.py` regenerates it from `debian/changelog` on every publish, so `debian/changelog` remains the one place to actually edit.
