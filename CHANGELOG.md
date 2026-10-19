# Changelog

Generated from `debian/changelog` - see that file for Debian packaging detail omitted here.

## 0.9.8 - 2026-10-19

- admintui: clients tab now highlights stale/unconfirmed clients in yellow (no successful connection/order in 2 months) or red (never connected, or not confirmed)
- added clients.last_connection_ip, tracked for both the traditional protocol and ACME accounts; shown as "Last IP" in admintui's Clients tab and in cltmanager's listall/confirm/revoke/delete output
- admintui: Clients tab headers shortened ("Last connection", "Valid"/ "Invalid"/"Requested" instead of "Certs"-suffixed names)
- access-control deny log lines now name the specific matched subnet (netblock ACL) or resolved country (GeoIP ACL), instead of just listing every config field that could have been involved
- fixed: an address outside a configured allowed_networks/ acme_allowed_networks (but not in denied_networks) no longer bypasses allowed_countries/denied_countries - GeoIP now gets a chance to permit or deny it before access_control_default applies
- added packaging/rpm/sslcrtsrv.spec (client/server split RPM packages, mirroring the existing Debian split) and a GitHub Actions workflow building .deb/.rpm/source tarballs for every tagged release
- fixed: publish_public_repo.py's public export left a dangling man/scs-web-admin-bridge.1 reference in debian/sslcrtsrv-server.manpages, breaking a real .deb build from the exported tree (dh_installman couldn't find the export-ignored file)
- fixed: the release.yml RPM build job ran `git archive` against a checkout with no .git directory, since fedora:latest has no git preinstalled and actions/checkout silently falls back to a non-git download without it - git is now installed before checkout runs

## 0.9.7 - 2026-10-19

- added scs-cltmanager registration_command, printing the exact scs-client init/register command lines (with this server's own address/port/registration secret filled in) for onboarding a new client, instead of typing them by hand
- fixed: FQDNs quoted as one shell argument with spaces instead of commas (e.g. scs-client request "a.com b.com") were treated as a single bogus domain and silently failed to match an existing certificate, creating a duplicate request instead - affected request/info/retrieve, the server's own request handlers, and cltmanager's assign/revoke_permission/set_expiry
- Removed redundant message in scs-client when connecting to the server

## 0.9.6 - 2026-10-18

- added GeoIP country-level allow/deny access lists for scs-server and scs-acme-server (allowed_countries/denied_countries, acme_allowed_countries/acme_denied_countries), resolved against a user-provided MaxMind DB or IP2Location database (geoip_backend/geoip_database_path); an explicit netblock allow/deny verdict always takes priority over GeoIP, and access_control_default/acme_access_control_default sets the fallback ("allow" or "deny") when neither has an opinion

## 0.9.5 - 2026-10-18

- restructured repo for public release: internal-only docs moved under internal/, server_config.json/keysrv.db no longer tracked in git
- added LICENSE (FSL-1.1-ALv2)
- added internal/tools/publish_public_repo.py to publish curated public releases to GitHub
- web_admin (not yet functional) and its backend bridge are excluded from the public release
- fixed public GitHub repo references to point at GarryG/sslcrtsrv
- fixed .gitattributes export-ignore so excluded directories don't leave empty entries in the public export

## 0.9.4 - 2026-10-11

- added diagnostic logging for ACME orders stuck pending/never finalizing
- changed: an fqdns can now be managed independently by both the traditional protocol and ACME at once, each with its own certificate (previously mutually exclusive)
- ACME server now logs the fqdns of every new-order request

## 0.9.3 - 2026-09-27

- added netblock allow/deny access lists gating both scs-server and scs-acme-server's ports (allowed_networks/denied_networks, acme_allowed_networks/acme_denied_networks), with an option for the ACME list to check the real client's forwarded address instead of the reverse proxy's own
- added source-IP-based lockout after repeated authentication failures on scs-server, scs-acme-server, and the web admin login
- fixed a TOCTOU race in traditional-protocol nonce consumption
- added SSLCRTSRV_DB_PASSWORD as an opt-in alternative to a plaintext DB password in server_config.json
- added systemd hardening (NoNewPrivileges, ProtectSystem=strict, etc.) to both service units
- added X-Frame-Options/CSP headers and pinned/scanned dependencies (pip-audit in CI)

## 0.9.2 - 2026-09-20

- added trusted-client auto-approval for ACME: an admin can pre-issue an EAB or contact-token credential (cltmanager acme_create_eab_grant / acme_create_contact_token_grant) that auto-confirms an account and auto-approves matching fqdns, skipping acme_confirm/assign entirely
- fixed scs-acme-server's access log always showing the reverse proxy's own address instead of the real client - now honors X-Forwarded-For when acme_trusted_proxy_ip is set, same trust boundary as IP-pinning
- fixed check_schema_is_current() only checking for one past migration's column, letting init_database() silently half-upgrade a stale database on the next two migrations - now derived from scs-dbmigrate's own single up-to-date revision list instead of a second, easily-forgotten one
- unified logging across every tool: console/rotating-log-file/syslog now all go through one shared setup (new log_dir/log_max_bytes/ log_backup_count config fields), replacing crtrequest.py's own unrotated, CWD-relative crtrequest.log and giving cltmanager/ crtmanager/dbmigrate/admintui a persistent audit trail they never had

## 0.9.1 - 2026-09-16

- added ACME support to admintui: Clients tab shows a Type column and an ACME account's orders instead of a fingerprint; Certificates tab shows ACME vs traditional origin; Requests tab shows outstanding ACME orders with a cancel-order action
- added cltmanager acme_cancel_order to unblock a stuck/dead ACME order on demand instead of waiting for its automatic expiry

## 0.9.0 - 2026-09-16

- added scs-acme-server: optional RFC 8555 ACME protocol server for issuing certificates to third-party ACME clients (requires the new `acme` extra / python3-josepy)
- fixed scs-acme-server (and the classic server) using a TCP accept backlog of only 5, causing connections to stall indefinitely behind a reverse proxy under load
- fixed init_database() letting create_all() run against an unmigrated database, corrupting its schema into a state scs-dbmigrate couldn't cleanly recover from
- fixed an ACME renewal silently resetting an already-approved fqdns permission back to pending, requiring the admin to re-approve every single renewal

## 0.8.4 - 2026-09-14

- client.py notifications changed to routing settings as in the server config
- added man pages via debian/*.manpages for the .deb and share/man/man1/ in the generic tarballs

## 0.8.3 - 2026-09-15

- added client.py listpackages, build-embedded package-type auto-detection, and client_config.json presets so update needs fewer (or no) flags
- added real anti-replay protection (nonce+timestamp) to every client-server request, not just registration - closes a gap where a captured retrieve request could be replayed to fake a fresh download

## 0.8.2 - 2026-09-14

- changed crtmanager/admintui certificate listing to sort soonest-to-expire first instead of latest-to-expire first
- added client/server version advertisement - the server records each client's reported version, shown in cltmanager/admintui's client views, and client.py gains a checkversion command
- added crtmanager warn-stale-downloads: reports clients still running a downloaded certificate that's expiring, already renewed, or never fetched at all
- fixed client retrieve --combined (without --cert/--all) always overwriting instead of honoring the not-actually-newer check

## 0.8.1 - 2026-09-12

- fixed scs-dbmigrate migrate building an invalid connection URL for mysql/postgresql targets
- fixed scs-dbmigrate crashing with a raw traceback on a missing pymysql/psycopg2 driver or an unreachable target - now a clear error
- fixed scs-dbmigrate migrate aborting on a pre-existing orphaned client_certificate_relations row - now skipped and reported instead
- fixed a SAWarning during the certificates.id schema upgrade
- fixed a client's certificate request crashing on MySQL/PostgreSQL with a foreign key violation on client_certificate_relations
- fixed cltmanager assign-permission crashing the same way when granting access for a not-yet-issued certificate
- fixed crtrequest silently recording a fake 2020-01-01 validity date for a genuinely-issued certificate whenever the real date couldn't be extracted - now fails loudly instead of storing it
- fixed crtrequest never applying a configured mysql/postgresql backend - it silently kept using the default sqlite database on every run, so real issuance data never reached a migrated network database
- Manual updates: fresh MySQL/PostgreSQL setup walkthrough, scs-dbmigrate migrate's error handling

## 0.8.0 - 2026-08-31

- added pluggable database backends: MySQL/MariaDB and PostgreSQL, alongside the existing SQLite default
- added scs-dbmigrate for schema upgrades and cross-backend data migration
- added a real certificates.id primary key, replacing the SQLite-only rowid
- added a database backend selector to admintui's Config tab
- fixed debian/rules leaving stale egg-info from prior builds, which could break newly-added console scripts (e.g. scs-dbmigrate) on install

## 0.7.3 - 2026-08-31

- fixed cltmanager.py confirm reading the wrong server_config.json on a non-default --config; added --config to fix it

## 0.7.2 - 2026-08-31

- fixed: stalled HTTP requests weren't counted towards abuse tracking
- removed the unused legacy public_key_fingerprint protocol field
- added human-readable word-list rendering of public-key fingerprints

## 0.7.1 - 2026-08-30

- fixed double-click on notifier in admintui to open edit window

## 0.7.0 - 2026-08-30

- added a configurable per-notifier notification rate limit, overridable globally and per notifier name/window
- reduced the maximum TCP message size limit from 5MB to 2MB
- removed the legacy single-email notification configuration in favor of the general notifiers/notification_routing schema
- added a Notifiers tab to admintui for adding/editing/deleting any notifier type, event routing, and rate-limit overrides from the dashboard, replacing the old fixed-name email-only Config tab section
- Manual updates for all the changes
- reduced the README to essential project information, pointing to the manual for architecture, installation, and configuration details

## 0.6.0 - 2026-08-29

- added support for listening on multiple additional addresses/ports (bind_also)

## 0.5.0 - 2026-08-29

- added IP blocks when HTTP requests for unknown URLs occur

## 0.4.2 - 2026-08-23

- added syslog output to server
- removed original email notification implementation
- update admintui to use the new style email notification
- update to manual to show examples for different notification services

## 0.4.1 - 2026-08-22

- added notification features to client

## 0.4.0 - 2026-08-22

- API support for notification services
- selection of used notification service per type
- fix of scrolling in admintui Maintenance tab

## 0.3.0 - 2026-08-22

- Changes in the manual
- fixed issue #5 - permissions bug on initial server.py w/o prior init
- fixed issue #6 - datadir not honored at all places
- fixed issue #7 - last client connect timestamp et al.
- new feature - issue #8, allow for expiration date for access to a certificate
- fixed issue #9 - silent client delete when no certs are assigned
- fixed issue #11 - cltmanager always returning 0 even after errors
- fixed issue #12 - removed falback to unencrypted communication in case remote pubkey is missing
- comprehensive security audit of http functionality of the server (issue #13) - problems found
- fixed the missing socket timeout in HTTP
- fixed possible message bomb issue in HTTP that could cause DoS / memory exhaustion - size limit for messages
- added wrapper scripts for python packages for tar package distribution

## 0.2.5 - 2026-08-19

- reversed DNS check logic on crtrequest - DNS checks are now done by default
- added option to only do DNS check without actual acme.sh calls
- fixed bug in admintui/crtrequest when first attempt to request a new certificate via acme.sh fails
- fixed formatting of client list in crtmanager

## 0.2.4 - 2026-08-18

- added option --check-dns to crtrequest to only check for correct DNS CNAME entries without actually requesting any certificates via acme.sh
- added option in admintui to also support the check-dns option

## 0.2.3 - 2026-08-17

- When a request of a new certificate fails, the certificates wasn't shown in the "Requests" tab of admintui anymore - fixed
- crtmanager output for "list --clients" printed out the client name in the wrong column

## 0.2.2 - 2026-08-15

- added DNS-check for certificates to be renewed by acme.sh - checks for CNAME entries of the form *._acme-challenge or _acme-challenge[.host] in the domain

## 0.2.1 - 2026-08-14

- Server process now checks for changes of server config file, reloads
- added email test button in admintui config

## 0.2.0 - 2026-08-12

- Implemented client package delivery in the server

## 0.1.0 - 2026-08-10

- Initial Debian packaging: sslcrtsrv-client and sslcrtsrv-server, built from the sslcrtsrv Python distribution (pyproject.toml).
- Console scripts installed as scs-* (scs-client, scs-server, scs-crtmanager, scs-cltmanager, scs-crtrequest, scs-admintui, scs-web-admin-bridge) rather than the longer sslcrtsrv-* prefix.
- setup.cfg's version now reads src/sslcrtsrv/__init__.py's __version__ directly (attr:) instead of duplicating it, and debian/rules refuses to build if this changelog's upstream version doesn't match __version__ - catches a bumped __version__ with a forgotten `dch` at build time instead of silently shipping a stale-versioned .deb.
