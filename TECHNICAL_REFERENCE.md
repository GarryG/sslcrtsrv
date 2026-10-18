# SSLCrtSrv Technical Reference

*Version: 0.9.5 / Last Update: 2026-10-18* 

This document holds the technical/background material split out of `Manual.MD` - protocol internals, the encryption model, the database schema, and the comparison against alternative approaches. None of it is needed for day-to-day installation, configuration, or administration (see `Manual.MD` for that) - it exists for anyone extending this codebase, auditing its security properties, evaluating it against alternatives, or otherwise needing to understand *why* and *how* it works rather than just *how to run it*.

For the ACME (RFC 8555) server specifically, Section 2.7 below is a concise architectural summary only - `ACME_SERVER_DESIGN.md` at the repository root is the authoritative, exhaustive design document (protocol flow byte-for-byte, every endpoint's exact behavior, the full concurrency analysis, and the complete list of open risks); this section exists so the rest of this document's narrative about the system's architecture doesn't have a hole where ACME belongs, not to duplicate that document.

Cross-references to `Manual.MD` and `ACME_SERVER_DESIGN.md` are called out explicitly by filename throughout; a bare "Section X.Y" always means a section of this document.

## Table of Contents

- [1. Comparison with Alternative Approaches](#1-comparison-with-alternative-approaches)
  - [1.1. Local ACME Clients (acme.sh, Certbot)](#11-local-acme-clients-acmesh-certbot)
  - [1.2. Configuration-Management-Driven ACME (Ansible, Puppet, Chef, Salt)](#12-configuration-management-driven-acme-ansible-puppet-chef-salt)
  - [1.3. Reverse-Proxy/Edge Automatic HTTPS (Caddy, Traefik)](#13-reverse-proxyedge-automatic-https-caddy-traefik)
  - [1.4. Kubernetes cert-manager](#14-kubernetes-cert-manager)
  - [1.5. Internal/Private PKI (step-ca, HashiCorp Vault's PKI Engine, Active Directory Certificate Services)](#15-internalprivate-pki-step-ca-hashicorp-vaults-pki-engine-active-directory-certificate-services)
  - [1.6. Traditional Manual Issuance and Distribution](#16-traditional-manual-issuance-and-distribution)
  - [1.7. SSLCrtSrv, for Comparison](#17-sslcrtsrv-for-comparison)
  - [1.8. Summary Comparison Table](#18-summary-comparison-table)

- [2. Architecture and Technical Design](#2-architecture-and-technical-design)
  - [2.1. Component Overview and Interaction](#21-component-overview-and-interaction)
  - [2.2. Client/Server Network Protocol](#22-clientserver-network-protocol)
    - [2.2.1. Custom Binary Protocol](#221-custom-binary-protocol)
    - [2.2.2. HTTP Piggyback Protocol (Client Package Delivery)](#222-http-piggyback-protocol-client-package-delivery)
    - [2.2.3. Message Types and Exchange Flows](#223-message-types-and-exchange-flows)
    - [2.2.4. Message Schemas and Field Reference](#224-message-schemas-and-field-reference)
  - [2.3. Encryption and Security Model](#23-encryption-and-security-model)
    - [2.3.1. Server Identity Keypair](#231-server-identity-keypair)
    - [2.3.2. Message Signing and Encryption in Transit](#232-message-signing-and-encryption-in-transit)
    - [2.3.3. Database Encryption at Rest](#233-database-encryption-at-rest)
    - [2.3.4. Registration Secret and Anti-Replay Protection](#234-registration-secret-and-anti-replay-protection)
    - [2.3.5. File and Directory Permission Model](#235-file-and-directory-permission-model)
    - [2.3.6. Protocol Security Analysis: Impersonation Resistance and Malformed-Input Handling](#236-protocol-security-analysis-impersonation-resistance-and-malformed-input-handling)
  - [2.4. Certificate Lifecycle](#24-certificate-lifecycle)
    - [2.4.1. Client Registration and Confirmation](#241-client-registration-and-confirmation)
    - [2.4.2. Certificate Request and Admin Approval](#242-certificate-request-and-admin-approval)
    - [2.4.3. ACME Issuance via acme.sh](#243-acme-issuance-via-acmesh)
    - [2.4.4. Certificate Retrieval and Client-Side Storage](#244-certificate-retrieval-and-client-side-storage)
    - [2.4.5. Renewal, Expiry, and Staging/Production Handling](#245-renewal-expiry-and-stagingproduction-handling)
  - [2.5. DNS-01 Delegation Design](#25-dns-01-delegation-design)
    - [2.5.1. CNAME Delegation Scheme](#251-cname-delegation-scheme)
    - [2.5.2. DNS Verification (default / --no-check-dns / --check-dns-only)](#252-dns-verification-default---no-check-dns---check-dns-only)
  - [2.6. Configuration Live-Reload and Versioning](#26-configuration-live-reload-and-versioning)
  - [2.7. ACME (RFC 8555) Server Interface](#27-acme-rfc-8555-server-interface)
    - [2.7.1. Two Parallel Interfaces, One Shared Database](#271-two-parallel-interfaces-one-shared-database)
    - [2.7.2. Protocol Flow and Endpoints](#272-protocol-flow-and-endpoints)
    - [2.7.3. Data Model](#273-data-model)
    - [2.7.4. Security Model and Deliberate Simplifications](#274-security-model-and-deliberate-simplifications)
    - [2.7.5. Trusted-Client Auto-Approval (EAB / Contact-Token Grants)](#275-trusted-client-auto-approval-eab-contact-token-grants)

- [3. Database Schema](#3-database-schema)
  - [3.1. clients](#31-clients)
  - [3.2. certificates](#32-certificates)
  - [3.3. client_certificate_relations](#33-client_certificate_relations)
  - [3.4. used_nonces](#34-used_nonces)
  - [3.5. Pluggable Database Backends](#35-pluggable-database-backends)
  - [3.6. ACME Tables: acme_orders, acme_certificates, acme_processing_locks, acme_nonces](#36-acme-tables-acme_orders-acme_certificates-acme_processing_locks-acme_nonces)
  - [3.7. acme_trust_grants](#37-acme_trust_grants)

- [4. Status Codes and Constants Glossary](#4-status-codes-and-constants-glossary)

---

## 1. Comparison with Alternative Approaches

SSLCrtSrv is one of several established ways to solve the certificate lifecycle problem described in `Manual.MD`'s Section 1.1, not the only one. This section is a neutral technical comparison, written to help decide what actually fits a given environment - not to argue for SSLCrtSrv over the alternatives. Every solution below, including SSLCrtSrv itself, is described with its genuine strengths and weaknesses; several of SSLCrtSrv's own limitations noted here are real, current gaps (cross-referenced to where they're discussed in more detail elsewhere in this manual), not hedged-sounding boilerplate. None of these approaches are mutually exclusive - it's common, and often correct, for one organization to use several of them at once for different parts of its estate (e.g. a Kubernetes cluster's own `cert-manager` alongside SSLCrtSrv or Ansible for everything outside that cluster).

Each subsection below covers: what the approach is, its **Strengths**, its **Weaknesses**, the situations it's a particularly good fit for (**Opportunities**), and the situations where it tends to become a liability (**Risks**).

### 1.1. Local ACME Clients (acme.sh, Certbot)

Running `acme.sh` or Certbot directly on the host that needs the certificate - the most common starting point, and what most sysadmins reach for first. Issuance uses either HTTP-01 (the host serves a challenge file over plain HTTP) or DNS-01 (the host holds credentials for the DNS provider's API directly).

**Strengths**
- Minimal moving parts - no server component, no custom protocol, nothing extra to run or secure beyond the client tool itself.
- Extremely mature, distro-packaged, enormous community and documentation; the default choice for a reason.
- Direct control and immediate feedback - the host requesting the certificate is the host using it.
- Certbot in particular has plugins for many web servers that handle reload/reconfiguration automatically.

**Weaknesses**
- Every host needs either public HTTP reachability (HTTP-01) or its own copy of DNS API credentials (DNS-01) - exactly the two constraints `Manual.MD`'s Section 1.1 identifies as not always acceptable (mail servers, internal appliances, a security policy that refuses to hand out DNS-write credentials to every host).
- HTTP-01 specifically requires the host to be genuinely, inbound-reachable at the domain's own address at the moment the CA validates the challenge - a host behind NAT with no port forwarding, on a carrier-grade-NAT/dynamic IP connection, or otherwise firewalled off, cannot use HTTP-01 at all without also solving that separate reachability problem (port forwarding, a static IP, dynamic DNS, or a tunnel/VPN). DNS-01 mode has no such requirement - it only needs *outbound* connectivity from the host to the CA and the DNS provider's API - so a NAT'd/dynamic-IP host can still use `acme.sh`/Certbot in DNS-01 mode, provided it's still willing to hold DNS API credentials directly (the separate concern above).
- No central inventory: across dozens or hundreds of hosts, each manages its own renewal state independently - answering "what's expiring, where" needs external tooling or manually checking each host.
- No central authorization concept - anything holding the DNS/API credentials, or reachable for an HTTP-01 challenge, can obtain a certificate for that name. Fine when one organization controls its own zone; a real problem for a reseller issuing certificates on behalf of many independent customers (`Manual.MD`'s Section 1.1), since it means giving each customer's host some form of access to the issuing infrastructure.
- Renewal is typically a per-host cron job/systemd timer; a fleet-wide change (e.g. rotating a DNS provider token) means touching every host individually.

**Opportunities**
- A single organization with one DNS zone under its own control, and hosts that can either serve HTTP-01 or safely hold DNS credentials directly. The right, simplest choice for small-to-medium fleets with no reseller/multi-tenant angle.

**Risks**
- Scales poorly, operationally and from a security/blast-radius standpoint, as host count - and especially the number of independent trust domains (e.g. distinct customers) - grows. DNS/API credentials copied to every host are a large, hard-to-audit attack surface; a single compromised host holding a zone-wide token can potentially affect every name in that zone, not just its own.

### 1.2. Configuration-Management-Driven ACME (Ansible, Puppet, Chef, Salt)

The same underlying ACME mechanics as 1.5.1, but orchestrated centrally from a configuration-management tool - e.g. Ansible's `community.crypto.acme_certificate` module, or an equivalent Puppet/Chef/Salt module - typically templated per host or per role from one repository.

**Strengths**
- Centralizes the *definition* of what should exist (which hosts get which certificates) in one auditable, version-controlled place - a real improvement over 1.5.1's per-host drift.
- Reuses infrastructure and skills many organizations already have: existing inventory, existing CI/CD, existing secrets integration (Ansible Vault, a HashiCorp Vault lookup plugin, etc.) rather than adding a new bespoke system.
- Can apply the certificate as part of a larger configuration run - templating server config and restarting services in the same pass a new certificate is issued.
- Push-based - the target host itself needs no public exposure and no need to reach any central certificate service; only the control node needs a path (its usual management access, SSH/WinRM) to the target.

**Weaknesses**
- Still fundamentally per-host DNS-01/HTTP-01 issuance under the hood in most common setups - if the playbook run gives the target host the DNS credentials to issue for itself, this improves 1.5.1's *tracking* but not its *credential-distribution* problem. (Centralizing issuance on one delegate host and pushing only the result is possible but isn't how these modules are typically used, and moves closer in spirit to SSLCrtSrv's own model.)
- The push model's "no public exposure needed" strength above has a mirror-image cost: the *control node* still needs an inbound path (SSH/WinRM) to every managed host, at the moment it needs to run. A target behind NAT with no port forwarding, on a dynamic/unpredictable IP, or otherwise not directly reachable from wherever the control node lives, breaks this just as thoroughly as it breaks HTTP-01 (1.5.1) - the fix (a site-to-site VPN, a reverse tunnel, a mesh network like Tailscale/WireGuard, or switching to a pull-based agent like `ansible-pull`/a Puppet/Salt agent polling outward instead) is itself extra infrastructure to build and keep running, not something these tools solve by default. This is a common real obstacle for exactly the reseller/MSP-to-customer-premises scenario in `Manual.MD`'s Section 1.1, where the customer's equipment is frequently NAT'd, on a residential/dynamic-IP-style connection, or simply not something the provider controls the network path to.
- Renewal only happens when the playbook actually runs - a scheduled job (cron-triggered `ansible-playbook`, an AWX/Tower/Semaphore job, a CI pipeline) has to be built and maintained separately; nothing watches expiry dates and triggers a run proactively.
- Requires the CM tool's own control-plane trust and connectivity to every managed host - itself a security surface, and a broader one than a purpose-built protocol needs to be (Section 2.3). In a service-provider/customer relationship specifically, this typically means asking the customer to grant SSH/WinRM (i.e. effectively administrative) access to their systems - a level of access many customers are unwilling or contractually unable to hand to a third party, independent of whether the connectivity problem above is even solved.
- Per-client authorization is whatever the playbook/inventory logic encodes - flexible, but expressed in general-purpose CM/YAML/templating rather than a dedicated permission model; auditing "why does host X have access to certificate Y" means reading playbook and inventory logic rather than checking one purpose-built table (Section 3.3).
- No built-in at-rest encryption of private keys beyond whatever the CM tool's own secrets handling provides.

**Opportunities**
- Organizations already running Ansible/Puppet/Chef/Salt at scale for general configuration, with a mature secrets-management story, that would rather fold certificate issuance into that existing workflow than run a separate system.

**Risks**
- The "just run it more often" scheduling model can silently stop actually renewing - a broken cron entry, a decommissioned control host, a quietly-failing CI job - with no dedicated monitoring for that specific failure mode unless someone builds it.

### 1.3. Reverse-Proxy/Edge Automatic HTTPS (Caddy, Traefik)

The web-facing edge component requests and renews its own certificates automatically (usually HTTP-01 or TLS-ALPN-01), transparently to whatever runs behind it.

**Strengths**
- Effectively zero operational overhead once configured - often literally no extra configuration beyond stating the hostname.
- No separate certificate-management system, database, or protocol to run or secure - the edge server already had to run; this is a feature of it, not an addition.
- An excellent fit for many independent web-facing services with minimal ceremony - a strong default for small teams, homelabs, and many production deployments alike.

**Weaknesses**
- Only solves the problem for whatever terminates TLS at that exact proxy/edge - not applicable to non-HTTP services (mail servers, internal appliances, database TLS, embedded/IoT devices) or to a certificate that a fleet of *other*, non-proxy hosts each need for their own purposes.
- No central inventory, no cross-host authorization model, no distribution beyond the proxy instance itself - the certificate lives and dies with that one component's own state.
- Typically HTTP-01/TLS-ALPN-01 only, needing the edge itself to be the publicly, inbound-reachable endpoint for the domain at validation time - exactly the constraint DNS-01-based approaches (including SSLCrtSrv) exist to route around, and one a NAT'd or dynamic-IP deployment can't satisfy without also solving that reachability problem separately (port forwarding, dynamic DNS, a tunnel). Some of these tools (e.g. Caddy) also support DNS-01 via provider plugins as a workaround, which sidesteps the reachability issue but reintroduces 1.5.1/1.5.2's DNS-credential-distribution question on the edge device itself.
- Multiple independent edge instances issuing for overlapping or shared domains have no coordination unless the tool provides its own shared-storage/clustering feature for it - itself extra infrastructure to run.

**Opportunities**
- Web-facing services where the reverse proxy/load balancer is already the natural TLS termination point, and nothing else in the fleet needs the same certificate material.

**Risks**
- Organizations that start here for the easy web case and later find they need certificates for non-HTTP services anyway, ending up bolting on a second, unrelated mechanism just for those - worth considering up front if that need is foreseeable.

### 1.4. Kubernetes cert-manager

The Kubernetes-native equivalent of 1.5.3: a cluster-resident controller watching `Certificate` custom resources, driving ACME (or an internal CA, or Vault) issuance, and storing the result as a Kubernetes `Secret` for pods to mount.

**Strengths**
- Deeply integrated with Kubernetes' own reconciliation model - a `Certificate` resource, its renewal, rotation, and consumption by an Ingress or pod all follow the same patterns as everything else in the cluster.
- Mature and widely adopted, with many supported issuers (ACME, Vault, a private CA, self-signed) behind one consistent API.
- Strong ecosystem integration (Ingress controllers, ExternalDNS, and others build directly on it).

**Weaknesses**
- Kubernetes-only - not applicable to bare-metal/VM fleets, network appliances, or anything outside a cluster, which is SSLCrtSrv's actual target environment.
- Brings the full operational surface of running a Kubernetes controller (RBAC, CRDs, its own upgrade cadence) purely for certificate automation, if a cluster doesn't already exist for other reasons.

**Opportunities**
- Any organization already running Kubernetes and wanting certificates for in-cluster workloads - close to the default choice there.

**Risks**
- Not a realistic alternative outside its own ecosystem - included here mainly to note that "certificate lifecycle is the platform's job" is usually the right call *when* that platform is already in use, and a poor one otherwise.

### 1.5. Internal/Private PKI (step-ca, HashiCorp Vault's PKI Engine, Active Directory Certificate Services)

A self-hosted or managed private certificate authority issuing certificates trusted only within an organization's own trust store - not publicly trusted by browsers/clients by default - typically consumed via the CA's own API, an ACME-compatible endpoint, or a short-lived-certificate workflow.

**Strengths**
- Purpose-built for internal-only trust (service-to-service mTLS, internal web UIs, VPN/device certificates), a genuinely different problem from obtaining a publicly-trusted certificate.
- Can issue very short-lived certificates tied to strong workload/machine identity (e.g. SPIFFE/SPIRE integration with step-ca or Vault) - a capability none of the public-CA-oriented tools in this comparison attempt.
- Full control over CA policy, certificate lifetimes, and revocation, with no dependency on an external CA's rate limits or availability.

**Weaknesses**
- Solves a different problem than public-trust issuance: an internal CA's certificates aren't accepted by the public Internet or ordinary browsers unless its root is deliberately trusted everywhere it's needed - a real, separate distribution problem (trust-store management across every consuming client).
- Running a CA, even a small internal one, carries real operational and security responsibility (root/intermediate key protection, revocation infrastructure, audit trail) that's easy to underestimate.
- Doesn't, by itself, address the "give a fleet of independently-administered hosts controlled, authenticated access to specific *public* certificates" problem SSLCrtSrv targets - it's a different tool for a different (internal-trust) half of the overall certificate landscape, often used *alongside* a public-CA solution rather than instead of one.

**Opportunities**
- Internal service-to-service TLS, service meshes, VPN/device identity - anywhere the certificates are genuinely never meant to be publicly trusted.

**Risks**
- Conflating "we need internal PKI" with "we need public certificate fleet management" leads to picking the wrong tool for half the actual requirement - many organizations end up needing both, for different purposes, not one instead of the other.

### 1.6. Traditional Manual Issuance and Distribution

The pre-automation baseline: a human generates a CSR, obtains a certificate from a public or internal CA, and manually distributes the resulting files (email, SFTP, a manual copy).

**Strengths**
- No tooling investment or new infrastructure at all - works with nothing beyond a CA relationship and basic file transfer.
- Full human review of every issuance - a deliberate control point for organizations wanting a person to approve every single certificate rather than trusting an automated flow.
- No dependency on ACME/DNS-01 automation working correctly for exotic or legacy environments that don't fit any automated tool well.
- Straightforward path to commercial-CA-specific features (extended validation, code-signing certificates, vendor-specific requirements) that ACME-based approaches - including SSLCrtSrv - generally don't cover at all.

**Weaknesses**
- Doesn't scale past a handful of certificates/renewals a year without becoming a recurring, error-prone workload - the exact pain point motivating this project's Introduction (`Manual.MD`'s Section 1.1), worsening sharply as maximum certificate lifetimes shrink toward 47 days.
- No enforced expiry tracking beyond whatever calendar reminders or spreadsheets a human maintains - a missed renewal is a silent outage waiting to happen.
- Manual transfer of private key material is itself a security concern if not handled carefully (unencrypted email, casual file shares).

**Opportunities**
- Very small deployments (a handful of long-lived certificates), certificates needing commercial-CA-specific features ACME can't provide, or an organizational policy genuinely requiring human sign-off on every issuance.

**Risks**
- Viable at small scale, and actively risky (in terms of outage exposure) at any scale beyond it - a risk that keeps growing as certificate lifetimes continue shrinking industry-wide.

### 1.7. SSLCrtSrv, for Comparison

Held to the same standard as the sections above - genuine strengths, and equally genuine, current weaknesses.

**Strengths**
- A dedicated central inventory plus a purpose-built, per-client/per-FQDNs-set authorization model (Section 2.4.2/3.3) - not implicit in DNS/API credential possession, or in general-purpose CM/inventory logic.
- **Multi-client/multi-customer support built on that same authorization model, not bolted on separately**: because every certificate grant is a `client_certificate_relations` row scoped to one specific, individually-authenticated client and one specific FQDNs set (Section 3.3), one server can serve any number of independently-administered clients - including mutually distrusting ones, such as an ISP's separate customers - side by side, with each client only ever able to see or retrieve the certificates an administrator explicitly granted it. A client can never enumerate, request status on, or retrieve any FQDNs set it hasn't itself been authorized for (Section 2.4's three-layer access check: registered -> confirmed -> granted), so nothing about this "rights system" depends on customers trusting each other or the hosting party trusting every customer host equally - each relationship is independently confirmed (Section 2.4.1) and independently revocable (`cltmanager.py revoke_permission`/`revoke`, `Manual.MD`'s Section 9.8) without affecting any other client's access.
- No DNS-provider or ACME-account credentials ever need to leave the server - client hosts only ever hold a purpose-built, mutually-authenticated protocol keypair (Section 2.3), directly addressing 1.5.1's credential-distribution concern for the reseller/many-independent-hosts case described in `Manual.MD`'s Section 1.1.
- Works for any TCP-reachable host, not just HTTP-facing ones or hosts on a specific platform (unlike 1.5.3/1.5.4).
- Works behind NAT, on a dynamic IP, or otherwise not directly reachable from the server at all - no inbound access, port forwarding, static/dynamic-DNS address, or VPN/tunnel is ever needed. The client always *initiates* the outbound TCP connection to the server (Section 2.2) - the server never connects to, or needs a route to, the client. This is the flip side of 1.5.1's HTTP-01 reachability problem and 1.5.2's/1.5.3's push/control-node reachability problem (both discussed above): a customer-premises box behind carrier-grade NAT, a residential/dynamic-IP connection, or a firewall the provider doesn't control can still register, request, and retrieve certificates normally, as long as it can reach out to the server on one TCP port.
- Never requires the server operator to be granted SSH, WinRM, or any other form of administrative access to the client host, unlike push-based CM tooling (1.5.2) or a manual "log in and install it" workflow - the only thing ever installed on the client side is `client.py` itself and its own narrow protocol keypair (Section 2.3), which can retrieve certificates but cannot reach, modify, or execute anything else on that host. For a service-provider/customer relationship specifically (the ISP scenario in `Manual.MD`'s Section 1.1), this means a customer can receive automated certificate updates without handing the provider any broader access to their systems than that - directly answering the trust concern 1.5.2's push model runs into.
- Works for domains with **no public reachability at all**, not just NAT'd/dynamic-IP ones - because issuance is exclusively DNS-01 via the CNAME-delegation scheme (Section 2.5.1), the certified name never has to resolve to anything reachable, or even have an A/AAAA record at all. A purely internal hostname (split-horizon DNS, a private-network-only address, or no address published outside the organization whatsoever) can still receive a real, publicly-trusted certificate, as long as its zone's delegated challenge subdomain is itself publicly resolvable (Section 2.5.1's "consequence worth stating explicitly" note) - something HTTP-01/TLS-ALPN-01-based approaches (1.5.1's HTTP-01 mode, 1.5.3, and 1.5.4's default ACME issuers) cannot do at all, regardless of NAT/firewalling, since those challenge types require the CA to connect to the name's own address directly.
- The client itself needs no elevated privileges of its own to run, either: `client.py` only ever opens a plain outbound TCP connection and reads/writes whatever paths `--config`/`--key`/`--cert`/`--intermediate` point at, with no privileged port binding, no `chown`-to-a-system-user, and no read of any root-only file. It's only *convention* that the default config/data paths (`/etc/sslcrtsrv`, `/opt/sslcrtsrv`, `Manual.MD`'s Section 5.2) happen to need root to create - pointed instead at a location an ordinary user owns, the entire `register`/`request`/`retrieve` cycle runs start to finish as that unprivileged user, landing the retrieved key/certificate/intermediate files in a directory it controls. Installing them into their final, often privileged destination (`/etc/ssl/private/...`, a web server's config reload, etc.) is then a small, separate, deliberately narrow step - e.g. a root-run cron job or systemd timer that only copies from that known drop location and reloads the one service that needs it - keeping the actual network-facing, attacker-reachable component (the unprivileged client dialing out to a remote server) fully separated from anything privileged enough to matter if it were ever compromised.
- A pull-based client model with built-in self-update (Section 2.2.2) and optional admin notifications (`Manual.MD`'s Section 10) as first-class features, not bolted on separately.
- Also speaks the standard RFC 8555 ACME protocol itself (Section 2.7), not only its own bespoke one - any off-the-shelf ACME client (certbot, `acme.sh`, a router's/appliance's built-in support) can request certificates through the exact same central inventory and per-client authorization model above, without needing `client.py` installed at all, at the cost of substituting a human admin-approval step for real DNS-01/HTTP-01 challenge validation (Section 2.7.4's tradeoff).

**Weaknesses**
- A materially newer, far less battle-tested piece of software than acme.sh, Certbot, Ansible, or cert-manager, all of which have years of production use, large communities, and extensive independent security review behind them - not yet considered production-ready, a real, current caveat rather than boilerplate.
- Introduces an entirely new, bespoke network protocol and server process to run and secure (Section 2.2) - additional attack surface and operational responsibility compared to reusing an already-trusted CM tool or a host's own package manager.
- For DNS-01 automation, `crtrequest.py` is currently only wired up and tested against **PowerDNS** (`Manual.MD`'s Section 2.3.3) - `acme.sh` itself supports dozens of other DNS provider hooks, and nothing about SSLCrtSrv's architecture requires PowerDNS specifically, but as shipped today, using a different DNS backend means either adopting PowerDNS (potentially just for the delegated subzone, Section 2.5.1), extending `crtrequest.py` to support another hook, or not using this project's ACME automation at all.
- **No support for Let's Encrypt's IP address certificates** (generally available since January 2026): these are validated exclusively via HTTP-01 or TLS-ALPN-01 - DNS-01 is explicitly not possible for an IP identifier, since there's no DNS record that proves control of an address - and are deliberately short-lived (the `shortlived` ACME profile, 160 hours / about 6.7 days, not the ~90 days this project's renewal logic is tuned for). `acme.sh` itself already supports issuing them (`--certificate-profile shortlived` plus webroot/standalone/TLS-ALPN modes), so the gap is entirely in `crtrequest.py`'s own orchestration, not in the underlying ACME client - but it's a substantial gap, not a small patch: (1) `crtrequest.py` hardcodes the `dns_pdns` DNS-01 hook (`Manual.MD`'s Section 2.3.3) with no HTTP-01/TLS-ALPN-01 code path at all; (2) both of those challenge types need the CA to connect directly to the certified address at validation time, and since issuance runs centrally on the SSLCrtSrv server rather than on the target host, supporting this for a client that isn't the server itself would need a new live challenge-relay mechanism through the client/server protocol (the target answering a challenge served through the server in real time) - reintroducing, specifically for this one certificate type, the direct-reachability requirement the rest of this project's design exists to avoid (`Manual.MD`'s Section 1.1, and the NAT/internal-domain strengths above); and (3) both `certificates.fqdns` as the row's primary key (Section 3.2) and `crtrequest.py`'s fixed 14-day-before-expiry renewal window (Section 2.4.5) assume long-lived, name-based certificates - a ~6.7-day lifetime would need a distinct identifier type and a much shorter, closer-to-continuous renewal cadence than the current daily-cron model comfortably provides.
- The multi-client authorization model above governs *client* access to certificates, but has no equivalent concept of separate, scoped *administrator* accounts - there's a single `clients`/`certificates` database, and anyone able to run `cltmanager.py`/`crtmanager.py`/`admintui` (or reach `server_config.json`/`keysrv.db` directly, per the OS-level permissions in Section 2.3.5) can see and manage every client and certificate on the server, not just one customer's. A reseller wanting to delegate scoped, per-customer administration (rather than administering all customers themselves from one shared account) would need to build that separately - there's no built-in multi-admin RBAC or customer/tenant grouping.
- Currently, a single-server design with no built-in high-availability or clustering story - a SQLite-backed single process (Section 3) is simple to operate but is a single point of failure for certificate retrieval and (if relied on) new-issuance approval, unlike a CM-tool-based approach with no single running service to fail, or a properly clustered internal PKI.
- Currently, no web UI for administration, only a terminal dashboard (`Manual.MD`'s Section 7) - a real limitation for organizations wanting browser-based or delegated (non-shell-access) administration.
- A much smaller community and ecosystem than any of the alternatives above - fewer eyes on the code, no third-party plugins or integrations, and support effectively limited to this project's own maintainer(s).

**Opportunities**
- Fleets with a genuine need for centralized, per-host authorization to public certificates issued via DNS-01, where hosts can't or shouldn't hold DNS/ACME credentials directly - most concretely, an ISP or hosting provider issuing certificates on behalf of many independent, mutually-distrusting customer hosts from one central system (`Manual.MD`'s Section 1.1), relying on the per-client/per-FQDNs rights model above rather than per-customer infrastructure, as long as PowerDNS (or adopting it for a delegated subzone) is acceptable, or the DNS hook is extended to the provider actually in use.
- Specifically, customer-premises equipment that is behind NAT, on a dynamic IP, or otherwise not directly reachable by the server operator, **and** whose owner is unwilling or unable to grant that operator SSH/admin access to reach it directly - a combination that rules out 1.5.1's HTTP-01 mode, 1.5.2's push-based CM tooling, and manual/commercial distribution (1.5.6) all at once, but is exactly what the outbound-only, no-admin-access client model above is built for.

**Risks**
- Adopting it for its central-authorization/no-client-credentials model while underweighting its youth, single-server design, and current PowerDNS-only DNS-01 automation - all three are real constraints worth validating against a specific environment before committing to it over a more mature alternative. Relatedly, mistaking the per-client certificate authorization model for a full multi-tenant administration solution - it isolates which *certificates* a client can reach, not which *customers* an administrator can manage - is worth catching early if delegated per-customer admin access is actually a requirement.

### 1.8. Summary Comparison Table

| Dimension | Local acme.sh/Certbot | CM-driven (Ansible etc.) | Proxy auto-HTTPS (Caddy/Traefik) | k8s cert-manager | Internal PKI (step-ca/Vault) | Manual/commercial | SSLCrtSrv |
|---|---|---|---|---|---|---|---|
| Setup complexity | Low | Medium | Very low | Medium (if no cluster yet: high) | Medium-high | Very low | Medium |
| Ongoing per-cert effort | Low, but per-host | Low, centrally defined | Effectively none | Effectively none | Low-medium | High, manual | Low, centrally managed |
| Central certificate inventory | No | Partial (via CM repo/inventory) | No | Yes (cluster-scoped) | Yes (CA's own records) | No (manual tracking only) | Yes (Section 3) |
| Central per-client authorization model | No | Implicit (CM/inventory logic) | No | Namespace/RBAC-based | Policy-based (CA-side) | Human judgment only | Yes, dedicated (Section 2.4.2) |
| Multi-tenant/multi-customer client isolation | No (any credentialed host reaches the whole zone) | Depends on inventory/playbook design | No | Namespace-scoped, cluster-internal only | Policy-scoped (CA-side) | No (manual judgment only) | Yes, per-client/per-FQDNs (Section 3.3) - no separate per-customer *admin* accounts, though (Section 1.7) |
| DNS/ACME credentials on every client host | Yes (DNS-01 mode) | Often yes, unless issuance is centralized | No (edge holds them) | No (cluster secret holds them) | N/A (internal trust, not ACME) | No (no automation at all) | No (Section 2.3) |
| Works behind NAT/dynamic IP with no inbound access to the target | Yes (DNS-01 mode only; No for HTTP-01) | No - control node needs inbound SSH/WinRM to the target, unless a pull-mode agent/VPN is separately built | No - edge itself must be the inbound-reachable endpoint (HTTP-01/TLS-ALPN-01), unless using a DNS-01 plugin | N/A (internal to cluster) | Usually yes (client dials out to the CA/API) | N/A (files transferred out-of-band) | Yes - client always dials out to the server (Section 2.2) |
| Requires granting the operator admin/SSH access to the target host | No | Yes, for the control node (unless a pull-mode agent is used instead) | No | No | No | No (no remote access involved at all) | No - only a narrow, purpose-built protocol relationship (Section 2.3) |
| The client/agent tool itself needs root/admin privileges to run | Typically yes in practice - binding port 80/443 for HTTP-01 and writing to the system cert store/reload hooks usually run as root, even though DNS-01 mode alone doesn't strictly require it | Usually yes on the target - CM tasks installing certs/reloading services are typically run with elevated privileges (e.g. Ansible's `become: true`) | Yes for the edge process to bind ports 80/443 (or via `setcap`/a privileged front-end) | N/A (cluster-internal controller identity, not a host-level privilege) | Depends - the API call itself is usually unprivileged, but installing the result into a system location often isn't | Depends entirely on who performs the manual copy | No - can run entirely as an unprivileged user; only an optional, separate step installs the result somewhere privileged (Section 1.7) |
| Works for non-HTTP-facing hosts | Yes | Yes | No | No | Yes | Yes | Yes |
| Works for domains with no public reachability at all (DNS-01 only, no public A/AAAA needed) | Yes, in DNS-01 mode | Yes, if the underlying issuance is DNS-01 | No (HTTP-01/TLS-ALPN-01 only) | Yes, with a DNS-01 issuer | N/A (private trust, not public CA validation) | Yes (a human can request/receive a cert for any name a CA agrees to validate) | Yes - DNS-01 only, by design (Section 2.5.1) |
| Public IP-address certificates (Let's Encrypt's `shortlived` profile, ~6.7-day lifetime, HTTP-01/TLS-ALPN-01 only) | Yes - `acme.sh`/Certbot both added support (2025-2026) | Depends on whether the playbook/module has been updated for the ACME profile option | Actively evolving across tools/versions as of this writing, not yet uniform | Depends on the configured issuer's own support | N/A (a public-CA feature, not applicable to a private CA) | Possible via any CA/ACME client that supports it | No - would need new HTTP-01/TLS-ALPN-01 automation, a live challenge-relay to the remote target, and much shorter renewal cadence (Section 1.7) |
| Public CA trust | Yes | Yes | Yes | Yes (with ACME issuer) | No (internal only) | Yes | Yes |
| Internal-only trust support | Via manual CA config | Via manual CA config | No | Yes (with internal issuer) | Yes, purpose-built | Yes | No |
| DNS provider flexibility | Any Certbot/acme.sh-supported provider | Any provider the module/playbook supports | Any HTTP-01/TLS-ALPN-01-capable setup | Any cert-manager-supported issuer | N/A | N/A | PowerDNS only, currently (`Manual.MD`'s Section 2.3.3) - other `acme.sh` hooks would need code changes, not just config |
| High availability / clustering | N/A (per-host) | N/A (per-host) | Depends on tool's storage backend | Yes (cluster-native) | Depends on deployment | N/A | No (single server, Section 3) |
| Maturity / community | Very high | Very high | High | High | High | N/A (no tooling) | Low, actively developed |
| Typical best fit | Single org, own DNS zone, small-medium fleet | Orgs already standardized on a CM tool, with routed access to every target | Web-facing services behind that proxy | Kubernetes workloads | Internal mTLS/service identity | Very small scale, or CA-specific needs | Reseller/many-tenant fleets needing central authorization without distributing DNS credentials or admin access, including NAT'd/dynamic-IP customer premises equipment |

---

---

## 2. Architecture and Technical Design

### 2.1. Component Overview and Interaction

```mermaid
flowchart TB
 subgraph Server["Server"]
        ServerProcess["Server Process"]
        SQLiteDB["SQLite DB"]
        CltManager["CltManager"]
        CrtManager["CrtManager"]
        CrtRequest["CrtRequest"]
        AcmeTool["acme.sh"]
        AdminTUI["AdminTUI"]
  end
    AcmeTool -- DNS Updates --> DNSServer["DNS Server"]
    ServerProcess <--> SQLiteDB
    CrtManager <-- Manage Certs --> SQLiteDB
    CltManager <-- Manage Clients & Permissions --> SQLiteDB
    CrtRequest <-- Request/Refresh Certs --> SQLiteDB
    Client["Client"] <-- TCP Communication --> ServerProcess
    CrtRequest -- Uses --> AcmeTool
    AdminTUI -- Calls in-process --> CltManager
    AdminTUI -- Calls in-process --> CrtManager
    AdminTUI -- Invokes via subprocess --> CrtRequest
```

Everything server-side reads and writes the same single SQLite database - there is no message queue or separate state store between the tools. `CltManager` and `CrtManager`'s logic is called directly, in-process, by both their own CLIs and by `admintui`; `CrtRequest` is always invoked as a *separate process* (even from `admintui`), because it makes real, potentially slow ACME/DNS network calls and attaches its own logging that shouldn't corrupt a caller's own output or block its event loop. `ServerProcess` (the long-running TCP server) is the only component a client host ever talks to directly - clients have no access to the database, to `acme.sh`, or to any of the admin tools.

### 2.2. Client/Server Network Protocol

The server listens on one plain TCP port by default (`listen_address`/`port`, default `5514`), and optionally on any number of additional address/port pairs configured via `bind_also` (`Manual.MD`'s Section 5.1) - e.g. to also listen on a VPN-only interface or an IPv6 address. Every listener behaves identically: each client connection is handled in its own thread, and carries either the project's own binary protocol or, for one specific bootstrap purpose, plain HTTP - the two share the same port and are told apart by peeking at the connection's first byte before deciding how to handle it.

#### 2.2.1. Custom Binary Protocol

Every message on the wire is framed as:

| Field | Size | Contents |
|---|---|---|
| Encryption flag | 1 byte | `0x00` (unencrypted) or `0x01` (encrypted) |
| Payload length | 4 bytes, big-endian | Length of the payload that follows |
| Payload | variable | The message itself (see below) |
| Signature length | 4 bytes, big-endian | `0` if unsigned |
| Signature | variable | Present only if signature length > 0 |

The payload is built by taking a message dict, serializing it to JSON, UTF-8-encoding it, and compressing it with `zlib`; if a recipient public key was given, that compressed data is then encrypted (Section 2.3.2) before being placed on the wire - otherwise the compressed bytes are sent as-is. A signature, when present, is always computed over the *compressed* bytes (before any encryption), so verification on the receiving end decrypts first (if needed), then checks the signature against those same compressed-but-decrypted bytes, and only decompresses afterward.

Because the encryption flag byte is always `0x00` or `0x01` - and an HTTP request line always starts with an uppercase ASCII verb (`GET`, `HEAD`, ...) - a single non-consuming `MSG_PEEK` of the first byte is enough to route a new connection correctly (Section 2.2.2).

**Size limits**: `receive_secure_message()` refuses (closes the connection) rather than reading further if the declared payload length exceeds `MAX_MESSAGE_SIZE` (2 MiB) or the declared signature length exceeds `MAX_SIGNATURE_SIZE` (4 KiB) - a peer can no longer make the server buffer arbitrary amounts of memory just by lying about these lengths. Separately, the *decompressed* size of the payload is capped at `MAX_DECOMPRESSED_MESSAGE_SIZE` (2 MiB) regardless of how small the compressed data on the wire was - zlib's compression ratio can exceed 1000:1, so a wire-size cap alone would not stop a small, highly compressible payload from decompressing into a much larger allocation (a "decompression bomb"). All three limits are deliberately generous relative to real traffic (the largest legitimate message is a `retrieve` response's key/certificate/intermediate-chain PEM text, typically well under 100 KB) - they exist to bound the worst case, not to police normal use.

**Worked example - anatomy of one message on the wire.** Sending `{"type": "status", "status": "ok"}`, signed but not encrypted (no recipient public key was supplied to `send_secure_message()`):

| Offset | Size | Field | Value in this example |
|---|---|---|---|
| 0 | 1 byte | Encryption flag | `0x00` |
| 1 | 4 bytes | Payload length (big-endian) | length, in bytes, of `zlib.compress(json.dumps(message).encode('utf-8'))` - call it *N* |
| 5 | *N* bytes | Payload | the zlib-compressed JSON, sent as-is since there is no recipient key |
| 5+*N* | 4 bytes | Signature length (big-endian) | `256` - an RSA-2048 PSS signature is always exactly `key_size / 8` bytes |
| 9+*N* | 256 bytes | Signature | RSA-PSS(SHA-256) computed over the same *N* compressed bytes at offset 5 |

If a recipient public key had also been supplied, the bytes at offset 5 would instead be a 256-byte RSA-OAEP-encrypted Fernet key followed by the Fernet-encrypted compressed JSON (Section 2.3.2); the payload-length field covers that whole concatenation. The signature is always computed over the plain compressed bytes *before* this encryption step (never over the ciphertext), which is why verification on the receiving end decrypts first, then verifies, then decompresses (Section 2.3.2's ordering).

**A framing assumption worth stating explicitly**: the two 4-byte length-prefix fields above, and the 1-byte encryption flag, are each read with a single `sock.recv(n)` call rather than a loop that accumulates until exactly `n` bytes have arrived - unlike the payload and signature bodies just after them, which *do* correctly loop. `socket.recv(n)` on a TCP stream is only ever guaranteed to return *up to* `n` bytes, not exactly `n`; a short read on one of these three fields silently corrupts the parsed length rather than raising an error, desynchronizing the rest of that connection's framing. This is tracked as a known limitation in `issue.md`, alongside the mirror-image gap on the sending side (`send_secure_message()` uses `sock.send()` rather than `sock.sendall()` for every field, so a partial write under backpressure is similarly unnoticed). Neither is likely to manifest on a healthy loopback/LAN connection, where the kernel typically hands back an entire small write in one `recv()` call, but both are genuine gaps in the protocol's robustness against a slow/lossy network path or a deliberately adversarial peer.

#### 2.2.2. HTTP Piggyback Protocol (Client Package Delivery)

A brand-new host has no keys and no registration secret yet, so it cannot use the authenticated protocol described above to fetch its own install package - that's exactly the bootstrapping problem this exists to solve. `Server.handle_client()` peeks the first byte of every new connection; if it's an ASCII letter, the connection is handed off to a minimal, hand-rolled HTTP/1.1 handler instead of the binary protocol. This handler is deliberately basic: GET only, no keep-alive, no `Range` support, and entirely unauthenticated (there is nothing sensitive in an install package).

Three routes are recognized:

| Route | Response |
|---|---|
| `GET /client-packages` | JSON catalog: `{"packages": {name: {"version", "description"}}}` (deliberately omits each entry's local filesystem path) |
| `GET /client-package/<name>` | The package file itself, as `Content-Disposition: attachment`, if `<name>` matches a configured package with a readable file |
| `GET /list` | A plain-text help page: the same catalog, human-readable, plus the `curl` command to download by name |

Any other path at all - including an unconfigured/mistyped package name under `/client-package/` - gets `401 Unauthorized`, body `Authentication needed`, and counts toward that source IP's abuse tracking (Section 2.2.2.1). There is no self-correcting overview for a typo. A `/client-package/<name>` naming a real, *configured* package whose file is simply missing on disk is treated as a server-side misconfiguration instead (`500`), not tracked as abuse - that's not the requester's fault. A recognized route requested with a method other than `GET` gets `405`, also not tracked.

Available packages are configured via one or more `--client-package NAME:PATH:VERSION[:DESCRIPTION]` arguments to `scs-server init` (`Manual.MD`'s Section 6.1), stored in `server_config.json`'s `client_packages` map. `client.py update` (`Manual.MD`'s Section 6.2) is the consumer on the other end: it polls the JSON catalog, compares the server's version for a named package against its own (`sslcrtsrv.__version__`), and downloads/installs only if the server's is newer. `client.py listpackages` polls the same catalog purely to display it - name/version/description, no download.

**Package-type auto-detection**: `sslcrtsrv`'s own `.deb`/tarball builds are architecture-independent (`Architecture: all`, one `-generic` tarball) - there's no real CPU architecture to detect. Instead, each build embeds a small `PACKAGE_TYPE` marker file (`deb` or `tarball`) directly inside the installed `sslcrtsrv` package directory, next to `__init__.py` - written by `debian/rules`' `override_dh_auto_install` for the `.deb`, and by `build-tarballs.py` for the tarball. It's never present in the git source tree itself, so a development checkout/editable install correctly has none. `common/client_utils.py`'s `detect_package_type()` reads it back at runtime (`None` if absent/unreadable - never guessed).

`update` combines this with `client_config.json`'s `update_package_base` (`Manual.MD`'s Section 5.2) into the actual catalog name to request: `<update_package_base>-<detected type>`, e.g. base `sslcrtsrv-client` + detected type `deb` -> `sslcrtsrv-client-deb`. This is purely a **naming convention** an admin opts into by registering packages that way - the catalog JSON shape itself is unchanged (still just `version`/`description`, no `arch`/`type` field). Registering packages to match (`Manual.MD`'s Section 9.9):
```
scs-server init --client-package sslcrtsrv-client-deb:/path/to/sslcrtsrv-client_0.9.0-1_all.deb:0.9.0:"Debian package"
scs-server init --client-package sslcrtsrv-client-tarball:/path/to/sslcrtsrv-client-0.9.0-generic.tar.gz:0.9.0:"Generic tarball"
```
and setting `"update_package_base": "sslcrtsrv-client"` in `client_config.json` means `scs-client update` (no `--update-package` needed at all) picks the right one automatically on either kind of install. `update_package` (a full, literal override) and `update_command` presets are also available in `client_config.json` for the same reason - see `Manual.MD`'s Section 5.2's field reference and `Manual.MD`'s Section 9.9's full setup walkthrough.

**Connection timeout**: every accepted socket - whether it turns out to be speaking this HTTP handler or the binary protocol above, since the decision is made by peeking the same socket - gets a `DEFAULT_TIMEOUT` (10s) read timeout applied right after `accept()`. A peer that connects and then never finishes sending (a stalled request line, a partial protocol message) has its connection closed automatically once the timeout elapses, rather than pinning a handler thread open indefinitely. This is a per-`recv()` timeout, not a cumulative one - it stops a connection that goes completely silent, not a very slow trickle that stays just under 10s between bytes.

##### 2.2.2.1. Abuse Tracking and Subnet Blocking

Every `401` from the handler above (an unknown path) is tracked by source IP in `common/http_abuse_tracker.py`'s `HttpAbuseTracker` - one plain in-memory instance per running server process (never persisted; a restart always starts clean). This is deliberately scoped to the HTTP handler's own notion of "wrong" (an unrecognized path) - a malformed or unauthenticated message on the regular signed/encrypted protocol is *not* tracked here, since that path already has its own, much higher-volume rejection reasons (an unregistered client, a bad signature, ...) that would make this indistinguishable from ordinary traffic.

A connection that gets routed here at all (its first byte looked like an HTTP verb) but then stalls before finishing its request line - and so hits the same per-connection `DEFAULT_TIMEOUT` described above - also counts as a bad request, exactly like an unknown path does, rather than just being logged and silently dropped. In practice this covers almost every way such a connection can end up empty-handed: since being routed here at all already required at least one real byte to have arrived (the peeked verb), a partial request that trails off ends up read back as a short, unrecognized "path" and counted via the unknown-path branch regardless; only the genuinely rare case of that already-peeked byte being discarded by an abrupt connection reset (rather than a graceful close or a stall) still slips through uncounted.

State per source IP:

1. **Accumulating**: each bad request increments that IP's counter. The whole record is forgotten the moment a *correct* URL is requested from that IP (any of the three routes above), or if 5 minutes pass with no further bad request from it.
2. **Triggered**: the instant either that one IP reaches **5** bad requests, or the *combined* count across every IP currently tracked in its `/24` subnet reaches 5 - the whole `/24` is blocked from connecting to the server's port **at all** for 5 minutes. This is enforced in `Server.start_server()`'s accept loop, immediately after `accept()` and before either protocol (HTTP or the regular signed/encrypted one) is even identified - a blocked subnet's connection attempts are refused (the socket is accepted, then immediately closed, with no response at all) regardless of which protocol they'd have spoken. The aggregate-across-IPs trigger exists specifically so a scan that rotates through addresses within one `/24` can't dodge the threshold by never repeating an IP.
3. **Probation**, for 30 minutes after that block expires: every IP that was part of the triggering subnet stays tracked; a *single* further bad request from any of them instantly re-triggers another 5-minute block and restarts this 30-minute window from that new request's timestamp (not the original one) - so a subnet that keeps offending, even slowly, never reaches "forgotten," only one that goes fully quiet for 30 straight minutes does.

None of this is configurable today - the thresholds/durations are the module's own constants (`BAD_REQUEST_THRESHOLD=5`, `BLOCK_SECONDS=300`, `INACTIVITY_CLEAR_SECONDS=300`, `PROBATION_SECONDS=1800`).

#### 2.2.3. Message Types and Exchange Flows

Every message is a JSON object with a `type` field: `register`, `status`, `listcerts`, `request`, `response`, or `congestion`. A `request` message additionally carries a `request_type`:

| `request_type` | Purpose |
|---|---|
| `certificates` (plural) | Register interest in a new FQDNs set - creates a pending (`status=0`) `client_certificate_relations` row if one doesn't already exist. What `client.py request` sends. |
| `certificate` / `info` | Read-only metadata (validity dates, provider, which parts are present) for an already-authorized (`status=1`), already-issued FQDNs set. |
| `retrieve` | The actual key/certificate/intermediate data for an already-authorized, already-issued FQDNs set - the private key is decrypted from at-rest storage (Section 2.3.3) only at this moment, and only ever travels encrypted for this one response. |
| `listcerts` | Every FQDNs set the requesting client is currently authorized (`status=1`) for, with validity info. |
| `version` | No authorization needed beyond a valid signature - returns the server's own `sslcrtsrv` version. What `client.py checkversion` sends (`Manual.MD`'s Section 6.2). |

**Version advertisement**: every `register`/`request` message from the client carries a `client_version` field (the client's own `sslcrtsrv.__version__`), and every `response` from the server carries a `server_version` field - both added automatically by `common/message_utils.py`'s constructors, independent of which specific message type is being sent. The server records the client's most recently reported version in `clients.client_version` (refreshed on every successfully-verified message, not just at registration - visible in `cltmanager.py listall`/admintui's Clients tab), and `client.py checkversion` uses the `server_version` on any response to compare against its own version without needing a dedicated round trip beyond the `version` request above. This is purely informational, not a protocol-version negotiation - the version fields themselves never gate anything. Separately, every request also requires a valid nonce/timestamp regardless of version (Section 2.3.6 point 3), so actual interoperability across versions depends on that, not on this. In essence, older clients *may* work with newer servers, though breaking changes might occur in releases.

Registration is a special case handled entirely outside this request/response scheme: a `register` message carries the client's `client_id`, its public key (as PEM), and a nonce/timestamp/proof triple (Section 2.3.4). Unlike every other message, it is sent and received completely unsigned and unencrypted at the transport layer - the server has no public key on file for this client yet to verify a signature against, and the client has no server public key yet either on a first contact. Authenticity here comes entirely from the registration proof, not from the envelope. Every message *after* a successful registration is both signed (by the sender's private key) and encrypted (for the recipient's public key); on the server side, the sender's public key is looked up from the `clients` table by the `client_id` embedded in the message itself, never trusted from a key supplied inline in an already-registered client's message.

**Note on retry/congestion handling:** `common/network_utils.py` also defines a `congestion` message type, a client-side handler for it (`handle_congestion_response`), and a generic `retry_with_backoff` helper. As of this writing, however, `server.py` never actually emits a congestion response (no load-based throttling is implemented), and neither helper is called from anywhere else in the codebase - a failed send or receive simply returns `None`/`False` to the caller, with no automatic retry built in. Anything that needs retry behavior today (e.g. a cron job calling `client.py retrieve`) needs to implement it itself.

#### 2.2.4. Message Schemas and Field Reference

Every message is a JSON object (before compression/encryption - Section 2.2.1). This section gives the concrete field-by-field shape of each one, as actually constructed by `common/message_utils.py` and consumed by `common/server_utils.py`/`common/client_utils.py` - useful both for troubleshooting with a packet capture and for understanding exactly what an attacker on the wire can and cannot see or influence.

**`register`** (client -> server, sent unsigned/unencrypted - Section 2.3.4 explains why this is still safe):

```json
{
  "type": "register",
  "client_id": "web01.example.com",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "nonce": "5f2e...  (32 hex chars - REGISTRATION_NONCE_BYTES=16 random bytes)",
  "timestamp": "1780000000",
  "registration_proof": "a1b2...  (64 hex chars - HMAC-SHA256 hex digest)",
  "client_version": "0.8.2"
}
```

The response, like every other response in this protocol, is wrapped in the generic response envelope below - note `server_version`, present on every response regardless of type (see the version-advertisement note above):

```json
{"type": "response", "response_type": "register", "success": true, "server_version": "0.8.2",
 "data": {"message": "Registration successful", "server_public_key": "-----BEGIN PUBLIC KEY-----\n...\n"}}
```

`server_public_key` is present only on success; a failure response's `data` carries just a human-readable `message` (deliberately generic for most rejection reasons - Section 2.3.4/2.3.6 - so a failed registration attempt doesn't leak *why* it failed).

**`request`** (client -> server, always signed and encrypted post-registration): a single envelope shape, `{"type": "request", "request_type": "...", "client_version": "...", "nonce": "...", "timestamp": "...", "data": {...}}` (`client_version`/`nonce`/`timestamp` are top-level fields alongside `request_type`, not nested inside `data`) - `nonce`/`timestamp` are required on every request and checked before any type-specific handling (Section 2.3.6 point 3), covering five distinct operations:

| `request_type` | `data` fields | Purpose |
|---|---|---|
| `certificates` (plural) | `client_id`, `domains` (comma-joined, sorted FQDNs) | Register interest in a new FQDNs set (`client.py request`) |
| `certificate` (singular) | `client_id`, `fqdns` | Read-only metadata for one already-authorized, already-issued FQDNs set |
| `info` | `client_id`, `fqdns` | Same as `certificate` today - a separate `request_type` kept distinct for `client.py`'s own CLI ergonomics |
| `retrieve` | `client_id`, `fqdns` | The actual key/certificate/intermediate data |
| `listcerts` | `client_id` | Every FQDNs set this client currently holds an active permission for |
| `version` | `client_id` | Nothing beyond `server_version` on the response envelope itself - `client.py checkversion` |

Every one of these responses shares the same envelope, `{"type": "response", "response_type": "<request_type>", "success": bool, "server_version": "...", "data": {...}}`; on failure `data` is just `{"message": "..."}`, and on success:

```json
// response_type == "certificate" / "info"
{"certificate": {"fqdns": "...", "validity_end_date": "...", "format": "PEM", "certifier": "Unknown",
                 "key_present": true, "cert_present": true, "intermediate_present": true,
                 "parts_present": ["key", "certificate", "intermediate"], "id": "..."}}

// response_type == "retrieve"
{"fqdns": "...", "key_present": true, "cert_present": true, "intermediate_present": true,
 "key": "-----BEGIN PRIVATE KEY-----\n...\n", "cert": "-----BEGIN CERTIFICATE-----\n...\n",
 "intermediate": "-----BEGIN CERTIFICATE-----\n...\n"}

// response_type == "listcerts"
{"certificates": [{"name": "web01.example.com,www.example.com", "valid_from": "...", "valid_to": "..."}, ...]}
```

`key` is the one field in this entire protocol that ever carries private key material - it exists only in a `retrieve` success response, is decrypted from at-rest storage (Section 2.3.3) at the exact moment this response is built, and never persists anywhere in decrypted form beyond that response object and whatever the client itself writes to disk (Section 2.4.4; see `issue.md` for a residual gap in how permissively that write happens today).

**A vestigial shape worth knowing about**: `common/message_utils.py` also defines a standalone `MSG_LISTCERTS`/`create_listcerts_message()` producing a bare `{"type": "listcerts"}` message (no `request`/`request_type` wrapper). Nothing in this codebase actually sends that shape - `Client.list_certificates()` uses the `request`/`listcerts` form in the table above instead - and `Server.process_message()` would reject a real `{"type": "listcerts"}` message outright as an unrecognized top-level type if anything ever did send one. Documented here only so a packet capture (or a future integration) isn't misled by the unused constant; see `issue.md`.

**`response`**, **`congestion`**: covered inline above (every `response` is the generic envelope shown throughout this section; `congestion`'s `{"type": "congestion", "delay": <seconds>}` shape is defined but never actually emitted by `server.py` today - Section 2.2.3's note on retry/congestion handling).

### 2.3. Encryption and Security Model

#### 2.3.1. Server Identity Keypair

The server generates its own RSA-2048 keypair (public exponent 65537) the first time `scs-server init` runs, and stores both halves as PEM strings directly inside `server_config.json` - not as separate key files. This keypair is purely a network-protocol identity: it authenticates the server to clients and lets clients encrypt messages only the server can read. It is entirely separate from, and unrelated to, the DB-encryption keypair described in Section 2.3.3. Each client independently generates its own, equally separate RSA-2048 keypair at `client.py init`, stored the same way in `client_config.json`.

#### 2.3.2. Message Signing and Encryption in Transit

- **Signing**: RSA-PSS with SHA-256 (MGF1/SHA-256, maximum salt length), computed over the compressed-but-unencrypted message bytes.
- **Encryption**: a hybrid scheme. A fresh, per-message symmetric key (`cryptography.fernet.Fernet`, i.e. AES-128-CBC with an HMAC-SHA256 integrity tag) encrypts the actual compressed payload; that one-time Fernet key is itself encrypted with RSA-OAEP(SHA-256) for the recipient's public key. The wire payload is simply the 256-byte RSA-encrypted key followed by the Fernet ciphertext.

The practical effect is that every message exchanged after registration is both authenticated and confidential end-to-end, independent of whatever network path it travels over - the protocol does not use or require TLS on the socket itself.

This is a hard guarantee, not just a default: `network_utils.py`'s `send_secure_message()`/`receive_secure_message()` support signing/encrypting on a message-by-message basis purely because the *registration* handshake genuinely has no keys to use yet (Section 2.2.3) - but every caller on both the client and server side that isn't that one handshake refuses outright, rather than silently sending or accepting a weaker message, if the key it needs is ever missing. On the client, this is `Client._require_secure_channel()`, checked before `list`/`request`/`info`/`retrieve` ever touch the socket; on the server, `handle_client()` explicitly refuses to send a non-registration response if a client's public key wasn't resolved. (A real bug of exactly this shape - the client never actually loaded the server's public key it had on file, silently downgrading every post-registration request to unencrypted-and-unverified - was found and fixed; see `issue.md`.)

#### 2.3.3. Database Encryption at Rest

Only the `certificates.private_key` column is ever stored encrypted; `public_key` and `intermediates` are stored as plain PEM, since they aren't sensitive. Encryption uses a **third, dedicated keypair** - separate from every client/server identity keypair - generated once via `crtmanager.py init-db-key`. Only the public half is ever needed to *encrypt* a private key for storage (done by `crtmanager.py addlocal`/`update` and by `crtrequest.py` right after a successful `acme.sh` issuance), so any process that only ever writes certificates never needs the private half at all. Only `server.py` needs the private half, and only at the exact moment a confirmed, authorized client retrieves a certificate - the decrypted value is never persisted, only sent.

Stored ciphertext is the literal prefix `ENC1:` followed by base64 of the same hybrid RSA+Fernet envelope described in Section 2.3.2. That prefix is what lets already-encrypted rows and not-yet-migrated legacy plaintext rows (from before this feature existed) be told apart without needing the key at all; `crtmanager.py migrate-encrypt-keys` (also reachable from `admintui`'s Maintenance tab) performs that one-time migration. If the DB-encryption keypair hasn't been set up yet, any operation that would need to encrypt or decrypt a private key fails immediately with a clear error pointing at `init-db-key`, rather than silently storing or serving a key in plaintext.

#### 2.3.4. Registration Secret and Anti-Replay Protection

A single shared secret (`server_config.json`'s `registration_secret`) must be proven known by every client before the server accepts its registration. It's generated automatically (and printed once) by `scs-server init` if not supplied explicitly, and has to be distributed to client administrators out-of-band.

The secret itself is never transmitted. Instead, the client computes an HMAC-SHA256 "registration proof" over `client_id|public_key_pem|nonce|timestamp`, keyed by the secret; the server independently recomputes the same value and compares it (constant-time) against what the client sent. Binding the proof to a fresh, random nonce and the current Unix timestamp defeats simple replay: the server rejects any timestamp more than `REGISTRATION_TIMESTAMP_WINDOW_SECONDS` (300 seconds, by default) away from its own clock, and separately records every nonce it has ever accepted (the `used_nonces` table, Section 3.4 - shared with every general request's own anti-replay check, Section 2.3.6 point 3) so the exact same nonce can never be consumed a second time, even from within that window.

Confirming a registration (`cltmanager.py confirm`) is a deliberately separate, human step: successful registration only proves the client knew the shared secret, not that its administrator is who they claim to be. The registration response prints both the client's and the server's public-key fingerprints specifically so an administrator can verify them out-of-band before confirming - guarding against a secret that leaked to, or was guessed by, the wrong party.

**Fingerprints are rendered as words, not just hex.** Every place a fingerprint is shown for this out-of-band comparison - `client.py register`'s console output, `cltmanager.py confirm`, and admintui's Onboarding/Clients tabs - prints it as a numbered sequence of 32 short, common words (`common/fingerprint_words.py`, one word per byte of the 32-byte SHA-256 digest, e.g. `1:acorn  2:maple  3:otter ...`), with the raw hex kept underneath for anyone who wants to compare byte-for-byte or paste it into another tool. Reading or comparing 32 plain words - especially spoken aloud over the phone, the comparison channel this section already recommends - is far less error-prone than 64 hex digits, where a misheard "b" vs. "d" or "1" vs. "7" is easy to miss; the word list represents the entire fingerprint losslessly (never truncated), so it carries exactly the same security guarantee as comparing the full hex, just in a form a human is much less likely to misread.

#### 2.3.5. File and Directory Permission Model

Two base paths hold everything: `/etc/sslcrtsrv` (configuration and keys, overridable) and `/opt/sslcrtsrv` (runtime data - the database and every certificate's own `acme.sh` working directory, also overridable). The default permission model is strictly owner-only: directories `0700`, files `0600` - this is always what the client uses for its own configuration, since it contains the client's private key and nothing else needs to touch it.

A handful of server-side paths (`server_config.json`, `keysrv.db`, and the DB-encryption keypair's *public* half) instead use a wider, group-shared mode (`0750`/`0660`) so that a separate process running under a different Unix account, but in the same Unix group, can also read and write them. Widening the mode bits alone does nothing by itself - it only has any effect once an administrator actually places both accounts in a shared group. The DB-encryption keypair's *private* half is the one exception kept strictly owner-only regardless: only `server.py` itself should ever be able to decrypt a stored certificate key.

#### 2.3.6. Protocol Security Analysis: Impersonation Resistance and Malformed-Input Handling

This section pulls together, in one place, exactly what stops a network-positioned or malicious peer from impersonating someone else, and exactly what happens when the protocol receives something it doesn't expect - the two concerns raised most often about a hand-rolled binary protocol that deliberately does not run over TLS (Section 2.3.2). Nothing here is new relative to the mechanisms already described in Sections 2.2/2.3.1-2.3.5; this is the threat-model view of the same facts, plus an honest accounting of what is *not* covered.

**1. Can someone impersonate a client?**

A client's identity is its `client_id` plus whichever RSA keypair the server has on file as belonging to it. Registering a new identity (Section 2.2.3/2.3.4) requires computing `HMAC-SHA256(registration_secret, client_id|public_key_pem|nonce|timestamp)` - without knowing `registration_secret`, an attacker cannot produce a proof the server will accept for *any* `client_id`, whether already taken or not, so a shared-secret leak is the only path to squatting or hijacking an identity this way. The proof is checked with `hmac.compare_digest()` (constant-time), so a timing side-channel cannot be used to guess it byte-by-byte. Binding the proof to a fresh nonce and the current timestamp (checked against `REGISTRATION_TIMESTAMP_WINDOW_SECONDS`, and the nonce separately recorded in `used_nonces` so it can never be consumed twice - Section 3.4) means a captured registration message cannot simply be replayed later, even by someone who recorded it off the wire verbatim. Once registered, every subsequent message from that client is RSA-PSS-signed with a private key the server never sees - the server looks the corresponding public key up from its own `clients` table by `client_id`, **never** from a key embedded in the incoming message itself, so a message can't claim a different identity's key just by attaching one (`network_utils.py`'s `receive_secure_message()`, the `is_from_client` branch). A signature that doesn't verify against the stored key is rejected outright, the connection is closed, and that client's connection-health counters record the failure (Section 3.1) - it is never silently accepted or retried with a different key.

**2. Can someone impersonate the server?**

This is the one place the design has a real, acknowledged gap rather than a mitigated one: the server's public key is handed to a registering client *inside the registration response itself*, which - like the registration request - travels completely unsigned and unencrypted, because the client has no server key yet to verify a signature against (Section 2.2.3). A network-positioned attacker present at the exact moment of a client's *first* registration could substitute their own keypair for the server's, and from that point on the client would encrypt every future request for that attacker and accept anything signed by them as authentic. Nothing in the wire protocol itself prevents this - it's a trust-on-first-use (TOFU) bootstrap problem, structurally similar to SSH host keys the first time you connect to a host. The mitigation is procedural, not cryptographic: `register_with_server()` prints both the client's and server's public-key fingerprints (Section 2.3.4/2.4.1) specifically so an administrator can compare them out-of-band (phone, a separate trusted channel, physically reading the server's own output) *before* running `cltmanager.py confirm`. Skipping that comparison - or performing it over the same network path an attacker already controls - defeats it entirely. There is no certificate authority, pinning, or persisted "known server keys" file anywhere in this protocol; if the server's identity keypair is ever regenerated (e.g. after `internal/security/SECURITY_FINDINGS.md`'s scenario of a corrupt config forcing key regeneration - see `common/server_utils.py`'s `Server.__init__` error path), every already-registered client silently starts failing signature verification with no automatic re-trust mechanism, which is by design the safer failure mode (closed, not open) but does mean every client needs to go through this same out-of-band comparison again.

**3. Can a captured or altered message be replayed or tampered with?**

Every post-registration message is both signed and encrypted (Section 2.3.2) - tampering with either the ciphertext or the plaintext-then-recompressed bytes invalidates the RSA-PSS signature, which is verified before the message is acted on in any way. Every `request` message also carries its own nonce and timestamp, exactly mirroring registration's own scheme (`common/message_utils.py`'s `create_request_message()` generates them automatically; `common/server_utils.py`'s `handle_request()` checks and consumes them via the same `used_nonces` table/`consume_nonce()` registration uses - Section 3.4) - required unconditionally, with no fallback for a message missing either field. A byte-for-byte-identical, previously-valid message replayed later - even moments later, over a brand-new connection - is rejected outright, before any request_type-specific handler ever runs, regardless of whether that request type happens to be idempotent.

Server-to-client *response* replay (a malicious/MITM server replaying an old response to the client) is a different, separate threat, not addressed by this mechanism - see point 2's TOFU discussion for the related server-impersonation gap. `retrieve`'s own freshness check on the client side (Section 2.4.4 - an existing, still-valid local certificate is never overwritten by an older one) incidentally limits the practical impact of a stale replayed response for that one request type, but this isn't a general guarantee across every response type.

**4. What happens when the protocol receives malformed, oversized, or unexpected content?**

- **Oversized/adversarial length claims**: `MAX_MESSAGE_SIZE` and `MAX_SIGNATURE_SIZE` bound how much a peer's declared length fields are allowed to claim before the server refuses outright (Section 2.2.1); `MAX_DECOMPRESSED_MESSAGE_SIZE` separately bounds zlib's *output*, closing the decompression-bomb variant of the same attack that a wire-size cap alone would miss.
- **Framing corruption from a short read/write**: as detailed in Section 2.2.1's worked example, the length-prefix and encryption-flag fields are read with a single `recv()` call rather than an accumulating loop, and every send is a bare `send()` rather than `sendall()` - both are latent gaps that can desynchronize a connection's framing under a short read/write, tracked in `issue.md` as not yet fixed. They do not currently let a peer forge or bypass a signature check; the failure mode is a corrupted/rejected message or a hung connection, not an authentication bypass.
- **Unparseable JSON, missing fields, or unexpected types**: `receive_secure_message()`, `process_message()`, and every `handle_*` method are wrapped in broad `try/except` blocks that catch any exception (a `json.JSONDecodeError`, a `KeyError` from an assumed-present field, a `TypeError` from a wrong-shaped value) and turn it into either a clean rejection (`return None`, closing that connection) or a generic `create_response_message("error", False, {"message": "..."})` - never an unhandled exception that could crash the handler thread, let alone the server process. `message_utils.is_valid_message()` adds a first, cheap structural check (required fields present for `register`/`request`/`response`/`congestion`) before a message is dispatched at all.
- **A garbled or unrecognized encryption flag**: any byte other than the literal `0x01` is treated as "not encrypted" (Section 2.2.1's framing table) - a genuinely encrypted payload misflagged this way simply fails to decompress as plaintext and is rejected via the same broad exception handling above, rather than being misinterpreted as valid plaintext.
- **A response destined for an unresolved client key**: `handle_client()` explicitly double-checks, right before ever calling `send_secure_message()`, that a real client public key was resolved for anything other than a registration response (Section 2.3.2) - if that invariant is ever somehow violated by a bug elsewhere, the server closes the connection instead of ever sending an authenticated-looking response with no actual encryption behind it.
- **Connection-level abuse**: a per-connection read timeout (`DEFAULT_TIMEOUT`, applied immediately after `accept()`) closes a peer that connects and then stalls, and `HttpAbuseTracker` (Section 2.2.2.1) escalates repeated bad requests on the HTTP piggyback path into a temporary `/24` subnet block - both apply before either sub-protocol is even identified. Neither the socket-accept loop nor the per-connection handler thread pool has an upper bound today (an unbounded number of concurrently accepted connections each get their own daemon thread), which remains an open resource-exhaustion consideration for a server exposed to an untrusted network - see `internal/security/SECURITY_FINDINGS.md` finding #7's residual half.

### 2.4. Certificate Lifecycle

```mermaid
sequenceDiagram
    participant C as Client host
    participant S as Server
    participant A as Admin (cltmanager/admintui)
    participant Acme as acme.sh (crtrequest.py)

    C->>S: register (proof of registration secret)
    S-->>C: server public key
    C-->>S: client public key
    A->>A: compare printed key fingerprints
    A->>S: cltmanager confirm <client>
    C->>S: request <fqdns> (request_type=certificates)
    S-->>S: client_certificate_relations row, status=0
    A->>S: cltmanager assign <client> <fqdns>
    S-->>S: status=1 (approved)
    Acme->>Acme: crtrequest.py (scheduled, or "Issue now")
    Acme->>S: DNS check (optional), then acme.sh issuance
    S-->>S: certificates row populated, key encrypted at rest
    C->>S: retrieve <fqdns>
    S-->>C: key + certificate + intermediate (decrypted just for this response)
```

#### 2.4.1. Client Registration and Confirmation

1. `client.py init` generates the client's keypair and stores the registration secret it was given.
2. `client.py register` sends the `register` message (Section 2.2.3/2.3.4); on success it prints both its own and the server's public-key fingerprints.
3. The registration shows up as unconfirmed on the server (`cltmanager.py`'s default listing, or `admintui`'s Clients tab).
4. An administrator compares the printed fingerprints out-of-band with the client's administrator, then runs `cltmanager.py confirm <client-id>`, setting the client's status to `confirmed`.

Only confirmed clients can go on to request or retrieve certificates. `cltmanager.py revoke <client-id>` reverses step 4 at any time - it un-confirms the client entirely (e.g. if its key is suspected compromised, or the host is decommissioned), independent of and unrelated to any specific certificate permission (Section 2.4.2's `revoke_permission` is the one that revokes access to individual certificates instead).

#### 2.4.2. Certificate Request and Admin Approval

A `client_certificate_relations` row - one client tied to one FQDNs set, with a status of `0` (pending/unassigned) or `1` (approved/active) - can come into existence two ways:

- **Client-initiated**: `client.py request <fqdns>` sends a `certificates` request; the server creates the row at `status=0` if one doesn't already exist for that exact FQDNs string.
- **Admin-initiated**: `cltmanager.py assign <client> <fqdns>` (or the equivalent in `admintui`) creates or updates the row directly at `status=1`, whether or not the client ever asked for it.

Approving a client-initiated request is simply running `assign` again on the same FQDNs, moving it from `0` to `1`. `cltmanager.py revoke_permission <client> <fqdns>` undoes a specific grant (or every grant for a client, with `all` as parameter instead of FQDNs) at any time - this only ever affects the *relation*, never the underlying certificate itself, which is untouched and can still be assigned to other clients. (Don't confuse this with `cltmanager.py revoke <client>`, a different, client-level command that un-confirms a client entirely - Section 2.4.1.) Neither requesting nor approving triggers `acme.sh` - issuance is always a distinct, separate step (Section 2.4.3).

`assign` optionally takes `--valid-until DATETIME` to make the grant expire automatically at a given UTC date/time (bare dates like `2026-12-31` or full ISO datetimes both work); omit it for a permission that never expires on its own, the default. `cltmanager.py set_expiry <client> <fqdns> <DATETIME|never>` changes an already-granted permission's expiry without touching its status. Once `permission_valid_until` passes, the permission is treated exactly like a revoked one by every access check (Section 2.4's three-layer check, Section 3.3) - `admintui`'s permission tables mark it with an "(expired)" status suffix rather than removing the row, so the grant's history stays visible.

#### 2.4.3. ACME Issuance via acme.sh

Certificates reach the database in one of two ways:

- **Manual** (`crtmanager.py addlocal`/`update`): reads existing key/certificate/intermediate files directly, extracts the FQDNs from the certificate itself. `acme.sh` is never involved.
- **Automated** (`crtrequest.py`): for every approved (`status=1`) FQDNs set (batch mode - e.g. from cron), or one specific set (`--cert-name`, e.g. `admintui`'s "Issue now"):
  1. Creates or reuses a `certificates` row - a "placeholder" if brand new, with empty key/certificate data and a stub validity date.
  2. Unless `--no-check-dns` was given, verifies DNS delegation first (Section 2.5.2); a certificate missing it is skipped with a warning, and nothing else in this list happens for it.
  3. Invokes `acme.sh --issue`/`--renew` with `--home` pointed at that certificate's own dedicated working directory (`cert_home_dir/cert-<id>`) and `--dns dns_pdns` (`Manual.MD`'s Section 2.3.3), passing the DNS provider's credentials as environment variables.
  4. On success, reads the resulting files back off disk, encrypts the private key for storage (Section 2.3.3), and updates the `certificates` row.
  5. On any failure - `acme.sh` itself failing, or succeeding but leaving no certificate file behind - removes only the placeholder row created in step 1, **never** the client's own `client_certificate_relations` row, so a certificate that has never actually been issued always stays visible as a pending request rather than silently disappearing from view.

A certificate's ACME provider defaults from the server configuration but can be overridden per-certificate (`crtmanager.py set-provider`), including setting it to a special `manual` marker that permanently excludes that certificate from `crtrequest.py`'s automation.

#### 2.4.4. Certificate Retrieval and Client-Side Storage

`client.py retrieve <fqdns>` sends a `retrieve` request; the server only answers if the client is confirmed, its relation for those FQDNs is `status=1`, and a real (non-placeholder) certificate exists. Destinations are chosen with `--key`/`--cert`/`--intermediate`/`--combined` (certificate and intermediate concatenated into one "fullchain" file) and/or `--all` (a filename template producing key, certificate and intermediate, though not the combined version, at once).

Before writing anything, the client compares the *retrieved* certificate's own validity end date against whatever already exists at the `--cert` destination; if the existing file is already as new or newer, every destination file is left untouched and `--exec` is skipped entirely, so a scheduled `retrieve` doesn't needlessly rewrite files or restart services when nothing has actually changed. The server's response reports whether a write actually happened (`certificate_replaced`), and `client.py` exits with a distinct code (`10`) specifically when it wasn't, so a wrapper script can tell "up to date" apart from "an actual error" or "success."

`--exec <command>` runs a shell command after a real (non-skipped) write - typically to reload whatever service consumes the certificate.

**Download tracking**: every successful `retrieve` (the private key actually decrypted and returned - not a rejected/failed one) records `last_download_at` and a snapshot of the certificate's `validity_end_date` *at that moment* onto the client's `client_certificate_relations` row (Section 3.3). Since a renewal overwrites `certificates.validity_end_date` in place, this snapshot is what lets `scs-crtmanager warn-stale-downloads` (`Manual.MD`'s Section 6.3) later tell that a client is still running whatever copy it fetched then, even after the server's own certificate has since moved on - something the live `certificates` row alone can't reveal. A failed retrieval attempt (no permission, certificate not found, decryption failure) never touches this - only a real, successful handoff of key material does.

#### 2.4.5. Renewal, Expiry, and Staging/Production Handling

`crtrequest.py`'s batch mode renews any certificate within 14 days of its `validity_end_date`, or when no valid date is recorded at all. `--staging` requests from the CA's staging/test environment instead of production, and never overwrites an existing, still-valid production certificate unless `--force` is also given; a production request, conversely, always overwrites an existing staging certificate, forcing a real re-issuance rather than trusting `acme.sh`'s own "nothing changed" skip logic (which would otherwise leave the old staging certificate in place). Whether a stored certificate actually is a staging one (`is_staging`) is corrected based on inspecting the real, issued certificate's issuer field against a list of known staging-CA issuer strings, rather than just trusting whichever flag was passed in - so this can't silently drift out of sync with what's actually on disk.

`--force-dns-refresh` is a separate, deliberate operation - not part of routine renewal - that forces a real re-issuance against every affected certificate specifically to push a freshly rotated DNS-provider token into `acme.sh`'s own saved state immediately, rather than waiting for each certificate's natural renewal window.

### 2.5. DNS-01 Delegation Design

#### 2.5.1. CNAME Delegation Scheme

DNS-01 validation needs a TXT record at `_acme-challenge.<domain>`, but many organizations' primary/authoritative DNS can't accept the kind of dynamic, automated updates `acme.sh` needs to make there. This project's answer is to delegate just that one name, per domain, via a `CNAME`, to a small, separate subzone hosted on a DNS backend `acme.sh` *can* update programmatically (`Manual.MD`'s Section 2.3.3) - the domain's real, primary DNS is otherwise untouched.

The exact CNAME entry needed depends on the domain's shape (`crtrequest._acme_challenge_dns_name()`):

| Domain | Required CNAME entry |
|---|---|
| A normal domain, e.g. `example.com` | `_acme-challenge.example.com` |
| A subdomain, e.g. `mail.example.com` | `_acme-challenge.mail.example.com` |
| A wildcard, e.g. `*.example.com` | `*._acme-challenge.example.com` (a literal wildcard record - **not** the RFC 8555 "strip the `*.`" name, which would otherwise collide with the base domain's own entry) |

Every one of these CNAME entries points at the same place: `_acme-challenge.<CHALLENGE_ALIAS>`, where `CHALLENGE_ALIAS` is configured once in `crtrequest_config.json` and shared by every domain this server manages. The delegated subzone itself needs no manual entries beyond its own `NS` record - `acme.sh` manages everything under it dynamically through the DNS backend's API.

**A consequence worth stating explicitly: the domain being certified never has to resolve to anything reachable at all.** DNS-01 validation only ever queries the `_acme-challenge.<domain>` TXT record (via the CNAME above) - unlike HTTP-01/TLS-ALPN-01, it never connects to the domain's own A/AAAA address. A purely internal hostname - one with no public A/AAAA record whatsoever, resolvable only inside a private network or via split-horizon DNS - can still receive a publicly-trusted certificate through this design, as long as its zone is delegated publicly enough for the CNAME chain above to be queryable (the delegated subzone/`CHALLENGE_ALIAS` needs public DNS presence; the certified name itself does not). Combined with the client/server protocol's own client-initiated-only connectivity model (Section 2.2), this means neither the domain name nor the host using it ever needs any inbound reachability, a public IP, or even public DNS resolution of its own - see the comparison in Section 1.7 for how this compares to HTTP-01-based approaches, which cannot do this at all.

#### 2.5.2. DNS Verification (default / --no-check-dns / --check-dns-only)

- **Default** (no flag needed): a gate on the normal issue/renew flow, on automatically. Before calling `acme.sh` for a certificate, `crtrequest.py` resolves each of that certificate's domains' expected CNAME entry (via `dig +short CNAME`) and confirms it points at the expected `_acme-challenge.<CHALLENGE_ALIAS>` target. A certificate that fails is skipped, with a warning, without ever calling `acme.sh` or creating a placeholder row - processing simply moves on to the next certificate.
- **`--no-check-dns`** disables that gate entirely, restoring the old unconditional behavior (e.g. if `dig` isn't installed and the extra lookups genuinely aren't wanted).
- **`--check-dns-only`** is a pure diagnostic, independent of the other two: the identical check, run standalone against one certificate (`--cert-name`) or every FQDNs set the server currently tracks, and never calls `acme.sh` or touches the database regardless of what it finds. Useful for confirming DNS is actually ready before approving a request, or before relying on the next scheduled renewal run.

All three require `dig` (`Manual.MD`'s Section 2.3.2); none of them perform a lookup, or fail silently, if `CHALLENGE_ALIAS` isn't configured or `dig` isn't installed - both conditions are reported plainly instead. `admintui`'s "Issue now" dialog (Requests/Certificates tabs) has a "Skip DNS check" checkbox mirroring `--no-check-dns`, unchecked by default; the same tabs' `d` key and the Maintenance tab's "Check DNS (all tracked certificates)" button instead run the standalone `--check-dns-only` check, via a small subprocess bridge.

### 2.6. Configuration Live-Reload and Versioning

`server.py` watches its own configuration file for changes using Linux's `inotify` API (`Manual.MD`'s Section 2.1), via a small `ctypes` wrapper rather than a polling loop or an extra dependency. The watch is placed on the file's *containing directory*, not the file itself, so it survives both an atomic replace (a text editor writing a temp file and renaming it over the original) and an in-place rewrite (how the server's own config-saving code, including `admintui`'s Config tab, writes it). On any relevant change - a write, an attribute change, a rename-over, or a deletion of the config file - the server logs it, cleanly shuts down its listening socket, and re-executes itself in place (`python3 -m sslcrtsrv.server`, same PID, same original arguments), picking up the new configuration exactly as if it had been restarted by hand. No supervisor (`systemd` or otherwise) needs to notice or be involved.

A single version string (`sslcrtsrv.__version__`) is the one source of truth used everywhere a version could otherwise silently drift out of sync: every console script's `--version` flag, the Debian packaging's build-time check that `debian/changelog`'s version actually matches it, `build-tarballs.py`'s output filenames, and the client's own self-update comparison against the server's package catalog (Section 2.2.2).

### 2.7. ACME (RFC 8555) Server Interface

`scs-acme-server` is a second, independent server process that lets *third-party* ACME clients (certbot, `acme.sh` itself, a router's or appliance's built-in ACME support, ...) request certificates from this project directly, over the standard RFC 8555 protocol - instead of, or alongside, the custom client/server protocol described in Sections 2.1-2.4. Everything in this section is additive: nothing about the traditional protocol changes, and a deployment that never enables `acme_enabled` behaves exactly as if this section didn't exist. The full design rationale - including nine rounds of review that shaped several of the invariants described below - lives in `ACME_SERVER_DESIGN.md` at the repository root; this section is the operator-facing summary.

#### 2.7.1. Two Parallel Interfaces, One Shared Database

```mermaid
flowchart TB
 subgraph Server["Server Host"]
        ServerProcess["Server Process (traditional protocol)"]
        AcmeServerProcess["scs-acme-server (RFC 8555)"]
        SQLiteDB["Database"]
        CrtRequest["CrtRequest"]
        AcmeTool["acme.sh"]
  end
    Client["Traditional Client (scs-client)"] <-- TCP --> ServerProcess
    AcmeClient["Third-Party ACME Client"] -- HTTPS via reverse proxy --> AcmeServerProcess
    ServerProcess <--> SQLiteDB
    AcmeServerProcess <--> SQLiteDB
    CrtRequest <-- Both traditional and ACME orders --> SQLiteDB
    CrtRequest -- Uses --> AcmeTool
```

`scs-acme-server` reads and writes the *same* database as everything else (Section 3) - there is no separate ACME database, and no separate `init` subcommand: it reads `acme_*` fields directly out of the same `server_config.json` the traditional server uses (`Manual.MD`'s Section 5.1/4.6). Certificate issuance itself still goes through `crtrequest.py` (Section 2.4.3) - `scs-acme-server` never invokes `acme.sh` itself; it only accepts orders and CSRs, and `crtrequest.py`'s existing cron-driven pass (`Manual.MD`'s Section 9.3) picks them up alongside its traditional-protocol work, in the same run. An ACME account is simply a `Client` row with `client_kind='acme'` (Section 2.7.3) - `cltmanager.py`/`admintui`'s client-listing views show ACME accounts and traditional clients side by side, distinguished by this field.

**A certificate's FQDNs set can be managed by both interfaces independently, each with its own certificate.** Each side protects only its own write to the shared `certificates` row: `scs-acme-server`'s CSR-relay issuance skips updating that row if it already holds a traditional-protocol (or manually-imported) private key, since an ACME client's own certificate is always served from its own separate `acme_certificates` record regardless; the traditional issuance loop simply writes its own real key+cert as usual, since nothing on the ACME side ever reads from the shared row to deliver its own certificate. `database.is_acme_managed(fqdns)` reports whether a live ACME order exists for an fqdns, used by `crtrequest.py`'s traditional-issuance loop purely for an informational log line - see `ACME_SERVER_DESIGN.md`'s §6.4 ("Coexistence with the traditional protocol") for the full mechanism.

#### 2.7.2. Protocol Flow and Endpoints

```mermaid
sequenceDiagram
    participant AC as ACME Client
    participant AS as scs-acme-server
    participant A as Admin (cltmanager/admintui)
    participant CR as crtrequest.py

    AC->>AS: GET directory
    AC->>AS: HEAD new-nonce
    AC->>AS: POST new-account (JWK-signed)
    AS-->>AS: Client row, client_kind='acme', status='registered'
    A->>AS: cltmanager acme_confirm <client>
    AC->>AS: POST new-order (kid-signed)
    AS-->>AS: AcmeOrder row, status='pending'
    A->>AS: cltmanager assign <client> <fqdns>
    AC->>AS: POST finalize (CSR)
    AS-->>AS: AcmeProcessingLock acquired, status='processing'
    CR->>CR: scheduled crtrequest.py pass
    CR->>CR: acme.sh --signcsr (no private key ever touches this server)
    CR-->>AS: AcmeOrder status='valid', AcmeCertificate row inserted
    AC->>AS: POST order (poll)
    AC->>AS: POST certificate (download)
```

Every endpoint below lives under `acme_external_url`'s path prefix (`Manual.MD`'s Section 4.6) and is implemented in `common/acme_server_utils.py`:

| Endpoint | Method | Purpose |
|---|---|---|
| `directory` | `GET` | RFC 8555 directory discovery - the URLs for every other endpoint below. The only endpoint (besides `new-nonce`) a client is allowed to reach with a plain, unauthenticated request. |
| `new-nonce` | `HEAD`/`GET` | Issues a fresh anti-replay nonce (`Replay-Nonce` header) - required before any signed `POST`. |
| `new-account` | `POST` | Registers a new ACME account - open, unauthenticated self-registration (any JWK can register), exactly like the traditional protocol's own `register` (Section 2.2.3) is open to any key. What actually grants access is the same as there too: a human admin's confirmation (below). |
| `account/<id>` | `POST` (POST-as-GET or update) | Fetch or update (contact info only) an account. |
| `account/<id>/orders` | `POST` (POST-as-GET) | List this account's orders - bounded (Section 2.7.3), not a full unbounded history. |
| `new-order` | `POST` | Create a new order for one or more DNS identifiers. Rejected outright if any identifier fails basic syntactic validation (RFC 1035/1123 label syntax, length limits, a single leftmost wildcard, IDNA-encoded Unicode domains, no IP-address literals - `Manual.MD`'s Section 11.5). Coexists freely with a traditional-protocol certificate or another live ACME order for the same identifiers (Section 2.7.1) - multiple concurrent orders for one fqdns are allowed; a *conflicting* second `finalize` for the same fqdns while one is already `processing` is what actually gets rejected, with `orderConflict` (Section 2.7.3). |
| `order/<id>` | `POST` (POST-as-GET) | Poll an order's status. |
| `order/<id>/finalize` | `POST` | Submit the CSR once the order is externally approved (below) - this is the moment the order transitions to `processing` and becomes visible to `crtrequest.py`. |
| `authz/<order>/<n>`, `chall/<order>/<n>` | `POST` (POST-as-GET) | Authorization and challenge objects (Section 2.7.4 explains why these describe admin approval, not a real DNS-01/HTTP-01 exchange). |
| `cert/<order>` | `POST` (POST-as-GET) | Download the issued certificate + intermediate chain. |
| `intermediate` | `GET` | Unauthenticated, always-fetchable download of the most recently issued intermediate certificate - the `rel="up"` target every `cert/<order>` response links to. |

**"Admin approval" replaces DNS-01/HTTP-01 challenge validation entirely.** There is no real challenge exchange: an order only becomes eligible for `finalize` once an admin runs `cltmanager.py assign` (Section 2.4.2 / `Manual.MD`'s Section 9.2) for that account/FQDNs pair - exactly the same admin action the traditional protocol already uses to approve a request. The authorization/challenge objects returned to the ACME client are schema-correct (RFC 8555 shape, a `status`, a non-empty `challenges` array) but describe this out-of-band approval, not a real DNS or HTTP validation - see Section 2.7.4 for why, and the one open real-world risk this carries.

#### 2.7.3. Data Model

Three extra columns on existing tables, plus four new tables (full column-level reference: Section 3.1/3.2/3.6):

- **`clients.client_kind`** (`'custom'` or `'acme'`) distinguishes a traditional client from an ACME account; **`clients.acme_key_thumbprint`** (RFC 7638 JWK thumbprint, unique) is an ACME account's identity, playing the same role `client_id` plus a keypair plays for a traditional client; **`clients.acme_contact`** stores the optional contact URLs an account can set.
- **`certificates.key_fingerprint`** records the public-key fingerprint of whatever key is currently associated with a certificate - populated for both traditional and ACME-issued certificates, used to detect a genuine key rotation.
- **`acme_orders`** is the single, authoritative issuance-state record - there is deliberately no separate "issuance queue" table; `crtrequest.py`'s ACME pass simply queries `acme_orders` directly for the ones ready to work on (`Manual.MD`'s Section 6.3).
- **`acme_certificates`** is an *immutable, per-order* certificate record - a renewal creates a brand-new row rather than overwriting the previous order's, so `cert/<old-order>` keeps returning exactly what that order actually issued even after a later renewal. The single shared `certificates` row (used by the traditional protocol, `crtmanager.py`, etc.) always reflects only the *latest* one.
- **`acme_processing_locks`** enforces "at most one order per FQDNs set may be mid-issuance at a time" - primary-keyed on `fqdns`, so a second `finalize` for the same FQDNs set fails outright (`orderConflict`) while the first is still being processed.
- **`acme_nonces`** backs `new-nonce`/replay protection - a separate pool from the traditional protocol's `used_nonces` (Section 3.4), since ACME's nonce lifecycle (issued speculatively, consumed on first use) is different from a request-bound nonce.

#### 2.7.4. Security Model and Deliberate Simplifications

**JWS verification** (`common/acme_server_utils.py`'s `verify_acme_jws()`) is the single choke point every authenticated endpoint goes through: Content-Type (`application/jose+json`), envelope structure, an algorithm allowlist (`RS256`/`ES256`/`ES384`), the correct `jwk` (new-account only) vs. `kid` (everything else) usage, the signed `url` matching the actual request URL, nonce consumption, and the cryptographic signature itself - built on `josepy` for the underlying JWK/JWS primitives (`Manual.MD`'s Section 2.2), with a hand-written CSR layer alongside it (`common/acme_jose.py`), since `josepy` has no CSR support at all.

**Account confirmation mirrors the traditional protocol's own trust model, with one difference worth understanding.** `cltmanager.py acme_confirm <client-id>` (`Manual.MD`'s Section 6.4/9.10) is the ACME equivalent of `cltmanager.py confirm` (Section 2.4.1) - a required, human, out-of-band step before an account can do anything. The difference: the traditional protocol's `confirm` step lets an admin compare *two* fingerprints (client's and server's - Section 2.3.4), because that protocol has a real mutual-authentication handshake. ACME's account key never proves anything about the server, so `acme_confirm` only ever shows the account's own RFC 7638 thumbprint (rendered as words, same `common/fingerprint_words.py` helper - Section 2.3.4) for the admin to verify against whatever the requesting user/system provided out-of-band; there is no server-side fingerprint to compare it against.

**Optional IP-pinning as a second factor.** For a known, fixed-source-IP client (e.g. a firewall appliance's own ACME client), `cltmanager.py set_allowed_ip <client-id> <ip-or-cidr>` (`Manual.MD`'s Section 6.4/9.10) narrows the blast radius if an account key is ever compromised, on top of the JWS cryptography that already authenticates every request - a request whose source IP doesn't match is rejected with the exact same `403`/`unauthorized`/"Account is not yet confirmed" response as an unconfirmed account, deliberately, so a probing attacker learns nothing about *why* a request was rejected. Checked against the direct TCP peer by default; only trusts `X-Forwarded-For` when that peer is itself the configured `acme_trusted_proxy_ip` (`Manual.MD`'s Section 4.6/5.1) - never from an arbitrary connecting peer, which would otherwise let anyone spoof past the pin simply by setting that header themselves. Off (unrestricted) by default; not a substitute for account confirmation, an additional restriction on top of it.

**What this design deliberately does not do**, and why it's still safe within its own threat model: there is no real DNS-01/HTTP-01/TLS-ALPN-01 challenge validation (Section 2.7.2 above) - authorization is granted purely by the same admin-approval step the traditional protocol already relies on, not by proving control of the domain over the wire. This is a deliberate v1 simplification, not an oversight, and the biggest still-open question about it (`Manual.MD`'s Section 11.5/`ACME_SERVER_DESIGN.md` §11) is whether real, unmodified ACME clients tolerate an authorization object describing a non-standard "already validated by admin" challenge type - a small prototype test against Let's Encrypt staging with a real client is the recommended way to confirm this before relying on it in production. Also out of scope for v1: `revokeCert`, account-key rollover (`keyChange`), and any *real* CAA/challenge-type validation (the upstream CA, if any is used at all in a given deployment's `crtrequest.py` provider, is the one actually performing whatever validation it itself requires) - see `ACME_SERVER_DESIGN.md` `Manual.MD`'s Section 9 for the complete list. External Account Binding, listed as out-of-scope in earlier revisions of this document, is now implemented (Section 2.7.5 below) - as an opt-in auto-approval mechanism, not as the mandatory-EAB mode RFC 8555 §7.3.4 also describes (this server's directory always advertises `externalAccountRequired: false`, since self-registration without any credential remains a fully supported path).

#### 2.7.5. Trusted-Client Auto-Approval (EAB / Contact-Token Grants)

An `AcmeTrustGrant` (`common/database.py`) is an admin-issued, out-of-band pre-shared credential that collapses both manual admin steps (`acme_confirm` and `assign`, Section 2.7.4/`Manual.MD` Section 9.10) into zero-touch automation for a specific, admin-trusted device - `Manual.MD`'s Section 9.11 is the operational walkthrough; this section is the design rationale. Explicitly a reduced-security convenience feature, never the default path: a device presenting a valid grant is trusted *because the admin already decided to trust it* when generating the grant, not because of anything the device itself proves about its own identity beyond "knows this secret."

**Two credential methods, sharing one underlying grant record** (`allowed_fqdns_pattern`, optional `expires_at`, soft `revoked_at`, `use_count`/`last_used_at` for audit) - reusable across many bootstrap events, not single-use, per explicit product decision (2026-09-20):

- **RFC 8555 §7.3.4 External Account Binding.** `cltmanager.py acme_create_eab_grant` generates a `(kid, hmac_key)` pair; the HMAC key is stored encrypted at rest via `common/db_crypto.py`'s `encrypt_for_storage()` (the same envelope `Certificate.private_key` already uses) since, unlike a password, HMAC verification needs the actual secret bytes at verify time, not a one-way hash. Verification (`common/acme_jose.py`'s `verify_eab_jws()`) is a structurally separate code path from the outer JWS's own `verify_acme_jws()` - deliberately never routed through that function's `ALLOWED_JWS_ALGS` allowlist, which excludes every HMAC algorithm specifically to prevent an alg-confusion attack on the *outer* envelope (Section 2.7.4 above); the EAB's inner JWS is explicitly required to be `alg: HS256` by a literal string check, nothing broader. The EAB payload is compared to the account's own asserted JWK by RFC 7638 thumbprint (not raw byte equality), robust to a client re-serializing the same key with different field order.
- **Contact-field token** - the fallback for a client with no EAB support at all (discovered via a real deployment: FortiOS before 7.6.3 exposes only a free-text Email field in its ACME configuration, no EAB fields). `cltmanager.py acme_create_contact_token_grant` generates a high-entropy token, stored only as a SHA-256 hash (no reversible-secret requirement here, since this method only ever needs an equality check). The admin configures the device's contact/email field as a plus-addressed string (`provisioning+<token>@anydomain`); `handle_new_account()` extracts and looks up the token from any `contact` entry matching that shape.

**Hook points** (`common/acme_server_utils.py`): `handle_new_account()` checks for a presented EAB or matching contact-token *before* creating the account row, and if found, creates it already `status='confirmed'` with `Client.trust_grant_id` set - atomically, not via a separate follow-up update (avoiding a window where the row briefly exists unconfirmed). A *claimed* EAB that fails verification is rejected outright (never silently downgraded to a normal pending registration, which would let a wrong/stale credential attempt still produce *some* account to keep retrying against). `handle_new_order()` extends the same `_get_relation(...) is None` first-order guard already in place for renewal-permission persistence: for a trust-granted account's genuinely first order on a given fqdns, if `fqdns_matches_trust_grant()` (glob match via `fnmatch`, re-checking revocation/expiry at request time rather than trusting a stale cached decision) returns true, the `ClientCertificateRelation` is created already `status=1` instead of `0` - the order's externally-visible status is `ready` immediately, with no `assign` ever run.

**Revocation is immediate for new grants, never retroactive for old ones** - `revoke_acme_trust_grant()` sets `revoked_at`, which both `find_active_*()` lookups (blocking new account bootstrapping) and `fqdns_matches_trust_grant()` (blocking new fqdns auto-approval) check; an already-approved `ClientCertificateRelation` from before the revocation is untouched, exactly mirroring how revoking a normal `assign` grant never un-approves a certificate already issued.

---

---

## 3. Database Schema

Accessed entirely through a SQLAlchemy ORM (`common/database.py`) - no tool ever hand-writes SQL against these tables directly (see Section 3.5 for the one exception, `scs-dbmigrate`). `init_database()`'s `Base.metadata.create_all()` creates any missing tables on first use, but never alters an existing one - a database created by an older version of this codebase, before a column/table existed, must be brought up to date with `scs-dbmigrate upgrade-schema` (Section 3.5) before starting any other tool against it; they will refuse to start with a clear error otherwise (`common/database.py`'s `check_schema_is_current()`).

```mermaid
erDiagram
    clients ||--o{ client_certificate_relations : has
    certificates ||--o{ client_certificate_relations : has

    clients {
        int id
        string client_id
        string public_key
        datetime registration_date
        string status
        datetime last_successful_connection
        datetime first_unsuccessful_connection
        int unsuccessful_attempts
        string client_version
    }

    client_certificate_relations {
        int client_id
        string fqdns
        int status
        datetime permission_valid_until
        datetime last_download_at
        datetime last_download_validity_end_date
    }

    certificates {
        int id
        string fqdns
        string public_key
        string private_key
        string intermediates
        datetime validity_end_date
        datetime last_update
        string acme_provider
        bool is_staging
    }

    used_nonces {
        string nonce
        datetime created_at
    }
```

### 3.1. clients

| Column | Type | Notes |
|---|---|---|
| `id` | Integer, primary key, autoincrement | The numeric database ID (what `cltmanager.py`'s commands also accept in place of `client_id`) |
| `client_id` | String, unique, not null | The identifier the client registered under (Section 2.4.1) |
| `public_key` | Text, not null | PEM, as sent at registration |
| `registration_date` | DateTime | Set at registration |
| `status` | String | `registered` (default, also what `revoke` reverts to) or `confirmed` - a free-text column in practice only ever holding these two values |
| `last_successful_connection`, `first_unsuccessful_connection`, `unsuccessful_attempts` | DateTime / DateTime / Integer | Updated automatically (`update_client_connection_success`/`_failure` in `common/database.py`) from `common/network_utils.py`'s `receive_secure_message()`, once per authenticated message from a known, registered client: a successfully-verified message sets `last_successful_connection` to now and resets the other two; a failed signature verification increments `unsuccessful_attempts` and records `first_unsuccessful_connection` on the first failure of a streak. Shown as "Last successful connection" in `admintui`'s Clients tab and by `cltmanager.py list`/`listall`. |
| `client_version` | String, nullable | The `sslcrtsrv` version this client most recently reported (Section 2.2.3's version-advertisement note) - set at registration and refreshed on every subsequent authenticated message. `NULL` for a client that has never connected with a version reporting this field. Shown as "Version" in `admintui`'s Clients tab and per-client detail dialog, and by `cltmanager.py listall`/`list`. |
| `client_kind` | String, not null | `'custom'` (default - a traditional `scs-client` registration) or `'acme'` (an ACME account created via `scs-acme-server`'s `new-account` endpoint - Section 2.7.1/2.7.3). Everything else in this table and in `client_certificate_relations` (Section 3.3) is shared identically by both kinds. |
| `acme_key_thumbprint` | String, unique, nullable | RFC 7638 JWK thumbprint (base64url) - an ACME account's identity (Section 2.7.4). `NULL` for a `client_kind='custom'` row. |
| `acme_contact` | Text, nullable | The account's optional contact URL(s), as submitted/updated via the ACME protocol's own account-update endpoint (Section 2.7.2) - JSON-encoded. `NULL` for a `client_kind='custom'` row, or an ACME account that never set one. |
| `allowed_source_ip` | String, nullable | Optional IP-pinning restriction (`Manual.MD`'s Section 9.10) - a bare IP or CIDR network string. `NULL` (the default) means unrestricted. Set via `cltmanager.py set_allowed_ip`; enforced only for ACME accounts, never for the traditional protocol. |
| `trust_grant_id` | Integer, FK -> `acme_trust_grants.id`, nullable | Which trust grant (Section 3.7), if any, auto-confirmed this account (Section 2.7.5). `NULL` for every normally-self-registered account and every `client_kind='custom'` row. |

### 3.2. certificates

| Column | Type | Notes |
|---|---|---|
| `id` | Integer, primary key, autoincrement | The numeric ID `crtmanager.py`/`cltmanager.py` accept in place of a FQDNs set, and what Section 2.4.3's `cert-<id>` acme.sh working-directory naming uses. Before Section 3.5's pluggable backends, `fqdns` was this table's primary key and there was no separate `id` column - callers used SQLite's own implicit, backend-specific `rowid` instead (`fixed-issues.md`). |
| `fqdns` | String(512), unique, not null, indexed | The comma-separated FQDNs set. Not the primary key, but still the natural business key everything else joins on. |
| `public_key` | Text, not null | Plaintext PEM - not sensitive. |
| `private_key` | Text | Empty for a not-yet-issued placeholder; `ENC1:`-prefixed ciphertext once encrypted (Section 2.3.3); legacy plaintext PEM if added before that feature existed and not yet migrated. |
| `intermediates` | Text | Plaintext PEM. |
| `validity_end_date` | DateTime, not null | A stub past date (`2020-01-01`) for a placeholder row; the certificate's real expiry once issued. |
| `last_update` | DateTime | Set automatically on insert, and again whenever the row is updated with real data. |
| `acme_provider` | String | Defaults to the server's configured default; `manual` permanently excludes it from `crtrequest.py` (Section 2.4.3). |
| `is_staging` | Boolean | Corrected against the certificate's actual issuer field, not just trusted from whatever was requested (Section 2.4.5). |
| `key_fingerprint` | String, nullable, indexed | Public-key fingerprint of whichever key this row's `public_key` certificate was issued for - populated for both traditionally-issued and ACME-issued (Section 2.7.3) certificates once one exists; `NULL` for a not-yet-issued placeholder. |

### 3.3. client_certificate_relations

The many-to-many link between clients and certificates - composite primary key `(client_id, fqdns)`, so one row per client/FQDNs-set pair.

| Column | Type | Notes |
|---|---|---|
| `client_id` | Integer, FK -> `clients.id` | Part of the composite primary key. |
| `fqdns` | String, FK -> `certificates.fqdns` | Part of the composite primary key. **Not** required to already exist in `certificates` at insert time - this is exactly how a brand-new client request creates a relation row before any certificate has ever been issued for it (Section 2.4.2). SQLite doesn't enforce this FK by default (no `PRAGMA foreign_keys=ON` is ever set), which is what makes that ordering possible at all. |
| `status` | Integer, not null, `CHECK (status IN (0, 1))` | `0` = pending/unassigned, `1` = approved/active (Section 2.4.2). |
| `permission_valid_until` | DateTime | Optional automatic expiry for this specific FQDNs grant, independent of the certificate's own `validity_end_date`. `NULL` (the default) means the permission never expires on its own. Enforced live at access time by `common/database.py`'s `permission_is_active()` - every access check treats a permission whose `permission_valid_until` has passed exactly like one with `status=0`, without needing a background job to flip `status` itself. Set via `cltmanager.py assign --valid-until`/`set_expiry` or the equivalent `admintui` fields (Section 2.4.2, `Manual.MD`'s Section 6.4). |
| `last_download_at` | DateTime, nullable | When this client last successfully retrieved this certificate (Section 2.4.4's download-tracking note). `NULL` means never. |
| `last_download_validity_end_date` | DateTime, nullable | Snapshot of `certificates.validity_end_date` *at the moment of that download* - not the live value, which a later renewal overwrites in place. Compared against the current live value by `scs-crtmanager warn-stale-downloads` (`Manual.MD`'s Section 6.3) to flag a client still running a since-superseded copy. `NULL` iff `last_download_at` is `NULL`. |

### 3.4. used_nonces

One shared pool of nonces backing both registration's and every general request's anti-replay check (`common/database.py`'s `consume_nonce()`, Section 2.3.6 point 3) - a single table rather than one per use, since a collision between a registration nonce and a request nonce is as cryptographically negligible as a collision between two different clients' nonces.

| Column | Type | Notes |
|---|---|---|
| `nonce` | String, primary key | One row per accepted registration attempt (Section 2.3.4) or general request (Section 2.3.6 point 3) - never updated, only inserted or pruned. |
| `created_at` | DateTime | Used to prune nonces older than the relevant window (`REGISTRATION_TIMESTAMP_WINDOW_SECONDS` for registration, `REQUEST_TIMESTAMP_WINDOW_SECONDS` for everything else) on every subsequent `consume_nonce()` call. |

No foreign key to any other table - it exists purely to make a captured message un-replayable, independent of which client, server, or request type it belongs to. An existing installation's old `registration_nonces` table (from before this rename) is dropped automatically by `scs-dbmigrate upgrade-schema` (`alembic/versions/0005_drop_registration_nonces.py`) - `used_nonces` itself isn't Alembic-managed, like its predecessor, and is simply (re)created by `init_database()`'s `create_all()` on any install that doesn't have it yet.

### 3.5. Pluggable Database Backends

SQLite is the default and requires no configuration - a single file under `data_dir` (`Manual.MD`'s Section 8.1.2), no separate database server to run. MySQL/MariaDB and PostgreSQL are also fully supported, for deployments that already run a shared/remote database server, need a warmer standby than file-level backup of a SQLite file provides, or want the server's data alongside other services managed by the same DBMS.

The backend is selected in `server_config.json`'s optional `database` key (`Manual.MD`'s Section 5.1):

```json
"database": {
    "backend": "mysql",
    "mysql": {
        "host": "db.internal", "port": 3306,
        "user": "sslcrtsrv", "password": "...", "database": "sslcrtsrv"
    }
}
```

Omitting `database` entirely (or setting `"backend": "sqlite"`) is exactly today's `data_dir`-based SQLite behavior - no existing installation needs to change anything. For `"mysql"`/`"postgresql"`, the matching sub-section's `host`/`port`/`user`/`password`/`database` fields build the connection; `port` defaults to 3306/5432 respectively if omitted. `server.py init`'s `--db-backend {sqlite,mysql,postgresql}`/`--db-host`/`--db-port`/`--db-user`/`--db-password`/`--db-name` flags (`Manual.MD`'s Section 6.1) and `admintui`'s Config tab (`Manual.MD`'s Section 7.6) both write this same section - the CLI upserts it the same way `--notifier` upserts a named notifier, and the Config tab's form merges onto whatever's already saved so switching backends there and back never drops the other backend's connection details.

Connecting to MySQL requires the `PyMySQL` Python package installed (Debian: `python3-pymysql`); PostgreSQL requires `psycopg2` (Debian: `python3-psycopg2`) - both are optional `pip`/Debian dependencies, pulled in only if that backend is actually configured (`setup.cfg`'s `mysql`/`postgresql` extras), so a SQLite-only install needs neither. MySQL/MariaDB's `client_id`/`fqdns` columns are pinned to a case-sensitive binary collation, matching SQLite's/PostgreSQL's own case-sensitive default behavior (MySQL's default collation is case-insensitive, which would otherwise let e.g. two client IDs differing only in case collide).

**Setting up a fresh installation directly on MySQL/PostgreSQL** (no existing SQLite data to migrate): the database/user must already exist on the DB server - nothing in this project runs `CREATE DATABASE` or creates DB users/grants, only `CREATE TABLE`s within an already-existing, empty database. On the DB server:

```sql
-- MySQL/MariaDB
CREATE DATABASE sslcrtsrv CHARACTER SET utf8mb4;
CREATE USER 'sslcrtsrv'@'%' IDENTIFIED BY '...';
GRANT ALL PRIVILEGES ON sslcrtsrv.* TO 'sslcrtsrv'@'%';

-- PostgreSQL
CREATE DATABASE sslcrtsrv;
CREATE USER sslcrtsrv WITH PASSWORD '...';
GRANT ALL PRIVILEGES ON DATABASE sslcrtsrv TO sslcrtsrv;
```

Then on the sslcrtsrv server host: `sudo scs-server init --db-backend mysql --db-host ... --db-port ... --db-user ... --db-password ... --db-name ...` (or `admintui`'s Config tab, `Manual.MD`'s Section 7.6) - this only writes the `database` section into `server_config.json`, it does not touch the database itself. The first time any tool then runs against that config (starting `server.py`, or any of `crtmanager.py`/`cltmanager.py`/`crtrequest.py`/`admintui`), `init_database()`'s `Base.metadata.create_all()` creates every table automatically - **no `scs-dbmigrate` step is needed for a brand-new backend**; that tool exists only for bringing an *existing* database's schema up to date, or copying *already-populated* data to a different backend (below).

**Schema upgrades and cross-backend migration** are deliberately kept out of every day-to-day tool (`server.py`/`crtmanager.py`/`cltmanager.py`/`admintui`) - they only ever create a fresh, empty, up-to-date schema on first run, and refuse to start with a clear error (`SchemaOutOfDate`) against an existing database whose schema predates the running code, rather than silently attempting to alter it. All schema evolution and backend migration is the job of the separate `scs-dbmigrate` tool (`Manual.MD`'s Section 6.8), which is also the only place in the codebase that uses Alembic:

- `scs-dbmigrate upgrade-schema` brings an existing database's schema up to date in place (e.g. adding `certificates.id` to a pre-existing installation) - run this once after upgrading `sslcrtsrv` past a version that changed the schema, before starting any other tool. Safe to run against a brand-new or already-current database too (a clean no-op in both cases).
- `scs-dbmigrate migrate --to-backend {sqlite,mysql,postgresql}` copies every client/certificate/permission row to a freshly created target backend, then repoints `server_config.json` at it - the source backend/data is left untouched, so the change can be rolled back by editing the config back if needed. Short-lived registration-nonce anti-replay state is deliberately not copied; the only effect of skipping it is a harmless one-time re-registration window for any client mid-handshake at the moment of migration.

### 3.6. ACME Tables: acme_orders, acme_certificates, acme_processing_locks, acme_nonces

```mermaid
erDiagram
    clients ||--o{ acme_orders : "places (account_client_id)"
    certificates ||--o{ acme_orders : "issues for (fqdns)"
    acme_orders ||--o| acme_certificates : "yields (order_id, immutable)"
    acme_orders ||--o| acme_processing_locks : "holds (order_id + fqdns)"

    acme_orders {
        int id
        int account_client_id
        string fqdns
        text identifiers_json
        text csr_pem
        string csr_key_fingerprint
        string status
        datetime created_at
        datetime expires_at
        datetime finalized_at
        int issuance_attempts
        datetime last_issuance_attempt_at
        text last_issuance_error
        datetime next_issuance_attempt_at
    }

    acme_certificates {
        int id
        int order_id
        text certificate_pem
        text intermediates
        string key_fingerprint
        datetime validity_end_date
        datetime created_at
    }

    acme_processing_locks {
        string fqdns
        int order_id
        datetime locked_at
    }

    acme_nonces {
        string nonce
        datetime created_at
    }
```

| Table | Column | Notes |
|---|---|---|
| **`acme_orders`** | `id` | Primary key - what `order/<id>`/`authz/<id>/<n>`/`chall/<id>/<n>`/`cert/<id>` URLs are built from. |
| | `account_client_id` | FK -> `clients.id` - the ACME account that placed this order. |
| | `fqdns` | FK -> `certificates.fqdns` - the same comma-joined FQDNs convention the traditional protocol uses (Section 3.2), so `is_acme_managed()`/traditional-loop guards (Section 2.7.1) can compare directly. |
| | `identifiers_json` | The order's identifiers, exactly as submitted to `new-order`, JSON-encoded - preserved verbatim for `order/<id>` polling responses. |
| | `csr_pem` / `csr_key_fingerprint` | Set only once `finalize` succeeds (Section 2.7.2) - `NULL` beforehand. The CSR's own public-key fingerprint, checked against the account key at `finalize` time (the account-key-vs-CSR-key rejection - `ACME_SERVER_DESIGN.md` §5.10/§11 risk 5). |
| | `status` | `pending` (created, not yet finalized) -> `processing` (finalized, queued for `crtrequest.py`) -> `valid` (issued) or `invalid` (expired, or failed past `acme_max_issuance_attempts`). Never goes backward. |
| | `created_at` / `expires_at` | `expires_at` (`acme_order_ttl_days` after creation, `Manual.MD`'s Section 5.1) is what the cleanup pass (`Manual.MD`'s Section 4.6 point 4) checks. |
| | `finalized_at` | Set the moment `finalize` succeeds - the authoritative "has this order been finalized" marker `authorization_status()`/`challenge_status()` (Section 2.7.2) key off, deliberately never inferred from `status` alone, since `status` also changes for reasons unrelated to finalization (expiry, issuance failure). |
| | `issuance_attempts`, `last_issuance_attempt_at`, `last_issuance_error`, `next_issuance_attempt_at` | `crtrequest.py`'s retry bookkeeping (`Manual.MD`'s Section 6.3/9.10) - capped exponential backoff between attempts, up to `acme_max_issuance_attempts` before the order is invalidated. |
| **`acme_certificates`** | `id` | Primary key. |
| | `order_id` | FK -> `acme_orders.id`, **unique** - exactly one certificate per order, ever (Section 2.7.3's immutability note). |
| | `certificate_pem` / `intermediates` / `key_fingerprint` / `validity_end_date` | The issued certificate itself - a permanent, never-overwritten snapshot of what this specific order produced, independent of whatever the shared `certificates` row looks like later. |
| **`acme_processing_locks`** | `fqdns` | Primary key - at most one row per FQDNs set, ever, is the entire mechanism behind "at most one order per FQDNs set may be `processing` at a time" (Section 2.7.3). |
| | `order_id` | Which order currently holds this FQDNs set's lock. Released (row deleted) scoped by **both** `fqdns` and `order_id` together, never `fqdns` alone - releasing by `fqdns` alone would risk deleting a *different*, newer order's lock during a race between an expiring order and a fresh one re-acquiring the same FQDNs set (`ACME_SERVER_DESIGN.md` §4.4.1's concurrency analysis; verified by `tests/test_acme_concurrency.py`, `Manual.MD`'s Section 9.10). |
| | `locked_at` | When the lock was acquired - purely informational, not itself used for expiry (the order's own `expires_at` is). |
| **`acme_nonces`** | `nonce` | Primary key - the ACME protocol's own nonce pool (`new-nonce`, Section 2.7.2), separate from the traditional protocol's `used_nonces` (Section 3.4). |
| | `created_at` | Pruned opportunistically (older than `acme_nonce_ttl_seconds`, `Manual.MD`'s Section 5.1) every time a new nonce is issued. |

Deleting an ACME account (`cltmanager.py delete`, `Manual.MD`'s Section 6.4/9.8) cascades through all three order-related tables first - every `acme_processing_locks`/`acme_certificates`/`acme_orders` row belonging to that account's orders is removed before the `client_certificate_relations` cleanup the traditional protocol already does, inside the same transaction.

### 3.7. acme_trust_grants

| Column | Type | Notes |
|---|---|---|
| `id` | Integer, primary key, autoincrement | What `clients.trust_grant_id` (Section 3.1) references. |
| `label` | Text, not null | Admin-facing name only - never shown to, or presented by, the ACME client itself. |
| `eab_kid` | String, unique, nullable | RFC 8555 §7.3.4 External Account Binding key ID (Section 2.7.5) - set only for an `eab`-method grant. |
| `eab_hmac_key_encrypted` | Text, nullable | The EAB HMAC key, encrypted at rest via `common/db_crypto.py`'s `encrypt_for_storage()` - the same envelope `certificates.private_key` uses. Unlike a password, this must stay decryptable (HMAC verification needs the real key bytes), so it's encrypted, never one-way hashed. |
| `contact_token_hash` | String, unique, nullable | SHA-256 hex of a contact-token-method grant's raw token - set only for that method. Only ever needs an equality check, so a one-way hash is sufficient (unlike the EAB key above). |
| `allowed_fqdns_pattern` | Text, not null | Comma-separated glob pattern(s) (`fnmatch` semantics - `*` matches across dots too), checked against a `new-order` request's fqdns (Section 2.7.5) to decide whether to auto-approve it. |
| `created_at` | DateTime, not null | |
| `expires_at` | DateTime, nullable | Optional - `NULL` means the grant never expires on its own. |
| `revoked_at` | DateTime, nullable | Soft-revoke timestamp (`cltmanager.py acme_revoke_trust_grant`) - kept for audit history rather than deleting the row outright. |
| `last_used_at`, `use_count` | DateTime, Integer | Bumped each time the grant actually auto-confirms an account (not on every lookup attempt) - `cltmanager.py acme_list_trust_grants`' audit trail. |

Exactly one of `eab_kid`+`eab_hmac_key_encrypted` or `contact_token_hash` is set per row, enforced in `common/database.py`'s `create_acme_trust_grant()` rather than a DB constraint (simpler, portable across all three backends). No cascade concern on `clients` deletion in this direction - `trust_grant_id` is a nullable FK *from* `clients` *to* this table, and a grant is designed to be reused across many accounts/devices, so deleting one client must never touch the grant it was created through.

---

---

## 4. Status Codes and Constants Glossary

| Value | Meaning |
|---|---|
| `Client.status`: `registered` | Default on registration; also what `revoke` reverts to (Section 2.4.1) |
| `Client.status`: `confirmed` | Set by `confirm`/onboarding approval |
| `ClientCertificateRelation.status`: `0` | Pending/unassigned request (Section 2.4.2) |
| `ClientCertificateRelation.status`: `1` | Approved/active - the client may retrieve this certificate once issued |
| `Certificate.acme_provider`: `letsencrypt` / `buypass` / `google` / `zerossl` / `sslcom` | Known ACME CAs `crtrequest.py` maps to their staging/production `--server` values (Section 2.4.5) |
| `Certificate.acme_provider`: `manual` | Permanently excluded from `crtrequest.py`'s automation (Section 2.4.3) |
| `Certificate.acme_provider`: *(anything else)* | Passed straight through to `acme.sh --server` as a raw ACME directory URL - no known staging equivalent |
| `Certificate.is_staging` | Whether the currently stored certificate is from the CA's staging/test environment (Section 2.4.5) |
| Message `type`: `register` / `status` / `listcerts` / `request` / `response` / `congestion` | Top-level protocol message types (Section 2.2.3) - `congestion` is defined but never actually sent by the server today |
| `request_type`: `certificate` / `certificates` / `info` / `retrieve` / `listcerts` / `version` | Sub-type of a `request` message (Section 2.2.3) - `version` returns the server's own version, no other data |
| `client_version` / `server_version` | Informational version fields carried on every `register`/`request` and every `response` respectively (Section 2.2.3) - not a protocol-version negotiation |
| `ClientCertificateRelation.last_download_at` / `.last_download_validity_end_date` | When/what a client last successfully retrieved for a given certificate (Section 3.3) - `NULL` means never downloaded |
| `sslcrtsrv/PACKAGE_TYPE` marker: `deb` / `tarball` | This install's package type, embedded at build time (Section 2.2.2) - absent entirely on a development checkout |
| `Client.client_kind`: `custom` / `acme` | Traditional `scs-client` registration vs. an ACME account created via `scs-acme-server` (Section 2.7.1/3.1) |
| `AcmeOrder.status`: `pending` / `processing` / `valid` / `invalid` | ACME order lifecycle (Section 3.6) - never goes backward; `invalid` is terminal (expired, or exhausted `acme_max_issuance_attempts`) |
