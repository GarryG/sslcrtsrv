![](sslcrtsrv-med.png)

# SSLCrtSrv

SSLCrtSrv is a self-hosted client/server system for centrally requesting, issuing, and securely distributing TLS certificates - via ACME DNS-01 automation or manual upload - to any number of registered client hosts. One administrator, and one server, replace per-host manual certificate handling across an entire fleet.

With maximum public TLS certificate lifetimes headed down to 47 days by 2029 (CA/Browser Forum), manual renewal across more than a handful of hosts stops being practical. ACME automates issuance itself, but its challenge types assume things that aren't always true - that the certificate's own host is reachable over HTTP, or that whoever needs the certificate also controls the domain's DNS. SSLCrtSrv exists to close that gap: a client host never needs direct DNS-provider or ACME-account credentials, only an authenticated, end-to-end encrypted relationship with the central server, which handles issuance, renewal, and authorization centrally. The canonical case is an ISP or hosting provider issuing and renewing certificates for many customer domains without handing out shared ACME/DNS credentials to every customer host.

**Please note:** while extensively tested in-house, this software is not yet considered production-ready.

## Key Features

- Central inventory of certificates - manually uploaded and ACME-issued certificates side by side, both manageable through the same tools.
- Per-client, per-FQDNs-set authorization, with a certificate assignable to multiple clients.
- A mutually authenticated, end-to-end encrypted client/server protocol - no dependency on TLS at the transport layer.
- Automated ACME issuance/renewal via `acme.sh`, including a CNAME-delegation scheme for organizations whose primary DNS can't accept dynamic updates.
- At-rest encryption of stored certificate private keys.
- Config-file live reload - the server restarts itself automatically when its configuration changes.
- A full-screen terminal admin dashboard (`admintui`) for day-to-day certificate and client administration.
- Optional admin notifications (email, Pushover, Gotify, ntfy, generic webhooks, and more) on client registration, certificate requests, and server errors.
- Packaged as native Debian packages (client/server split) and as distribution-agnostic tarballs.

## Documentation

**[Manual.MD](Manual.MD)** is the authoritative reference for everything beyond this overview: architecture and protocol details, the security/encryption model, installation and deployment (Debian packages and tarballs), the full configuration and command-line reference, the `admintui` dashboard guide, the database schema, administration workflows, notifications, and troubleshooting.

To get started, see the Manual's [Initial Setup Walkthrough](Manual.MD#43-initial-setup-walkthrough) (server init, client registration, first certificate request) and [Installation and Deployment](Manual.MD#4-installation-and-deployment) sections.

## Disclaimer and Disclosure

This project has been developed with a varying involvement of AI tools. Especially for the planning stage, detailed documents of functionality, security precautions, etc were generated based on detailed descriptions, and ran through multiple AI services (Claude, Gemini, ChatGPT and DeepSeek) with multiple iterations to weed out holes or errors in the project definition. The AI-generated content was then reviewed to hopefully ensure no "halucinations" made it in the final definitions (though running through different LLMs appeared to have ironed out most every problem I was able to find).

During coding, AI (Claude in this case) was also used to varying degrees. Especially for the ACME server or InternetX integration, code was almost exclusively implemented by AI assistance, with the generated code as well as updates being reviewed and tested by me. Library functions were partly generated or rewritten.

AI was used for extensive security reviews, with resulting findings being checked, evaluated and at least partially implemented by AI.

All of the documentation was generated and kept in sync with the code and updated by AI, with proof-reading by myself.

The project has been in development and testing for well over a year at this point, and used to supply SSL certificates for multiple production services. Still, I can't guarantee it will work for everybody, and every use case. It fits my personal requirements, though I have tried to keep it generic enough so that adaption to other setups should be easily possible.


## ⚖️ License & Commercial Use

This software is provided under the **Functional Source License (FSL)**.

### For Individuals & Non-Commercial Use
You are free to use, modify, and distribute these tools for personal projects, educational purposes, or non-profit work at no cost.

See the [LICENSE](LICENSE) file for the full license text and commercial-use terms.

