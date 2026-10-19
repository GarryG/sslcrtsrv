# RPM spec for sslcrtsrv, mirroring the debian/ packaging's split into two
# binary packages: sslcrtsrv-client (scs-client only) and sslcrtsrv-server
# (everything else, depending on sslcrtsrv-client for the shared code/
# package metadata). See debian/control's long descriptions and
# debian/sslcrtsrv-{client,server}.install for the authoritative file split
# this spec reproduces.
#
# Built by .github/workflows/release.yml in a Fedora/EPEL-compatible
# container (needs python3-rpm-macros for %{python3_sitelib} and the
# %pycached macro used below to let a single Python package's modules be
# split across two subpackages without rpmbuild's "unpackaged files" check
# tripping over the separately-generated __pycache__ entries).
#
# Pure Python, no compiled extensions in this project itself (cryptography's
# own C/Rust extension is an external dependency, resolved from the distro's
# python3-cryptography package) - both subpackages are noarch, exactly like
# debian/control's "Architecture: all".

%global srcname sslcrtsrv

Name:           sslcrtsrv
Version:        %{?version}%{!?version:0.0.0}
Release:        1%{?dist}
Summary:        SSLCrtSrv certificate management client/server tools
# Not an SPDX-recognized identifier - see debian/copyright's own note.
# Functional Source License 1.1, ALv2 Future variant: source-available now,
# converts to Apache-2.0 two years after each release. See LICENSE.
License:        FSL-1.1-ALv2
URL:            https://github.com/GarryG/sslcrtsrv
Source0:        %{srcname}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-rpm-macros

%description
SSLCrtSrv is a self-hosted client/server system for centrally requesting,
issuing, and securely distributing TLS certificates to any number of
registered client hosts. This source package builds two binary packages,
sslcrtsrv-client and sslcrtsrv-server - install whichever matches the role
of this particular host.

%package client
Summary:        SSLCrtSrv client - request and retrieve managed certificates
Requires:       python3-cryptography
%if 0%{?fedora} || 0%{?rhel} >= 9
Recommends:     python3-rich
%endif

%description client
Client tool (scs-client) for the SSLCrtSrv certificate management system:
registers a host with an SSLCrtSrv server, requests certificates for given
FQDNs, and retrieves issued key/certificate/intermediate files.

python3-rich is optional: scs-client listcerts/info fall back to plain text
output without it, rather than requiring it.

Install sslcrtsrv-server instead on the host running the certificate server
itself.

%package server
Summary:        SSLCrtSrv server - certificate management server and admin tools
Requires:       %{name}-client = %{version}-%{release}
Requires:       python3-cryptography
Requires:       python3-sqlalchemy
Requires:       python3-alembic
Requires:       python3-textual
Requires:       python3-pytz
Requires:       python3-rich
Requires(pre):  shadow-utils
%if 0%{?fedora} || 0%{?rhel} >= 9
Recommends:     bind-utils
Suggests:       python3-pymysql
Suggests:       python3-psycopg2
Suggests:       python3-josepy
Suggests:       python3-maxminddb
%endif

%description server
Server-side tools for the SSLCrtSrv certificate management system:

 * scs-server - the TCP server clients register/request against
 * scs-crtmanager / scs-cltmanager - certificate and client administration
   CLIs
 * scs-crtrequest - requests/renews certificates via acme.sh
 * scs-admintui - full-screen terminal admin dashboard
 * scs-dbmigrate - one-time schema upgrades and cross-backend data
   migration for the database (SQLite by default; MySQL/MariaDB and
   PostgreSQL are also supported, see Manual.MD)
 * scs-acme-server - optional RFC 8555 ACME protocol server, letting other
   ACME clients request certificates through this server instead of (or
   alongside) the native scs-client protocol

acme.sh itself is not packaged here and must be installed separately
(see https://github.com/acmesh-official/acme.sh) if you intend to use
scs-crtrequest. bind-utils (for `dig`) is needed for scs-crtrequest's DNS
delegation check, which runs by default (pass --no-check-dns to skip it).

python3-pymysql/python3-psycopg2 are only needed if you configure the
MySQL/MariaDB or PostgreSQL database backend respectively - the default
SQLite backend needs neither. python3-josepy is only needed if you run
scs-acme-server. python3-maxminddb is only needed for GeoIP country-based
access control with the default "maxmind" geoip_backend; the alternative
"ip2location" backend has no Fedora/EPEL package and needs
`pip install IP2Location` into a venv instead.

%prep
%autosetup -n %{srcname}-%{version}

%build
%py3_build

%install
%py3_install

# Marker file read at runtime by common/client_utils.py's
# detect_package_type() (scs-client update) - "rpm" here, the same way
# debian/rules writes "deb" and build-tarballs.py writes "tarball" into the
# identical path for their own builds.
echo rpm > %{buildroot}%{python3_sitelib}/%{srcname}/PACKAGE_TYPE

# Man pages (setup.cfg/setuptools has no concept of these - installed
# directly from the source tree, same files debian/*.manpages reference).
install -d %{buildroot}%{_mandir}/man1
for page in man/*.1 ; do
    install -Dm644 "$page" %{buildroot}%{_mandir}/man1/$(basename "$page")
done
# Not packaged publicly (see .gitattributes/publish_public_repo.py - the
# web_admin PHP bridge is excluded from the public release entirely).
rm -f %{buildroot}%{_mandir}/man1/scs-web-admin-bridge.1
rm -f %{buildroot}%{_bindir}/scs-web-admin-bridge
rm -f %{buildroot}%{python3_sitelib}/%{srcname}/web_admin_bridge.py

# systemd units - same unit files debian/ ships (User=/Group=sslcrtsrv,
# /etc/sslcrtsrv + /opt/sslcrtsrv paths are this project's own convention,
# not Debian-specific), installed but not enabled/started, matching
# debian/rules' `dh_installsystemd --no-enable --no-start`.
install -Dm644 debian/sslcrtsrv-server.service \
    %{buildroot}%{_unitdir}/sslcrtsrv-server.service
install -Dm644 debian/sslcrtsrv-server.sslcrtsrv-acme-server.service \
    %{buildroot}%{_unitdir}/sslcrtsrv-acme-server.service

%pre server
# Dedicated system account the server processes run as (sslcrtsrv-server.service/
# sslcrtsrv-acme-server.service's User=/Group=) - see debian/sslcrtsrv-server.postinst
# for the identical rationale this mirrors.
getent group sslcrtsrv >/dev/null || groupadd -r sslcrtsrv
getent passwd sslcrtsrv >/dev/null || \
    useradd -r -g sslcrtsrv -d /opt/sslcrtsrv -s /sbin/nologin \
        -c "SSLCrtSrv server" sslcrtsrv
exit 0

%files client
%license LICENSE
%doc README.md
%{python3_sitelib}/%{srcname}-%{version}-py%{python3_version}.egg-info/
%dir %{python3_sitelib}/%{srcname}
%dir %{python3_sitelib}/%{srcname}/common
%pycached %{python3_sitelib}/%{srcname}/__init__.py
%{python3_sitelib}/%{srcname}/PACKAGE_TYPE
%pycached %{python3_sitelib}/%{srcname}/client.py
%pycached %{python3_sitelib}/%{srcname}/common/__init__.py
%pycached %{python3_sitelib}/%{srcname}/common/auth_failure_tracker.py
%pycached %{python3_sitelib}/%{srcname}/common/client_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/config_watcher.py
%pycached %{python3_sitelib}/%{srcname}/common/constants.py
%pycached %{python3_sitelib}/%{srcname}/common/crypto_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/fingerprint_words.py
%pycached %{python3_sitelib}/%{srcname}/common/fqdns_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/geoip_acl.py
%pycached %{python3_sitelib}/%{srcname}/common/http_abuse_tracker.py
%pycached %{python3_sitelib}/%{srcname}/common/logging_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/message_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/network_acl.py
%pycached %{python3_sitelib}/%{srcname}/common/network_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/notify_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/server_utils.py
%pycached %{python3_sitelib}/%{srcname}/common/system_utils.py
%{_bindir}/scs-client
%{_mandir}/man1/scs-client.1*

%files server
%pycached %{python3_sitelib}/%{srcname}/server.py
%pycached %{python3_sitelib}/%{srcname}/crtmanager.py
%pycached %{python3_sitelib}/%{srcname}/cltmanager.py
%pycached %{python3_sitelib}/%{srcname}/crtrequest.py
%pycached %{python3_sitelib}/%{srcname}/acme_server.py
%pycached %{python3_sitelib}/%{srcname}/common/database.py
%pycached %{python3_sitelib}/%{srcname}/common/db_crypto.py
%pycached %{python3_sitelib}/%{srcname}/common/acme_jose.py
%pycached %{python3_sitelib}/%{srcname}/common/acme_server_utils.py
%{python3_sitelib}/%{srcname}/admintui/
%{python3_sitelib}/%{srcname}/alembic/
%pycached %{python3_sitelib}/%{srcname}/dbmigrate.py
%{_bindir}/scs-server
%{_bindir}/scs-crtmanager
%{_bindir}/scs-cltmanager
%{_bindir}/scs-crtrequest
%{_bindir}/scs-admintui
%{_bindir}/scs-dbmigrate
%{_bindir}/scs-acme-server
%{_mandir}/man1/scs-server.1*
%{_mandir}/man1/scs-crtmanager.1*
%{_mandir}/man1/scs-cltmanager.1*
%{_mandir}/man1/scs-crtrequest.1*
%{_mandir}/man1/scs-admintui.1*
%{_mandir}/man1/scs-dbmigrate.1*
%{_mandir}/man1/scs-acme-server.1*
%{_unitdir}/sslcrtsrv-server.service
%{_unitdir}/sslcrtsrv-acme-server.service

%changelog
* Mon Oct 19 2026 Garry Glendown <sslcrtsrv@mlfwd.de> - 0.9.8-1
- Initial RPM packaging, mirroring the existing Debian client/server split.
  See CHANGELOG.md (generated from debian/changelog) for the full history.
