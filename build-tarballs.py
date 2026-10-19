#!/usr/bin/env python3
"""
Build plain, Linux-distribution-agnostic tarballs for sslcrtsrv's client and
server components - an alternative to the Debian .deb packages in debian/,
for hosts that aren't Debian/Ubuntu-based (or that just don't want dpkg).
Each tarball is meant to be a candidate entry in a server's client_packages
catalog alongside the .deb (see common/constants.py's
CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX and server.py init --client-package).

Deliberately has no separate, hand-maintained copy of anything already
defined elsewhere - everything is derived from the existing single sources
of truth, so this can't quietly drift out of sync with them:
  - which files belong in "client" vs "server": debian/sslcrtsrv-*.install
  - runtime dependencies: setup.cfg's install_requires/extras_require
  - console commands to document: setup.cfg's entry_points, cross-referenced
    against the file list above to see which ones actually ship in each archive
  - version number: src/sslcrtsrv/__init__.py's __version__

Usage:
    python3 build-tarballs.py [--output-dir DIR]

Produces (default --output-dir: dist/, already in .gitignore):
    sslcrtsrv-client-<version>-generic.tar.gz
    sslcrtsrv-server-<version>-generic.tar.gz
"""

import argparse
import configparser
import os
import shutil
import sys
import tarfile
import tempfile

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(REPO_ROOT, "src")
DEBIAN_DIR = os.path.join(REPO_ROOT, "debian")
SETUP_CFG_PATH = os.path.join(REPO_ROOT, "setup.cfg")
MAN_DIR = os.path.join(REPO_ROOT, "man")

DIST_PACKAGES_PREFIX = "usr/lib/python3/dist-packages/"

CLIENT_INSTALL_FILE = os.path.join(DEBIAN_DIR, "sslcrtsrv-client.install")
SERVER_INSTALL_FILE = os.path.join(DEBIAN_DIR, "sslcrtsrv-server.install")

COMPONENTS = {
    "client": {
        # Self-contained on its own.
        "install_files": [CLIENT_INSTALL_FILE],
        "extras": None,
    },
    "server": {
        # debian/control's sslcrtsrv-server Depends: sslcrtsrv-client, so
        # apt guarantees both packages' files land in the same directory -
        # sslcrtsrv-server.install alone is only ever a *fragment* on top of
        # sslcrtsrv-client's files, not a complete tree (common/__init__.py
        # imports from every module in common/, client-only ones included).
        # A standalone tarball has no such "combine with another archive"
        # mechanism, so this pulls in both files' paths - the "Depends"
        # relationship, made literal as "also bundled in".
        "install_files": [CLIENT_INSTALL_FILE, SERVER_INSTALL_FILE],
        "extras": "server",
    },
}


def get_version():
    """Read sslcrtsrv.__version__ - the single source of truth also used by
    debian/rules' build-time consistency check and the client's own `update`
    command."""
    sys.path.insert(0, SRC_DIR)
    import sslcrtsrv
    return sslcrtsrv.__version__


# debian/sslcrtsrv-server.install deliberately omits these two: in the .deb
# world, sslcrtsrv-server just Depends: sslcrtsrv-client and gets them from
# that package's files on the same filesystem. A standalone tarball has no
# such "combine with another package" mechanism - without its own copy of
# these, `import sslcrtsrv`/`from .common import ...` fail outright (proven
# by actually extracting a build and importing it in a clean venv with no
# sslcrtsrv already installed anywhere on sys.path - see this script's
# commit message/PR description for how that surfaced). Every component's
# archive must be self-contained, so these are always included regardless
# of which .install file "owns" them for Debian's inter-package purposes.
ALWAYS_REQUIRED_PATHS = ["sslcrtsrv/__init__.py", "sslcrtsrv/common/__init__.py"]



# Written into place by debian/rules' override_dh_auto_install at .deb
# build time (see that file and debian/sslcrtsrv-client.install's comment) -
# has no counterpart in the source tree, so it can't be copied like every
# other path in that .install file. write_package_type_marker() below
# writes this tarball's own value directly instead.
_DEB_ONLY_GENERATED_PATHS = {"sslcrtsrv/PACKAGE_TYPE"}


def parse_install_files(install_file_paths):
    """Extract the sslcrtsrv/-relative source paths listed across one or more
    .install files (files or whole directories), skipping comments/blank
    lines, usr/bin/* console-script entries (meaningless outside a real
    package install), glob patterns (the egg-info/dist-info metadata
    line - build metadata, with no equivalent in a plain source tarball),
    and _DEB_ONLY_GENERATED_PATHS (files debian/rules writes at .deb build
    time, not present in the source tree at all).
    Always includes ALWAYS_REQUIRED_PATHS even if none of the given files
    list them - see that constant's comment for why. Order-preserving,
    de-duplicated across files."""
    paths = list(ALWAYS_REQUIRED_PATHS)
    for install_file_path in install_file_paths:
        with open(install_file_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or not line.startswith(DIST_PACKAGES_PREFIX):
                    continue
                relative = line[len(DIST_PACKAGES_PREFIX):]
                if "*" in relative or relative in _DEB_ONLY_GENERATED_PATHS:
                    continue
                if relative not in paths:
                    paths.append(relative)
    return paths


def get_requirements(extras_group=None):
    """Read install_requires (and, if given, one extras_require group) from
    setup.cfg - the same dependency list pip and the .deb's Depends: already
    use, rather than a second copy kept here."""
    config = configparser.ConfigParser()
    config.read(SETUP_CFG_PATH)
    reqs = [line.strip() for line in config.get("options", "install_requires").splitlines() if line.strip()]
    if extras_group:
        reqs += [line.strip() for line in config.get("options.extras_require", extras_group).splitlines()
                 if line.strip()]
    return reqs


def get_entry_points():
    """Parse setup.cfg's console_scripts into {command_name: module_path}."""
    config = configparser.ConfigParser()
    config.read(SETUP_CFG_PATH)
    entries = {}
    for line in config.get("options.entry_points", "console_scripts").splitlines():
        line = line.strip()
        if not line:
            continue
        name, target = (part.strip() for part in line.split("=", 1))
        module_path = target.split(":", 1)[0]
        entries[name] = module_path
    return entries


def commands_shipped_in(paths, entry_points):
    """Which of setup.cfg's console commands are actually usable from this
    archive's file list - i.e. whose target module (sslcrtsrv.admintui.
    __main__ -> sslcrtsrv/admintui/__main__.py) is a file that was copied,
    or falls under a directory that was copied wholesale."""
    shipped = {}
    for name, module_path in entry_points.items():
        module_file = module_path.replace(".", "/") + ".py"
        for path in paths:
            if module_file == path or module_file.startswith(path.rstrip("/") + "/"):
                shipped[name] = module_path
                break
    return dict(sorted(shipped.items()))


def copy_source_paths(paths, dest_sslcrtsrv_dir):
    """Copy each sslcrtsrv/-relative path (file or whole directory) from
    src/ into dest_sslcrtsrv_dir, preserving the package layout so the
    result is directly runnable via `python3 -m sslcrtsrv.<module>` without
    installing anything."""
    for relative in paths:
        source = os.path.join(SRC_DIR, relative)
        dest = os.path.join(dest_sslcrtsrv_dir, os.path.relpath(relative, "sslcrtsrv"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.isdir(source):
            shutil.copytree(source, dest, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(source, dest)


def copy_man_pages(entry_points, dest_dir):
    """Copy man/<name>.1 for every command actually shipped in this archive
    (entry_points, already filtered by commands_shipped_in()) into
    dest_dir/share/man/man1/ - mirrors write_wrapper_scripts()'s same
    per-component filtering, so e.g. the client tarball doesn't ship
    scs-server.1. Shipped uncompressed, unlike the .deb (dh_compress gzips
    usr/share/man/** automatically there) - a plain .1 reads identically
    via `man -l`/`groff -man`, and is viewable without decompressing first."""
    man1_dir = os.path.join(dest_dir, "share", "man", "man1")
    os.makedirs(man1_dir, exist_ok=True)
    for name in entry_points:
        source = os.path.join(MAN_DIR, f"{name}.1")
        if os.path.isfile(source):
            shutil.copy2(source, os.path.join(man1_dir, f"{name}.1"))


USAGE_TEMPLATE = """\
sslcrtsrv-{component} {version} - generic Linux tarball
{underline}

Plain-source distribution for hosts that aren't Debian/Ubuntu-based (use the
.deb packages instead if they are - see the project's debian/ directory).
No dpkg/rpm involved - just Python {python_requires}+ and pip.

Setup:
    python3 -m venv venv
    ./venv/bin/pip install -r requirements.txt

Run - each command below has a wrapper script in bin/ using the same name
its Debian package installs to /usr/bin, so scripts written against one
work unmodified against the other. Run them directly (./bin/scs-client
--help), or add bin/ to PATH:
{command_examples}

Each wrapper picks up ./venv/bin/python3 automatically if the venv above
was created right here; otherwise it falls back to whatever `python3` is
on PATH. Equivalent to running `python3 -m {example_module} --help`
directly, for anyone who'd rather not use the wrapper.

Man pages for each command above are also included, under
share/man/man1/ - view one directly with e.g. `man -l
share/man/man1/scs-client.1`, or add this archive's share/man/ to
$MANPATH for normal `man scs-client` lookups.
"""

WRAPPER_TEMPLATE = """\
#!/bin/sh
# Wrapper for {name} - runs the bundled sslcrtsrv/ package in place,
# without requiring a system-wide install. Generated by build-tarballs.py;
# do not edit directly, edit that script instead. Uses the same command
# name as this project's Debian package installs to /usr/bin, so scripts
# written against one work unmodified against the other.
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$HERE/venv/bin/python3" ]; then
    PYTHON="$HERE/venv/bin/python3"
else
    PYTHON="python3"
fi
PYTHONPATH="$HERE${{PYTHONPATH:+:$PYTHONPATH}}"
export PYTHONPATH
exec "$PYTHON" -m {module} "$@"
"""


def write_usage_file(dest_dir, component, version, python_requires, entry_points):
    lines = [f"    ./bin/{name} --help"
              for name in entry_points]
    example_module = next(iter(entry_points.values()), "sslcrtsrv.<module>")
    content = USAGE_TEMPLATE.format(
        component=component, version=version, underline="=" * (len(component) + len(version) + 30),
        python_requires=python_requires, command_examples="\n".join(lines) or "    (no commands in this archive)",
        example_module=example_module
    )
    with open(os.path.join(dest_dir, "USAGE.txt"), "w") as f:
        f.write(content)


def write_wrapper_scripts(dest_dir, entry_points):
    """One executable shell wrapper per console command shipped in this
    archive, named identically to the command the Debian package installs
    to /usr/bin (see setup.cfg's console_scripts) - so a script written
    against a Debian install of this project (`scs-client ...`) works
    unmodified against this tarball's extracted copy too."""
    bin_dir = os.path.join(dest_dir, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    for name, module in entry_points.items():
        wrapper_path = os.path.join(bin_dir, name)
        with open(wrapper_path, "w") as f:
            f.write(WRAPPER_TEMPLATE.format(name=name, module=module))
        os.chmod(wrapper_path, 0o755)


def build_component(component, version, output_dir, python_requires):
    spec = COMPONENTS[component]
    paths = parse_install_files(spec["install_files"])
    entry_points = commands_shipped_in(paths, get_entry_points())
    requirements = get_requirements(spec["extras"])

    archive_name = f"sslcrtsrv-{component}-{version}-generic"
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, archive_name)
        sslcrtsrv_dir = os.path.join(root, "sslcrtsrv")
        os.makedirs(sslcrtsrv_dir)

        copy_source_paths(paths, sslcrtsrv_dir)

        # See _DEB_ONLY_GENERATED_PATHS - the .deb build writes its own
        # "deb" value into the equivalent path via debian/rules; this is
        # this tarball's counterpart (common/client_utils.py's
        # detect_package_type()).
        with open(os.path.join(sslcrtsrv_dir, "PACKAGE_TYPE"), "w") as f:
            f.write("tarball\n")

        with open(os.path.join(root, "requirements.txt"), "w") as f:
            f.write("\n".join(requirements) + "\n")

        write_wrapper_scripts(root, entry_points)
        copy_man_pages(entry_points, root)
        write_usage_file(root, component, version, python_requires, entry_points)

        os.makedirs(output_dir, exist_ok=True)
        archive_path = os.path.join(output_dir, archive_name + ".tar.gz")
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(root, arcname=archive_name)

    return archive_path, len(paths), list(entry_points)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", default=os.path.join(REPO_ROOT, "dist"),
                         help="Directory to write the .tar.gz files to (default: dist/)")
    args = parser.parse_args()

    version = get_version()
    config = configparser.ConfigParser()
    config.read(SETUP_CFG_PATH)
    python_requires = config.get("options", "python_requires", fallback=">=3.9").lstrip(">=")

    print(f"Building sslcrtsrv {version} generic tarballs...")
    for component in COMPONENTS:
        archive_path, file_count, commands = build_component(component, version, args.output_dir, python_requires)
        print(f"  {component}: {archive_path}")
        print(f"    {file_count} source path(s), commands: {', '.join(commands) if commands else '(none)'}")


if __name__ == "__main__":
    main()
