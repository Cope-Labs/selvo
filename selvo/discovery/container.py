"""
Container image scanning — extract OS package inventory from Docker images.

Three modes, tried in order:

  1. Docker CLI + daemon
     Used when ``docker`` is on PATH and ``/var/run/docker.sock`` is reachable
     (typical self-hosted setups). ``docker run --rm --entrypoint`` the image
     to read its package manager output. Fast, supports every OS selvo handles
     (debian/ubuntu/fedora/rhel/rocky/alma/alpine).

  2. Skopeo (daemon-less registry client)
     Used when Docker CLI is unavailable (typical SaaS deployments where
     mounting /var/run/docker.sock would be a container-escape risk). Skopeo
     copies the image from its registry straight to a docker-archive tarball,
     which is parsed via :func:`packages_from_image_tar`. Currently supports
     debian/ubuntu tarballs; rpm/alpine tarball parsing is a TODO.

  3. Tarball parsing (``packages_from_image_tar``)
     The lowest-level primitive. Given an already-exported tarball (from
     ``docker save`` or ``skopeo copy`` into a docker-archive target), pulls
     layers, finds ``/var/lib/dpkg/status``, parses it.

Returns list[PackageRecord] with version_source="container".
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)


# ── Docker inspect / exec ─────────────────────────────────────────────────────

def _run(cmd: list[str]) -> Optional[str]:
    """Run a shell command and return stdout, or None on error."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.debug("Command failed %s: %s", cmd[:3], exc)
    return None


def _dpkg_output_to_packages(output: str, ecosystem: str) -> list[PackageRecord]:
    """Parse `dpkg-query -W -f='${Package}\t${Version}\t${Description}\n'` output."""
    records = []
    for line in output.splitlines():
        parts = line.split("\t", 2)
        if len(parts) < 2:
            continue
        name, version = parts[0].strip(), parts[1].strip()
        desc = parts[2].strip()[:200] if len(parts) > 2 else ""
        if name and version and version != "<none>":
            records.append(PackageRecord(
                name=name,
                ecosystem=ecosystem,
                version=version,
                description=desc,
                version_source="container",
            ))
    return records


def _rpm_output_to_packages(output: str) -> list[PackageRecord]:
    """Parse `rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\n'` output."""
    records = []
    for line in output.splitlines():
        parts = line.split("\t", 1)
        if len(parts) < 2:
            continue
        name, version = parts[0].strip(), parts[1].strip()
        if name and version:
            records.append(PackageRecord(
                name=name,
                ecosystem="fedora",
                version=version,
                version_source="container",
            ))
    return records


def _apk_output_to_packages(output: str) -> list[PackageRecord]:
    """Parse `apk info -v` output: name-version pairs."""
    records = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # apk info -v: pkgname-ver-rel format
        # Try to split at last dash-digit boundary
        import re
        m = re.match(r"^(.+)-(\d[^\s]*).*$", line)
        if m:
            records.append(PackageRecord(
                name=m.group(1),
                ecosystem="alpine",
                version=m.group(2),
                version_source="container",
            ))
    return records


def _docker_cli_available() -> bool:
    """Return True if the Docker CLI can reach a running daemon."""
    if not shutil.which("docker"):
        return False
    # DOCKER_HOST override (remote daemon) also counts.
    if os.environ.get("DOCKER_HOST"):
        return True
    return Path("/var/run/docker.sock").exists()


def _packages_via_docker_cli(image: str) -> list[PackageRecord]:
    """Scan a container image by `docker run --rm --entrypoint` against a
    running daemon. Supports debian/ubuntu/fedora-family/alpine."""
    os_release = _run(["docker", "run", "--rm", "--entrypoint", "cat", image, "/etc/os-release"])
    if not os_release:
        raise RuntimeError(f"Cannot read /etc/os-release from image '{image}'. Is Docker running?")

    os_id = ""
    for line in os_release.splitlines():
        if line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"').lower()
            break

    if os_id in ("debian", "ubuntu"):
        eco = "ubuntu" if os_id == "ubuntu" else "debian"
        out = _run([
            "docker", "run", "--rm", "--entrypoint", "dpkg-query",
            image, "-W", "-f=${Package}\t${Version}\t${Description}\n"
        ])
        return _dpkg_output_to_packages(out or "", eco)

    elif os_id in ("fedora", "centos", "rhel", "rocky", "alma"):
        out = _run([
            "docker", "run", "--rm", "--entrypoint", "rpm",
            image, "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"
        ])
        return _rpm_output_to_packages(out or "")

    elif os_id == "alpine":
        out = _run(["docker", "run", "--rm", "--entrypoint", "apk", image, "info", "-v"])
        return _apk_output_to_packages(out or "")

    else:
        raise RuntimeError(
            f"Unsupported OS ID '{os_id}' in image '{image}'. "
            "selvo supports debian, ubuntu, fedora/rhel, and alpine containers."
        )


def _packages_via_skopeo(image: str) -> list[PackageRecord]:
    """Scan a container image without a Docker daemon, using skopeo.

    ``skopeo copy docker://<image> docker-archive:<path>`` produces a tarball
    in the same format as ``docker save``, which the existing
    :func:`packages_from_image_tar` can parse.

    Supports debian/ubuntu (dpkg), fedora/rhel/rocky/alma 9+ (rpm sqlite),
    and alpine (apk) images. Older RPM BDB/NDB-format databases (RHEL <=8
    base images) are not yet parseable from a tarball — fall back to the
    Docker CLI path for those.
    """
    if not shutil.which("skopeo"):
        raise RuntimeError(
            "Container image scan requires Docker CLI or skopeo. Neither is installed. "
            "In a self-hosted deployment, mount /var/run/docker.sock into the selvo "
            "container, or `apt-get install skopeo`."
        )

    # Reference sanity: skopeo needs an explicit scheme; if the caller passed
    # something bare like 'nginx:latest', prefix docker:// so skopeo talks to
    # Docker Hub. Callers may also pass full docker://registry/image:tag.
    if "://" in image:
        src = image
    else:
        src = f"docker://{image}"

    with tempfile.TemporaryDirectory(prefix="selvo-img-") as tmpdir:
        tar_path = str(Path(tmpdir) / "image.tar")
        # docker-archive:<path> matches `docker save` layout so the existing
        # parser works unchanged.
        proc = subprocess.run(
            ["skopeo", "copy", src, f"docker-archive:{tar_path}"],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"skopeo failed to pull '{image}': {proc.stderr.strip() or 'unknown error'}"
            )
        return packages_from_image_tar(tar_path)


def packages_from_docker_image(image: str) -> list[PackageRecord]:
    """
    Extract installed-package inventory from a container image.

    Tries Docker CLI first (self-hosted), falls back to skopeo (SaaS). Raises
    if neither is available. ``image`` may be a plain reference like
    ``ubuntu:24.04`` or a full URL like ``docker://ghcr.io/owner/img:tag``.
    """
    if _docker_cli_available():
        return _packages_via_docker_cli(image)
    return _packages_via_skopeo(image)


# ── Tarball / OCI layout analysis ────────────────────────────────────────────

def _read_file_from_layer(layer_tar: tarfile.TarFile, path: str) -> Optional[str]:
    """Try to read a file path from a layer tarball, returning text or None."""
    # OCI layer paths may have './' prefix or not
    for candidate in (path, "./" + path, path.lstrip("/")):
        try:
            member = layer_tar.getmember(candidate)
            f = layer_tar.extractfile(member)
            if f:
                return f.read().decode("utf-8", errors="replace")
        except KeyError:
            pass
    return None


def _read_bytes_from_layer(layer_tar: tarfile.TarFile, path: str) -> Optional[bytes]:
    """Same as :func:`_read_file_from_layer` but returns raw bytes — required
    for binary databases like rpmdb.sqlite."""
    for candidate in (path, "./" + path, path.lstrip("/")):
        try:
            member = layer_tar.getmember(candidate)
            f = layer_tar.extractfile(member)
            if f:
                return f.read()
        except KeyError:
            pass
    return None


def _parse_dpkg_status(status_text: str, ecosystem: str) -> list[PackageRecord]:
    """
    Parse a dpkg status file (var/lib/dpkg/status) into PackageRecord list.
    Format: RFC822-style records separated by blank lines.
    """
    records = []
    current: dict[str, str] = {}
    for line in status_text.splitlines():
        if line == "" or line == "\n":
            if current.get("Package") and current.get("Status", "").endswith("installed"):
                version = current.get("Version", "unknown")
                records.append(PackageRecord(
                    name=current["Package"],
                    ecosystem=ecosystem,
                    version=version,
                    description=current.get("Description", "")[:200],
                    version_source="container",
                ))
            current = {}
        elif ":" in line and not line.startswith(" "):
            k, _, v = line.partition(":")
            current[k.strip()] = v.strip()
    return records


def _parse_apk_installed(apk_db_text: str) -> list[PackageRecord]:
    """Parse Alpine's ``lib/apk/db/installed`` into PackageRecord list.

    Format is line-prefixed key-value records separated by blank lines:
        P:package-name
        V:1.2.3-r4
        A:x86_64
        T:short description
        ...
        (blank line between packages)
    """
    records: list[PackageRecord] = []
    name = ""
    version = ""
    desc = ""
    for line in apk_db_text.splitlines():
        if not line:
            if name:
                records.append(PackageRecord(
                    name=name,
                    ecosystem="alpine",
                    version=version or "unknown",
                    description=desc[:200],
                    version_source="container",
                ))
            name = version = desc = ""
            continue
        if len(line) < 2 or line[1] != ":":
            continue
        key, val = line[0], line[2:]
        if key == "P":
            name = val
        elif key == "V":
            version = val
        elif key == "T":
            desc = val
    # Trailing record without terminating blank line
    if name:
        records.append(PackageRecord(
            name=name,
            ecosystem="alpine",
            version=version or "unknown",
            description=desc[:200],
            version_source="container",
        ))
    return records


# RPM tag IDs we care about, per librpm/rpmtag.h
_RPMTAG_NAME = 1000
_RPMTAG_VERSION = 1001
_RPMTAG_RELEASE = 1002
_RPMTAG_SUMMARY = 1004


def _decode_rpm_header(blob: bytes) -> dict[int, str]:
    """Pull NAME / VERSION / RELEASE / SUMMARY out of an RPM header blob.

    The header format is documented in librpm; layout is:
      8 bytes  magic + reserved
      4 bytes  big-endian uint32 — index entry count
      4 bytes  big-endian uint32 — data store size
      16 * N   index entries: (tag uint32, type uint32, offset uint32, count uint32)
      data     null-terminated strings, integers, etc. — referenced by offset
    For string-typed entries, we only need to read up to the first NUL at the
    given offset within the data store.
    """
    import struct
    if len(blob) < 16:
        return {}
    # Magic-and-reserved is 8 bytes. Some headers are wrapped with an extra
    # 16-byte "lead" — try both.
    for hdr_start in (0, 8):
        try:
            n_idx, data_len = struct.unpack_from(">II", blob, hdr_start)
        except struct.error:
            continue
        idx_start = hdr_start + 8
        data_start = idx_start + 16 * n_idx
        if data_start + data_len > len(blob) or n_idx <= 0 or n_idx > 5000:
            continue
        wanted = {_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE, _RPMTAG_SUMMARY}
        out: dict[int, str] = {}
        for i in range(n_idx):
            tag, ttype, offset, _count = struct.unpack_from(">IIII", blob, idx_start + 16 * i)
            if tag not in wanted:
                continue
            # type 6 = STRING; type 8 = STRING_ARRAY (we take the first); type 9 = I18NSTRING
            if ttype not in (6, 8, 9):
                continue
            abs_off = data_start + offset
            end = blob.find(b"\x00", abs_off, data_start + data_len)
            if end == -1:
                continue
            try:
                out[tag] = blob[abs_off:end].decode("utf-8", errors="replace")
            except Exception:
                continue
        if _RPMTAG_NAME in out and _RPMTAG_VERSION in out:
            return out
    return {}


def _parse_rpm_sqlite(db_bytes: bytes) -> list[PackageRecord]:
    """Parse modern (Fedora 36+ / RHEL 9+ / Rocky 9 / Alma 9) RPM SQLite DB.

    rpmdb.sqlite stores each package's full header blob in the ``Packages``
    table. We pull NAME + VERSION + RELEASE out of the header and emit a
    PackageRecord per row. Older NDB / BDB formats are NOT supported.
    """
    import sqlite3
    import tempfile
    # sqlite3.connect needs a path; the layer gives us bytes. Stage to a temp
    # file rather than try memory-buffered access (which sqlite Python bindings
    # don't expose cleanly).
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        tmp.write(db_bytes)
        tmp.flush()
        conn = sqlite3.connect(tmp.name)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            if "Packages" not in tables:
                return []
            rows = conn.execute("SELECT blob FROM Packages").fetchall()
        finally:
            conn.close()

    records: list[PackageRecord] = []
    for (blob,) in rows:
        if not blob:
            continue
        hdr = _decode_rpm_header(bytes(blob))
        name = hdr.get(_RPMTAG_NAME, "")
        version = hdr.get(_RPMTAG_VERSION, "")
        release = hdr.get(_RPMTAG_RELEASE, "")
        if not name or not version:
            continue
        full_ver = f"{version}-{release}" if release else version
        # 'gpg-pubkey' is a synthetic RPM entry for trusted GPG keys, not a
        # software package — skip it so it doesn't pollute scans.
        if name == "gpg-pubkey":
            continue
        records.append(PackageRecord(
            name=name,
            ecosystem="fedora",  # canonical RPM-family ecosystem in selvo
            version=full_ver,
            description=hdr.get(_RPMTAG_SUMMARY, "")[:200],
            version_source="container",
        ))
    return records


def packages_from_image_tar(tar_path: str | Path) -> list[PackageRecord]:
    """
    Extract OS packages from a Docker image tarball (`docker save image > image.tar`).

    Does NOT require a running Docker daemon — reads the tarball directly.

    Args:
        tar_path:  Path to the image tar file.

    Returns:
        list[PackageRecord] with version_source='container'.
    """
    path = Path(tar_path)
    records: list[PackageRecord] = []

    with tarfile.open(path, "r:*") as outer:
        # Read manifest.json to get layer order
        try:
            manifest_f = outer.extractfile("manifest.json")
            manifest = json.loads(manifest_f.read()) if manifest_f else []
        except (KeyError, json.JSONDecodeError):
            manifest = []

        layer_paths: list[str] = []
        if manifest and isinstance(manifest, list):
            for entry in manifest:
                layer_paths.extend(entry.get("Layers", []))

        # Walk layers in reverse (last-writer-wins). Look for any of the
        # supported package DBs and the os-release file.
        dpkg_status: Optional[str] = None
        apk_db: Optional[str] = None
        rpm_sqlite: Optional[bytes] = None
        rpm_legacy_present = False
        os_id = ""

        for layer_path in reversed(layer_paths):
            try:
                layer_member = outer.getmember(layer_path)
                layer_f = outer.extractfile(layer_member)
                if not layer_f:
                    continue
                with tarfile.open(fileobj=io.BytesIO(layer_f.read()), mode="r:*") as layer:
                    if not os_id:
                        os_rel = _read_file_from_layer(layer, "etc/os-release")
                        if os_rel:
                            for line in os_rel.splitlines():
                                if line.startswith("ID="):
                                    os_id = line.split("=", 1)[1].strip().strip('"').lower()
                                    break

                    if dpkg_status is None:
                        dpkg_status = _read_file_from_layer(layer, "var/lib/dpkg/status")
                    if apk_db is None:
                        apk_db = _read_file_from_layer(layer, "lib/apk/db/installed")
                    if rpm_sqlite is None:
                        rpm_sqlite = _read_bytes_from_layer(layer, "var/lib/rpm/rpmdb.sqlite")
                    # Legacy BDB / NDB rpm DBs we can't currently parse — flag
                    # for a clearer error message at the end.
                    if not rpm_legacy_present and (
                        _read_bytes_from_layer(layer, "var/lib/rpm/Packages")
                        or _read_bytes_from_layer(layer, "var/lib/rpm/Packages.db")
                    ):
                        rpm_legacy_present = True

            except (KeyError, tarfile.TarError):
                pass

        # Pick the parser that found data. Order matters because some images
        # carry stale files for a different package manager (e.g. debian
        # base image with an empty rpm dir).
        if dpkg_status:
            eco = "ubuntu" if os_id == "ubuntu" else "debian"
            records = _parse_dpkg_status(dpkg_status, eco)
        elif rpm_sqlite:
            records = _parse_rpm_sqlite(rpm_sqlite)
        elif apk_db:
            records = _parse_apk_installed(apk_db)
        elif rpm_legacy_present:
            raise RuntimeError(
                "Image uses the legacy RPM BDB/NDB database format which selvo "
                "cannot parse from a tarball yet. Either scan via Docker CLI "
                "(self-hosted), or rebuild the base image on a modern release "
                "(Fedora 36+, RHEL 9+, Rocky 9, Alma 9 — these use SQLite)."
            )
        elif not records:
            raise RuntimeError(
                "Could not find a supported package database in image tarball "
                f"(os-release ID='{os_id or 'unknown'}'). "
                "Supported: debian/ubuntu (dpkg), fedora/rhel/rocky/alma 9+ "
                "(rpm sqlite), alpine (apk)."
            )

    return records
