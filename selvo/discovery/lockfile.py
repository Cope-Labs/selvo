"""
Lock file / manifest input adapter.

Parses common application dependency lock files and package manifests into
list[PackageRecord] for the selvo enrichment pipeline. This extends selvo
beyond OS packages to cover application-layer dependencies.

Supported formats:
  requirements.txt     Python pip freeze / requirements file
  Pipfile.lock         Pipenv lock
  poetry.lock          Poetry lock
  package-lock.json    npm v2/v3 lock
  yarn.lock            Yarn Berry (v2+) and Classic (v1) lock
  Cargo.lock           Rust Cargo lock
  go.sum               Go module checksum database (approximation)
  Gemfile.lock         Ruby Bundler lock
  composer.lock        PHP Composer lock
  pom.xml              Maven POM (dependency section)
  *.csproj / *.fsproj  .NET project SDK-style (PackageReference)

Usage:
    from selvo.discovery.lockfile import load_lockfile
    packages = load_lockfile("/path/to/requirements.txt")
    packages = load_lockfile("/path/to/package-lock.json")
    # Auto-detect by filename — or pass format= to override:
    packages = load_lockfile("/path/to/myfile", format="cargo")

Returns list[PackageRecord] with ecosystem and version populated.
version_source is set to "lockfile".
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from selvo.discovery.base import PackageRecord


# ── Python ────────────────────────────────────────────────────────────────────

def _parse_requirements_txt(text: str) -> list[PackageRecord]:
    """Parse pip requirements.txt / pip freeze output."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, ~=, <=, != — take the first pinned == if present
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;,]+)", line)
        if m:
            records.append(PackageRecord(
                name=m.group(1).lower().replace("_", "-"),
                ecosystem="pypi",
                version=m.group(2),
                version_source="lockfile",
            ))
        else:
            # Unpinned — record name only
            m2 = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if m2:
                records.append(PackageRecord(
                    name=m2.group(1).lower().replace("_", "-"),
                    ecosystem="pypi",
                    version="unknown",
                    version_source="lockfile",
                ))
    return records


def _parse_pipfile_lock(data: dict) -> list[PackageRecord]:
    records = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            records.append(PackageRecord(
                name=name.lower().replace("_", "-"),
                ecosystem="pypi",
                version=version or "unknown",
                version_source="lockfile",
            ))
    return records


def _parse_poetry_lock(text: str) -> list[PackageRecord]:
    """Parse poetry.lock TOML (minimal parser — avoids tomllib dep on older Py)."""
    records = []
    current: dict[str, str] = {}
    in_package = False
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if in_package and current.get("name"):
                records.append(PackageRecord(
                    name=current["name"].lower().replace("_", "-"),
                    ecosystem="pypi",
                    version=current.get("version", "unknown"),
                    version_source="lockfile",
                ))
            current = {}
            in_package = True
        elif in_package and "=" in line and not line.startswith("["):
            k, _, v = line.partition("=")
            current[k.strip()] = v.strip().strip('"')
    if in_package and current.get("name"):
        records.append(PackageRecord(
            name=current["name"].lower().replace("_", "-"),
            ecosystem="pypi",
            version=current.get("version", "unknown"),
            version_source="lockfile",
        ))
    return records


# ── Node / npm / yarn ─────────────────────────────────────────────────────────

def _parse_package_lock_json(data: dict) -> list[PackageRecord]:
    """npm package-lock.json v2/v3 (packages map)."""
    records = []
    # v2/v3: top-level "packages" dict with "" key for root
    packages = data.get("packages", {})
    for path, info in packages.items():
        if not path or path == "":
            continue  # skip root
        # path like "node_modules/express" or "node_modules/a/node_modules/b"
        name = path.split("node_modules/")[-1]
        if not name:
            continue
        records.append(PackageRecord(
            name=name,
            ecosystem="npm",
            version=info.get("version", "unknown"),
            version_source="lockfile",
        ))
    if not records:
        # v1 fallback: "dependencies" dict
        for name, info in data.get("dependencies", {}).items():
            records.append(PackageRecord(
                name=name,
                ecosystem="npm",
                version=info.get("version", "unknown"),
                version_source="lockfile",
            ))
    return records


def _parse_yarn_lock(text: str) -> list[PackageRecord]:
    """Parse Yarn v1 and Berry lock files (text format)."""
    records = []
    current_name: Optional[str] = None
    for line in text.splitlines():
        line_s = line.strip()
        # Block header: `"express@^4.0.0", "express@^4.18.0":` or `express@npm:^4.0.0:`
        if not line.startswith(" ") and (line_s.endswith(":") or line_s.endswith('":')
                                         or '", "' in line_s):
            # Extract package name (first entry before @)
            m = re.match(r'"?([^@"]+)@', line_s)
            if m:
                current_name = m.group(1).strip()
        elif current_name and line_s.startswith("version"):
            m = re.match(r'version[:\s]+"?([^"]+)"?', line_s)
            if m:
                records.append(PackageRecord(
                    name=current_name,
                    ecosystem="npm",
                    version=m.group(1),
                    version_source="lockfile",
                ))
                current_name = None
    return records


# ── Rust ─────────────────────────────────────────────────────────────────────

def _parse_cargo_lock(text: str) -> list[PackageRecord]:
    """Parse Cargo.lock TOML (minimal parser)."""
    records = []
    current: dict[str, str] = {}
    in_package = False
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if in_package and current.get("name"):
                records.append(PackageRecord(
                    name=current["name"].strip('"'),
                    ecosystem="cargo",
                    version=current.get("version", "unknown").strip('"'),
                    version_source="lockfile",
                ))
            current = {}
            in_package = True
        elif in_package and "=" in line and not line.startswith("["):
            k, _, v = line.partition("=")
            current[k.strip()] = v.strip().strip('"')
    if in_package and current.get("name"):
        records.append(PackageRecord(
            name=current["name"].strip('"'),
            ecosystem="cargo",
            version=current.get("version", "unknown").strip('"'),
            version_source="lockfile",
        ))
    return records


# ── Go ────────────────────────────────────────────────────────────────────────

def _parse_go_sum(text: str) -> list[PackageRecord]:
    """
    Parse go.sum — each line: module version hash.
    go.sum has two lines per version (with and without /go.mod suffix);
    deduplicate to one PackageRecord per module.
    """
    seen: set[str] = set()
    records = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")  # strip /go.mod suffix and v prefix
        if module in seen:
            continue
        seen.add(module)
        records.append(PackageRecord(
            name=module,
            ecosystem="go",
            version=version,
            version_source="lockfile",
        ))
    return records


# ── Ruby ─────────────────────────────────────────────────────────────────────

def _parse_gemfile_lock(text: str) -> list[PackageRecord]:
    """Parse Bundler Gemfile.lock."""
    records = []
    in_gems = False
    for line in text.splitlines():
        if line.strip() in ("GEM", "specs:"):
            in_gems = True
            continue
        if in_gems and line.strip() and not line[0].isspace():
            in_gems = False
        if in_gems:
            # Lines like: "    rails (7.1.0)" (4-space indent for direct, 6 for transitive)
            m = re.match(r"^    ([a-zA-Z0-9][a-zA-Z0-9_.\-]*) \(([^\)]+)\)", line)
            if m:
                records.append(PackageRecord(
                    name=m.group(1),
                    ecosystem="gem",
                    version=m.group(2),
                    version_source="lockfile",
                ))
    return records


# ── PHP ───────────────────────────────────────────────────────────────────────

def _parse_composer_lock(data: dict) -> list[PackageRecord]:
    records = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            records.append(PackageRecord(
                name=pkg.get("name", ""),
                ecosystem="composer",
                version=pkg.get("version", "unknown").lstrip("v"),
                description=pkg.get("description", "")[:200],
                version_source="lockfile",
            ))
    return records


# ── .NET ──────────────────────────────────────────────────────────────────────

def _parse_csproj(text: str) -> list[PackageRecord]:
    """Parse .csproj / .fsproj SDK-style PackageReference elements."""
    records = []
    for m in re.finditer(
        r'<PackageReference\s+'
        r'(?:Include="([^"]*)"\s+(?:Version|version)="([^"]*)"'
        r'|(?:Version|version)="([^"]*)"\s+Include="([^"]*)")',
        text,
    ):
        name = m.group(1) or m.group(4) or ""
        version = m.group(2) or m.group(3) or "unknown"
        if name:
            records.append(PackageRecord(
                name=name,
                ecosystem="nuget",
                version=version,
                version_source="lockfile",
            ))
    return records


# ── Maven ─────────────────────────────────────────────────────────────────────

def _parse_pom_xml(text: str) -> list[PackageRecord]:
    """Parse Maven pom.xml dependency declarations using stdlib XML parser."""
    import xml.etree.ElementTree as ET

    records = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Fallback to regex for malformed XML
        return _parse_pom_xml_regex(text)

    # Handle Maven namespace if present
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    for dep in root.iter(f"{ns}dependency"):
        artifact_el = dep.find(f"{ns}artifactId")
        group_el = dep.find(f"{ns}groupId")
        version_el = dep.find(f"{ns}version")
        if artifact_el is None or not artifact_el.text:
            continue
        name = artifact_el.text.strip()
        group = group_el.text.strip() if group_el is not None and group_el.text else ""
        full_name = f"{group}:{name}" if group else name
        version = "unknown"
        if version_el is not None and version_el.text:
            v = version_el.text.strip()
            if not v.startswith("${"):
                version = v
        records.append(PackageRecord(
            name=full_name,
            ecosystem="maven",
            version=version,
            version_source="lockfile",
        ))
    return records


def _parse_pom_xml_regex(text: str) -> list[PackageRecord]:
    """Regex fallback for malformed pom.xml files."""
    records = []
    for block in re.finditer(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
        content = block.group(1)
        artifact_m = re.search(r"<artifactId>([^<]+)</artifactId>", content)
        version_m = re.search(r"<version>([^<]+)</version>", content)
        group_m = re.search(r"<groupId>([^<]+)</groupId>", content)
        if artifact_m:
            name = artifact_m.group(1).strip()
            group = group_m.group(1).strip() if group_m else ""
            full_name = f"{group}:{name}" if group else name
            v = version_m.group(1).strip() if version_m else "unknown"
            if v.startswith("${"):
                v = "unknown"
            records.append(PackageRecord(
                name=full_name,
                ecosystem="maven",
                version=v,
                version_source="lockfile",
            ))
    return records


# ── Format detection ──────────────────────────────────────────────────────────

def _detect_format(path: Path, text: str, data: Optional[dict]) -> Optional[str]:
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name == "requirements.txt":
        return "requirements"
    if name == "pipfile.lock":
        return "pipfile"
    if name == "poetry.lock":
        return "poetry"
    if name == "package-lock.json":
        return "npm"
    if name == "yarn.lock":
        return "yarn"
    if name == "cargo.lock":
        return "cargo"
    if name == "go.sum":
        return "gosum"
    if name == "gemfile.lock":
        return "gemfile"
    if name == "composer.lock":
        return "composer"
    if name in ("pom.xml",):
        return "pom"
    if suffix in (".csproj", ".fsproj", ".vbproj"):
        return "csproj"
    # Heuristics on content
    if data and "packages" in data and "lockfileVersion" in data:
        return "npm"
    if data and ("packages" in data or "packages-dev" in data) and "content-hash" in data:
        return "composer"
    if "[[package]]" in text and "source" in text:
        return "cargo" if 'name = "' in text else "poetry"
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def load_lockfile(
    path: str | Path,
    format: Optional[str] = None,  # noqa: A002
) -> list[PackageRecord]:
    """
    Parse a package lock file or manifest and return list[PackageRecord].

    Args:
        path:    Path to the lock file.
        format:  Optional format override. One of:
                 requirements | pipfile | poetry | npm | yarn | cargo | gosum |
                 gemfile | composer | pom | csproj

    Returns:
        list[PackageRecord] ready for selvo enrichment pipeline.

    Raises:
        ValueError:  Unknown format.
        FileNotFoundError:  path does not exist.
    """
    p = Path(path)
    text = p.read_text(errors="replace")

    data: Optional[dict] = None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    fmt = format or _detect_format(p, text, data)
    if fmt is None:
        raise ValueError(
            f"Cannot detect lock file format for '{p.name}'. "
            "Pass format= explicitly. Supported: requirements, pipfile, poetry, npm, "
            "yarn, cargo, gosum, gemfile, composer, pom, csproj."
        )

    dispatcher = {
        "requirements": lambda: _parse_requirements_txt(text),
        "pipfile":      lambda: _parse_pipfile_lock(data or json.loads(text)),
        "poetry":       lambda: _parse_poetry_lock(text),
        "npm":          lambda: _parse_package_lock_json(data or json.loads(text)),
        "yarn":         lambda: _parse_yarn_lock(text),
        "cargo":        lambda: _parse_cargo_lock(text),
        "gosum":        lambda: _parse_go_sum(text),
        "gemfile":      lambda: _parse_gemfile_lock(text),
        "composer":     lambda: _parse_composer_lock(data or json.loads(text)),
        "pom":          lambda: _parse_pom_xml(text),
        "csproj":       lambda: _parse_csproj(text),
    }

    fn = dispatcher.get(fmt)
    if fn is None:
        raise ValueError(f"Unsupported lock file format: '{fmt}'")

    return [pkg for pkg in fn() if pkg.name]
