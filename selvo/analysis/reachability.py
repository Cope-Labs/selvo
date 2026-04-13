"""Call-graph reachability analysis for selvo.

Filters CVEs on each PackageRecord to only those reachable from the actual call
graph of the target application — eliminating the 60–80% of transitive CVEs that
exist in the dependency tree but are never invoked.

Two backends are supported, selected automatically by ecosystem:

  - **Go** (`govulncheck`): runs ``govulncheck -json ./...`` in the target
    directory and cross-references its reachable vulnerability IDs against
    selvo's CVE list.  Requires ``govulncheck`` to be installed
    (``go install golang.org/x/vuln/cmd/govulncheck@latest``).

  - **Python** (AST): traces ``import`` chains from an entrypoint file using
    the standard-library ``ast`` module plus ``importlib.util`` to resolve
    module→package mappings. No external tools required.

New fields populated on :class:`~selvo.discovery.base.PackageRecord`:

  - ``reachable``           – True if ≥1 CVE is reachable
  - ``reachability_source`` – "govulncheck" | "pyast" | "unknown"
  - ``reachable_cves``      – CVE IDs confirmed reachable
  - ``unreachable_cves``    – CVE IDs confirmed unreachable

Scoring impact (applied automatically after enrichment):
  Unreachable CVEs reduce the EPSS contribution of the package by 80% when
  the scorer is re-run, and remove packages from KEV/weaponized block gates
  in policy unless at least one reachable CVE remains.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)


# ── Public entry point ────────────────────────────────────────────────────────

def enrich_reachability(
    packages: list[PackageRecord],
    *,
    target_dir: str = ".",
    entrypoint: Optional[str] = None,
    ecosystem: str = "auto",
) -> list[PackageRecord]:
    """Enrich *packages* with call-graph reachability data.

    Args:
        packages:    List of PackageRecords to enrich in-place.
        target_dir:  Root directory of the project to analyse.
        entrypoint:  Path to the Python entry-point file (Python backend only).
                     When *None* and the ecosystem is Python, ``main.py`` /
                     ``__main__.py`` / ``app.py`` are tried automatically.
        ecosystem:   Force a specific backend: ``"go"``, ``"python"``, or
                     ``"auto"`` (default) to detect from project layout.

    Returns:
        The same *packages* list with reachability fields populated.
    """
    if not packages:
        return packages

    root = Path(target_dir).resolve()
    backend = _detect_backend(root, ecosystem)

    if backend == "go":
        reachable_cve_ids = _govulncheck_reachable(root)
        _apply_reachability(packages, reachable_cve_ids, source="govulncheck")
    elif backend == "python":
        ep = _find_entrypoint(root, entrypoint)
        if ep is None:
            log.warning(
                "reachability: no entrypoint found in %s — skipping Python AST walk", root
            )
            _mark_unknown(packages)
        else:
            reachable_pkgs = _pyast_reachable_packages(ep, root)
            _apply_python_reachability(packages, reachable_pkgs)
    elif backend == "node":
        reachable_pkgs = _node_reachable_packages(root)
        _apply_python_reachability(packages, reachable_pkgs)  # same name-match logic
    else:
        log.debug("reachability: no supported backend detected for %s", root)
        _mark_unknown(packages)

    return packages


# ── Backend detection ─────────────────────────────────────────────────────────

def _detect_backend(root: Path, hint: str) -> str:
    if hint in ("go", "python", "node"):
        return hint
    if (root / "go.mod").exists():
        return "go"
    if any(root.glob("*.py")) or (root / "pyproject.toml").exists() or (root / "setup.cfg").exists():
        return "python"
    if (root / "package.json").exists():
        return "node"
    return "unknown"


# ── Go backend (govulncheck) ──────────────────────────────────────────────────

def _govulncheck_reachable(root: Path) -> set[str]:
    """Run ``govulncheck -json ./...`` and return reachable CVE/GO-ID aliases."""
    if shutil.which("govulncheck") is None:
        log.warning(
            "reachability: 'govulncheck' not found. "
            "Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
        )
        return set()

    try:
        result = subprocess.run(
            ["govulncheck", "-json", "./..."],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(root),
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        log.warning("reachability: govulncheck timed out after 120s")
        return set()
    except OSError as exc:
        log.warning("reachability: govulncheck failed: %s", exc)
        return set()

    reachable: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # govulncheck -json emits {"finding": {...}} objects for reachable vulns
        finding = obj.get("finding") or {}
        osv_id = finding.get("osv", "")
        if osv_id:
            reachable.add(osv_id.upper())
        # Also collect any CVE aliases in the advisory
        for alias in finding.get("aliases", []):
            if alias.upper().startswith("CVE-"):
                reachable.add(alias.upper())

    log.debug("reachability(govulncheck): %d reachable vuln IDs found", len(reachable))
    return reachable


# ── Python AST backend ────────────────────────────────────────────────────────

def _find_entrypoint(root: Path, hint: Optional[str]) -> Optional[Path]:
    if hint:
        p = Path(hint)
        if not p.is_absolute():
            p = root / p
        return p if p.exists() else None
    for candidate in ("main.py", "__main__.py", "app.py", "run.py", "server.py"):
        p = root / candidate
        if p.exists():
            return p
    return None


def _pyast_reachable_packages(entrypoint: Path, root: Path) -> set[str]:
    """Return the set of top-level package names imported (transitively) from *entrypoint*.

    Uses a best-effort AST walk — does not execute code or follow dynamic imports.
    Resolves ``import foo`` and ``from foo import bar`` at module level only.
    """
    visited_files: set[Path] = set()
    imported_modules: set[str] = set()

    def _walk_file(path: Path) -> None:
        if path in visited_files:
            return
        visited_files.add(path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, OSError) as exc:
            log.debug("reachability(pyast): skipping %s: %s", path, exc)
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    imported_modules.add(top)
                    _try_follow(top, root, path.parent)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    imported_modules.add(top)
                    _try_follow(top, root, path.parent)

    def _try_follow(module_name: str, root: Path, pkg_dir: Path) -> None:
        """Follow a local/relative module file if it resolves inside root."""
        spec = importlib.util.find_spec(module_name)
        if spec and spec.origin:
            origin = Path(spec.origin)
            if origin.is_relative_to(root):
                _walk_file(origin)

    # Add project root to sys.path temporarily for spec resolution
    inserted = False
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
        inserted = True
    try:
        _walk_file(entrypoint)
    finally:
        if inserted:
            sys.path.remove(str(root))

    log.debug("reachability(pyast): %d imported top-level modules", len(imported_modules))
    return imported_modules


# ── Node.js backend (package.json + require/import AST) ──────────────────────

def _node_reachable_packages(root: Path) -> set[str]:
    """Return the set of npm package names directly or transitively required/imported
    by the project's JS/TS source files.

    Strategy:
    1. Parse ``package.json`` to get the declared dependency list.
    2. Walk all ``.js``, ``.mjs``, ``.cjs``, ``.ts``, ``.tsx`` files under
       ``src/``, ``lib/``, ``index.*`` and the entrypoints listed in
       ``package.json`` (``main``, ``exports``).
    3. Extract bare specifiers from ``require('...')`` and
       ``import ... from '...'`` / ``import('...')`` using a regex scan
       (no full JS parser required — bare specifiers always start without
       ``./`` or ``/``).
    4. Return the intersection of declared deps ∩ found bare specifiers.
       This means a dep listed in package.json but never imported is marked
       unreachable, while anything imported is considered reachable.

    Falls back to returning all declared dependencies if no source files
    are found (conservative — nothing is discounted).
    """
    pkg_json_path = root / "package.json"
    if not pkg_json_path.exists():
        return set()

    try:
        pkg_json = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        log.warning("reachability(node): could not parse package.json: %s", exc)
        return set()

    declared: set[str] = set()
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        declared.update(pkg_json.get(section, {}).keys())

    if not declared:
        return set()

    # Source roots to scan — common conventions
    source_roots: list[Path] = []
    for candidate in ("src", "lib", "app", "pages", "components", "routes"):
        p = root / candidate
        if p.is_dir():
            source_roots.append(p)
    # Also scan index files in root
    for glob in ("index.js", "index.mjs", "index.cjs", "index.ts", "index.tsx", "server.js", "server.ts"):
        p = root / glob
        if p.exists():
            source_roots.append(p)

    # Entrypoints from package.json main/exports
    for key in ("main", "module", "browser"):
        ep = pkg_json.get(key)
        if isinstance(ep, str):
            p = root / ep
            if p.exists():
                source_roots.append(p)

    if not source_roots:
        # No src/ found — fall back to conservative: all declared deps are "reachable"
        log.debug("reachability(node): no source root found in %s — marking all deps reachable", root)
        return declared

    # Collect all .js/.mjs/.cjs/.ts/.tsx files
    extensions = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
    source_files: list[Path] = []
    for entry in source_roots:
        if entry.is_file():
            source_files.append(entry)
        else:
            for ext in extensions:
                source_files.extend(entry.rglob(f"*{ext}"))

    if not source_files:
        return declared  # conservative fallback

    # Regex to match bare specifiers in require() and import statements
    # Bare specifier: starts with a letter, @scope, digits — not ./ ../ /
    _REQUIRE_RE = re.compile(
        r"""(?:require|import)\s*\(\s*['"](@?[a-zA-Z0-9_\-][^'"./][^'"]*)['"]"""
        r"""|from\s+['"](@?[a-zA-Z0-9_\-][^'"./][^'"]*)['"]""",
        re.MULTILINE,
    )

    imported: set[str] = set()
    for sf in source_files:
        try:
            text = sf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _REQUIRE_RE.finditer(text):
            raw = m.group(1) or m.group(2)
            if not raw:
                continue
            # Strip subpath: @scope/pkg/sub → @scope/pkg; pkg/sub → pkg
            if raw.startswith("@"):
                parts = raw.split("/")
                bare = "/".join(parts[:2]) if len(parts) >= 2 else raw
            else:
                bare = raw.split("/")[0]
            imported.add(bare)

    reachable = declared & imported
    log.debug(
        "reachability(node): %d declared deps, %d imported, %d reachable",
        len(declared), len(imported), len(reachable),
    )
    return reachable


# ── Apply reachability to packages ────────────────────────────────────────────

def _apply_reachability(
    packages: list[PackageRecord],
    reachable_ids: set[str],
    source: str,
) -> None:
    """Mark each package's CVEs as reachable/unreachable based on a set of known-reachable IDs."""
    for pkg in packages:
        pkg.reachability_source = source
        pkg.reachable_cves = [c for c in pkg.cve_ids if c.upper() in reachable_ids]
        pkg.unreachable_cves = [c for c in pkg.cve_ids if c.upper() not in reachable_ids]
        pkg.reachable = bool(pkg.reachable_cves)


def _apply_python_reachability(
    packages: list[PackageRecord],
    reachable_pkg_names: set[str],
) -> None:
    """For Python AST backend: a package is reachable if its name is imported."""
    for pkg in packages:
        pkg.reachability_source = "pyast"
        # Normalise: dashes → underscores for import name comparison
        normalised_name = pkg.name.lower().replace("-", "_")
        if normalised_name in {n.lower() for n in reachable_pkg_names}:
            pkg.reachable = True
            pkg.reachable_cves = list(pkg.cve_ids)
            pkg.unreachable_cves = []
        else:
            pkg.reachable = False
            pkg.reachable_cves = []
            pkg.unreachable_cves = list(pkg.cve_ids)


def _mark_unknown(packages: list[PackageRecord]) -> None:
    for pkg in packages:
        pkg.reachability_source = "unknown"


# ── Scoring adjustment helper ─────────────────────────────────────────────────

def apply_reachability_score_discount(packages: list[PackageRecord]) -> None:
    """Reduce the effective EPSS signal for packages with only unreachable CVEs.

    Call this *before* ``score_and_rank`` to let the scorer use discounted values.
    Packages with at least one reachable CVE keep their full EPSS.
    Packages whose reachability check ran but found zero reachable CVEs get an
    80% EPSS discount (matching the Endor Labs / roadmap recommendation).
    Packages not yet checked (reachability_source == "") are left untouched.
    """
    for pkg in packages:
        if pkg.reachability_source and pkg.reachability_source != "unknown":
            if not pkg.reachable and pkg.cve_ids:
                pkg.max_epss = pkg.max_epss * 0.2
                # Also remove from KEV / weaponized for policy purposes
                pkg.in_cisa_kev = False
                pkg.exploit_maturity = "none"
