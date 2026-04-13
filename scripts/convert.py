#!/usr/bin/env python3
"""
Convert a selvo JSON dump to HTML or CycloneDX SBOM.

Usage:
    python scripts/convert.py html  data.json  _site/index.html
    python scripts/convert.py sbom  data.json  _site/report.sbom.json

Supports both legacy flat-array JSON and the newer envelope format::

    { "meta": { ... }, "packages": [ ... ] }
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path


def _load(json_path: str):
    """Reconstruct (packages, ctx) from a selvo JSON dump.

    Handles both old flat-array format and the new ``{meta, packages}`` envelope.
    Returns a tuple of (list[PackageRecord], SystemContext | None).
    """
    from selvo.discovery.base import PackageRecord, FixRef

    fix_ref_fields = {f.name for f in dataclasses.fields(FixRef)}
    pkg_fields = {f.name for f in dataclasses.fields(PackageRecord)}

    raw = json.loads(Path(json_path).read_text())

    ctx = None
    if isinstance(raw, dict) and "packages" in raw:
        # New envelope format
        records = raw["packages"]
        if "meta" in raw:
            from selvo.analysis.local_context import SystemContext
            meta = raw["meta"]
            ctx_fields = {f.name for f in dataclasses.fields(SystemContext)}
            ctx = SystemContext(**{k: v for k, v in meta.items() if k in ctx_fields})
    else:
        # Legacy flat array
        records = raw

    packages = []
    for d in records:
        fix_refs = [
            FixRef(**{k: v for k, v in r.items() if k in fix_ref_fields})
            for r in d.get("fix_refs", [])
        ]
        kwargs = {k: v for k, v in d.items() if k in pkg_fields and k != "fix_refs"}
        kwargs["fix_refs"] = fix_refs
        packages.append(PackageRecord(**kwargs))
    return packages, ctx


def main() -> None:
    if len(sys.argv) != 4:
        print("Usage: convert.py <html|sbom> <input.json> <output_file>", file=sys.stderr)
        sys.exit(1)

    fmt, json_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    packages, ctx = _load(json_path)

    if fmt == "html":
        from selvo.reporters.html import render_html
        content = render_html(packages, ctx=ctx)
    elif fmt == "sbom":
        from selvo.reporters.sbom import render_sbom
        content = render_sbom(packages)
    else:
        print(f"Unknown format: {fmt!r}. Use 'html' or 'sbom'.", file=sys.stderr)
        sys.exit(1)

    # Upstream package metadata can contain surrogate characters from bad UTF-8.
    # Replace them rather than crashing the pipeline.
    Path(out_path).write_text(content, encoding="utf-8", errors="replace")
    print(f"Written {fmt} → {out_path}  ({len(packages)} packages)")


if __name__ == "__main__":
    main()
