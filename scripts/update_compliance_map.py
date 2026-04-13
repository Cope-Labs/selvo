#!/usr/bin/env python3
"""Fetch NIST SP 800-53 Rev 5 ↔ CWE cross-references and expand data/compliance_map.json.

Usage
-----
    python scripts/update_compliance_map.py [--dry-run] [--output PATH]

The script queries the NIST CPRT (Cyber PMO Resource Tool) API for all
SP 800-53 Rev 5 controls that "address" CWE weaknesses, then merges any
CWE entries that are missing from compliance_map.json.

Existing manually-curated entries are NEVER overwritten.
New entries land under their CWE key with a minimal mapping:
  - nist    : all 800-53 controls linked by NIST
  - fedramp : same list (conservative default; refine by hand)
  - soc2    : empty list (no authoritative machine-readable source yet)
  - pci     : empty list (same)

The API is documented at:
  https://csrc.nist.gov/projects/cprt

Data source:
  https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800-53_rev_5/element/ALL/relationship/addresses/element/ALL
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import defaultdict

try:
    import httpx
except ImportError:
    sys.exit("httpx is required: pip install httpx")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_REPO_ROOT = pathlib.Path(__file__).parent.parent
_MAP_PATH = _REPO_ROOT / "data" / "compliance_map.json"

# ---------------------------------------------------------------------------
# NIST CPRT API
# ---------------------------------------------------------------------------
_CPRT_BASE = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework"
_ADDRESSES_URL = (
    f"{_CPRT_BASE}/version/sp_800-53_rev_5/element/ALL"
    "/relationship/addresses/element/ALL"
)
_CWE_PATTERN = re.compile(r"^CWE-\d+$", re.ASCII)


def fetch_nist_cwe_map(timeout: float = 30.0) -> dict[str, list[str]]:
    """Return ``{CWE-NNN: [SP800-53-control, ...]}`` from the NIST CPRT API.

    The API returns a flat list of relationship objects.  We pivot them so
    each CWE key accumulates all associated 800-53 control identifiers
    (e.g. ``["SI-10", "AC-3"]``).

    Raises ``httpx.HTTPError`` or ``ValueError`` on failure.
    """
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(
            _ADDRESSES_URL,
            headers={"Accept": "application/json"},
        )
    if resp.status_code != 200:
        raise ValueError(
            f"NIST CPRT API returned HTTP {resp.status_code} — "
            "check the URL or NIST service availability."
        )

    data = resp.json()
    # Response shape (observed): {"response": {"elements": [{...}, ...], ...}}
    # Each element has "identifier" (e.g. "SI-10") and "relationships":
    #   [{"relationshipTypes": ["addresses"], "relatedTo": {"identifier": "CWE-20"}}]
    # Fall back to a top-level list if the shape differs.
    elements = (
        data.get("response", {}).get("elements")
        or data.get("elements")
        or (data if isinstance(data, list) else [])
    )

    cwe_map: dict[str, set[str]] = defaultdict(set)
    for elem in elements:
        control_id = (elem.get("identifier") or "").strip()
        if not control_id:
            continue
        for rel in elem.get("relationships") or []:
            related = rel.get("relatedTo") or {}
            related_id = (related.get("identifier") or "").strip()
            if _CWE_PATTERN.match(related_id):
                cwe_map[related_id].add(control_id)

    if not cwe_map:
        raise ValueError(
            "NIST CPRT response parsed but produced no CWE→control mappings. "
            "The API response shape may have changed — inspect the raw JSON."
        )

    return {cwe: sorted(controls) for cwe, controls in sorted(cwe_map.items())}


# ---------------------------------------------------------------------------
# Merge logic
# ---------------------------------------------------------------------------

def _sorted_cwe_key(key: str) -> tuple[int, str]:
    """Sort ``CWE-NNN`` entries numerically; special tags last."""
    m = re.match(r"CWE-(\d+)$", key)
    return (0, f"{int(m.group(1)):06d}") if m else (1, key)


def merge_into_map(
    existing: dict,
    new_cwe_map: dict[str, list[str]],
) -> tuple[dict, list[str], list[str]]:
    """Return ``(updated_map, added_keys, skipped_keys)``.

    New entries are inserted in ascending CWE-number order before any
    non-CWE special keys.  Existing CWE entries are left unchanged.
    """
    added: list[str] = []
    skipped: list[str] = []

    # Separate metadata keys from CWE/tag keys
    meta_keys = {k for k in existing if k.startswith("_")}
    data = {k: v for k, v in existing.items() if k not in meta_keys}

    for cwe, controls in new_cwe_map.items():
        if cwe in data:
            skipped.append(cwe)
            continue
        data[cwe] = {
            "nist": controls,
            "fedramp": controls,  # conservative default — review before shipping
            "soc2": [],
            "pci": [],
            "_source": "nist-cprt-auto",
        }
        added.append(cwe)

    # Re-assemble: meta first, then all CWE/tag keys sorted
    result: dict = {k: existing[k] for k in meta_keys}
    for k in sorted(data.keys(), key=_sorted_cwe_key):
        result[k] = data[k]

    return result, added, skipped


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Expand compliance_map.json with NIST SP 800-53 Rev 5 / CWE data."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print changes without writing the file."
    )
    parser.add_argument(
        "--output", metavar="PATH", default=str(_MAP_PATH),
        help=f"Output JSON path (default: {_MAP_PATH})."
    )
    args = parser.parse_args(argv)
    output_path = pathlib.Path(args.output)

    # Load existing map
    with _MAP_PATH.open() as f:
        existing: dict = json.load(f)
    print(f"Loaded {_MAP_PATH} ({len([k for k in existing if not k.startswith('_')])} entries)")

    # Fetch NIST data
    print(f"Fetching NIST CPRT data from:\n  {_ADDRESSES_URL}")
    try:
        new_map = fetch_nist_cwe_map()
    except (httpx.HTTPError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"  → received {len(new_map)} CWE→control relationship(s)")

    # Merge
    updated, added, skipped = merge_into_map(existing, new_map)
    print(f"\nResults:")
    print(f"  Added   : {len(added)}  ({', '.join(added[:10])}{'…' if len(added) > 10 else ''})")
    print(f"  Skipped : {len(skipped)} (already present, unchanged)")

    if not added:
        print("Nothing new to write.")
        return 0

    if args.dry_run:
        print("\n[dry-run] Would write updated compliance_map.json (use without --dry-run to apply).")
        return 0

    with output_path.open("w") as f:
        json.dump(updated, f, indent=2)
        f.write("\n")
    print(f"\nWrote {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
