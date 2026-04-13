"""JSON reporter."""
from __future__ import annotations

import dataclasses
import json
from typing import Optional, TYPE_CHECKING

from selvo.discovery.base import PackageRecord

if TYPE_CHECKING:
    from selvo.analysis.local_context import SystemContext


def _record_to_dict(pkg: PackageRecord) -> dict:
    """Serialize a PackageRecord, including computed properties.

    ``dataclasses.asdict`` only captures fields, not ``@property`` values.
    We inject ``is_outdated`` and ``cve_count`` explicitly so the frontend
    and downstream consumers can filter/display them correctly.
    """
    d = dataclasses.asdict(pkg)
    d["is_outdated"] = pkg.is_outdated
    d["cve_count"] = pkg.cve_count
    return d


def render_json(
    packages: list[PackageRecord],
    ctx: Optional["SystemContext"] = None,
) -> str:
    """Serialize packages to a JSON string.

    Output shape::

        {
          "meta": { "mode": "reference", "generated_at": "...", ... },
          "packages": [ { ... }, ... ]
        }

    The ``meta`` key is omitted when no :class:`~selvo.analysis.local_context.SystemContext`
    is supplied (backwards-compat for callers that don't go through the CLI).
    """
    pkgs_payload = [_record_to_dict(p) for p in packages]
    if ctx is not None:
        return json.dumps(
            {"meta": ctx.as_dict(), "packages": pkgs_payload},
            indent=2,
        )
    # Legacy flat-array format when no context provided
    return json.dumps(pkgs_payload, indent=2)
