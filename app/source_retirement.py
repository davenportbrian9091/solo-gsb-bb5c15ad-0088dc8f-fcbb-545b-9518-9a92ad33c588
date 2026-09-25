"""Source retirement inventory for a saved analysis version.

For every distinct ``source_tag`` of the version — in the order the tag first
appears in the original rule submission — this module removes **all rules of
that source at once** (the surviving rules keep their original relative order,
which still breaks same-CIDR priority ties), re-runs the longest-prefix-match
analysis on the remainder, and compares the resulting *final effective
actions* (``permit`` / ``deny`` / ``none``) against the original version over
both address families — the same geometric semantic diff as
``GET /api/analyses/{base}/diff/{target}``.

A source is reported ``safe_to_retire`` only when **no address at all**
changes its final action once the whole group is gone.  The verdict is always
recomputed from the group removal, never inferred from per-rule results:
every rule of a source may be individually redundant (e.g. two same-CIDR,
same-action rules of one tag where each covers for the other) while retiring
the group together still flips the range they jointly held.  When the source
carries every rule of the version, the empty remainder is compared against an
all-``none`` surface (no rule matches anywhere).

Each entry lists the source's rule ids in original submission order, the
``safe_to_retire`` flag, the exact number of addresses whose final action
would change, and the changes themselves as minimal CIDR ranges grouped by
action transition (the six ``permit``/``deny``/``none`` types, exact address
counts included — IPv6 counted exactly).

The inventory is read-only: the analyzer is re-run in memory only, nothing
is persisted and no new analysis version is created.
"""

from __future__ import annotations

from typing import Any

from .analyzer import analyze_rules
from .diff import diff_analyses
from .simulate import rebuild_input_rules


def _empty_analysis() -> dict[str, Any]:
    """Effective-action surface of an empty rule set (everything is ``none``).

    ``analyze_rules`` requires at least one rule, so retiring the source that
    carries every rule of the version is compared against this synthetic
    empty result instead (mirroring ``app.redundant._empty_analysis``).
    """
    return {"id": None, "ruleset_hash": None, "analyzer_version": None, "rules": []}


def source_retirement_inventory(base: dict[str, Any]) -> dict[str, Any]:
    """Check every source of a saved version for whole-group removability.

    ``base`` is the stored analysis result (as returned by
    ``db.get_analysis``).  Sources are reported in the order their tag first
    appears in the original rule submission; each entry carries the source's
    rule ids (original order), ``safe_to_retire``, the exact number of
    addresses whose final action would change if the whole source were
    withdrawn, and the minimal-CIDR changes grouped by action transition.
    """
    base_input = rebuild_input_rules(base)

    # Group rule ids by source tag, keeping the first-appearance order of the
    # tags and the original submission order of the ids inside each group.
    rule_ids_by_tag: dict[str, list[str]] = {}
    tag_order: list[str] = []
    for rule in base_input:
        tag = rule["source_tag"]
        if tag not in rule_ids_by_tag:
            rule_ids_by_tag[tag] = []
            tag_order.append(tag)
        rule_ids_by_tag[tag].append(rule["rule_id"])

    entries: list[dict[str, Any]] = []
    for tag in tag_order:
        remaining = [r for r in base_input if r["source_tag"] != tag]
        # Recompute the longest-prefix verdict without this whole source...
        reduced = analyze_rules(remaining) if remaining else _empty_analysis()
        # ...then compare final permit/deny/none actions on every address.
        diff = diff_analyses(base, reduced)
        changed = diff["summary"]["total_changed_addresses"]
        entries.append(
            {
                "source_tag": tag,
                "rule_ids": rule_ids_by_tag[tag],
                "rule_count": len(rule_ids_by_tag[tag]),
                "safe_to_retire": changed == 0,
                "changed_addresses": changed,
                "changes": diff["changes"],
            }
        )

    return {
        "analysis_id": base.get("id"),
        "ruleset_hash": base.get("ruleset_hash"),
        "analyzer_version": base.get("analyzer_version"),
        "summary": {
            "source_count": len(entries),
            "rule_count": len(base_input),
            "safe_to_retire_count": sum(1 for e in entries if e["safe_to_retire"]),
        },
        "sources": entries,
    }
