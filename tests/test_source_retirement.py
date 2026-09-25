"""End-to-end tests for the GET /api/analyses/{id}/source-retirement endpoint."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-source-retirement-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _inventory(client: TestClient, aid: str) -> dict:
    r = client.get(f"/api/analyses/{aid}/source-retirement")
    assert r.status_code == 200, r.text
    return r.json()


def _by_tag(payload: dict) -> dict[str, dict]:
    return {entry["source_tag"]: entry for entry in payload["sources"]}


# ---------------------------------------------------------------------------
def test_each_source_retired_as_a_whole(client: TestClient) -> None:
    # The README dc-2026-09 version: four sources of one rule each, every one
    # load-bearing.
    aid = _save(client, [
        {"rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "hq"},
        {"rule_id": "r2", "cidr": "10.10.0.0/16", "action": "deny", "priority": 500, "source_tag": "dc1"},
        {"rule_id": "r3", "cidr": "10.10.1.0/24", "action": "permit", "priority": 900, "source_tag": "lab"},
        {"rule_id": "r4", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "v6"},
    ])
    payload = _inventory(client, aid)
    entries = _by_tag(payload)

    assert [e["source_tag"] for e in payload["sources"]] == ["hq", "dc1", "lab", "v6"]
    assert payload["summary"] == {"source_count": 4, "rule_count": 4, "safe_to_retire_count": 0}

    # hq leaves: the /8 outside the deny /16 falls to none (8 minimal CIDRs).
    hq = entries["hq"]
    assert hq["rule_ids"] == ["r1"]
    assert hq["rule_count"] == 1
    assert hq["safe_to_retire"] is False
    assert hq["changed_addresses"] == 2 ** 24 - 2 ** 16
    assert hq["changes"] == [
        {
            "ip_version": 4,
            "change_type": "permit_to_none",
            "from_action": "permit",
            "to_action": None,
            "address_count": 2 ** 24 - 2 ** 16,
            "range_count": 8,
            "cidrs": [
                "10.0.0.0/13", "10.8.0.0/15", "10.11.0.0/16", "10.12.0.0/14",
                "10.16.0.0/12", "10.32.0.0/11", "10.64.0.0/10", "10.128.0.0/9",
            ],
        }
    ]

    # dc1 leaves: the /16 outside the permit /24 falls back to the permit /8.
    dc1 = entries["dc1"]
    assert dc1["changed_addresses"] == 2 ** 16 - 2 ** 8
    assert [c["change_type"] for c in dc1["changes"]] == ["deny_to_permit"]
    assert dc1["changes"][0]["address_count"] == 2 ** 16 - 2 ** 8

    # lab leaves: its /24 is exposed to the deny /16.
    lab = entries["lab"]
    assert lab["changes"] == [
        {
            "ip_version": 4,
            "change_type": "permit_to_deny",
            "from_action": "permit",
            "to_action": "deny",
            "address_count": 2 ** 8,
            "range_count": 1,
            "cidrs": ["10.10.1.0/24"],
        }
    ]

    # v6 leaves: the whole /32 becomes unmatched, counted exactly.
    v6 = entries["v6"]
    assert v6["changed_addresses"] == 2 ** 96
    assert v6["changes"][0]["change_type"] == "deny_to_none"
    assert v6["changes"][0]["ip_version"] == 6
    assert v6["changes"][0]["cidrs"] == ["2001:db8::/32"]


def test_group_verdict_is_recomputed_not_inferred_from_single_rules(client: TestClient) -> None:
    # b and c share CIDR, action and source tag: each one individually deletes
    # cleanly (the other takes over the /16), yet retiring the source removes
    # both and the /16 falls back to the permit /8.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "hq"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "dc"},
        {"rule_id": "c", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "dc"},
    ])

    # Individually, both dc rules are safe to remove.
    redundant = client.get(f"/api/analyses/{aid}/redundant-rules").json()
    per_rule = {e["rule_id"]: e for e in redundant["rules"]}
    assert per_rule["b"]["safe_to_remove"] is True
    assert per_rule["c"]["safe_to_remove"] is True

    entries = _by_tag(_inventory(client, aid))
    dc = entries["dc"]
    assert dc["rule_ids"] == ["b", "c"]
    assert dc["rule_count"] == 2
    assert dc["safe_to_retire"] is False
    assert dc["changed_addresses"] == 2 ** 16
    assert dc["changes"] == [
        {
            "ip_version": 4,
            "change_type": "deny_to_permit",
            "from_action": "deny",
            "to_action": "permit",
            "address_count": 2 ** 16,
            "range_count": 1,
            "cidrs": ["10.1.0.0/16"],
        }
    ]


def test_safe_source_retires_cleanly(client: TestClient) -> None:
    # The "old" source only holds same-action descendants of the permit /8:
    # withdrawing it hands every range back to the same-action ancestor.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "hq"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit", "source_tag": "old"},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "source_tag": "old"},
    ])
    payload = _inventory(client, aid)
    entries = _by_tag(payload)

    assert entries["old"]["rule_ids"] == ["b", "c"]
    assert entries["old"]["safe_to_retire"] is True
    assert entries["old"]["changed_addresses"] == 0
    assert entries["old"]["changes"] == []
    assert entries["hq"]["safe_to_retire"] is False
    assert payload["summary"]["safe_to_retire_count"] == 1


def test_source_spanning_both_families_reports_both(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "v4", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "mixed"},
        {"rule_id": "v6", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "mixed"},
        {"rule_id": "other", "cidr": "192.0.2.0/24", "action": "permit", "source_tag": "ops"},
    ])
    entries = _by_tag(_inventory(client, aid))

    mixed = entries["mixed"]
    assert mixed["rule_ids"] == ["v4", "v6"]
    assert mixed["safe_to_retire"] is False
    assert mixed["changed_addresses"] == 2 ** 24 + 2 ** 96
    # IPv4 changes are reported before IPv6 ones.
    assert [(c["ip_version"], c["change_type"]) for c in mixed["changes"]] == [
        (4, "permit_to_none"),
        (6, "deny_to_none"),
    ]
    assert mixed["changes"][0]["cidrs"] == ["10.0.0.0/8"]
    assert mixed["changes"][1]["cidrs"] == ["2001:db8::/32"]

    # The untouched third rule never appears in any change set.
    ops = entries["ops"]
    assert ops["safe_to_retire"] is False
    assert ops["changed_addresses"] == 2 ** 8


def test_source_carrying_every_rule_compares_against_all_none(client: TestClient) -> None:
    # Single-source version: retiring it empties the ruleset, so every
    # forwarded address becomes unmatched.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "solo"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "solo"},
    ])
    payload = _inventory(client, aid)

    assert payload["summary"] == {"source_count": 1, "rule_count": 2, "safe_to_retire_count": 0}
    solo = payload["sources"][0]
    assert solo["source_tag"] == "solo"
    assert solo["rule_ids"] == ["a", "b"]
    assert solo["safe_to_retire"] is False
    assert solo["changed_addresses"] == 2 ** 24
    assert [(c["change_type"], c["address_count"]) for c in solo["changes"]] == [
        ("permit_to_none", 2 ** 24 - 2 ** 16),
        ("deny_to_none", 2 ** 16),
    ]
    assert solo["changes"][1]["cidrs"] == ["10.1.0.0/16"]


def test_single_rule_version_retires_to_none(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "only", "cidr": "192.168.0.0/24", "action": "deny"}])
    payload = _inventory(client, aid)

    assert payload["sources"] == [
        {
            "source_tag": "default",
            "rule_ids": ["only"],
            "rule_count": 1,
            "safe_to_retire": False,
            "changed_addresses": 2 ** 8,
            "changes": [
                {
                    "ip_version": 4,
                    "change_type": "deny_to_none",
                    "from_action": "deny",
                    "to_action": None,
                    "address_count": 2 ** 8,
                    "range_count": 1,
                    "cidrs": ["192.168.0.0/24"],
                }
            ],
        }
    ]


def test_default_tag_groups_untagged_rules(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "dc"},
        {"rule_id": "c", "cidr": "172.16.0.0/12", "action": "permit"},
    ])
    payload = _inventory(client, aid)
    entries = _by_tag(payload)

    assert [e["source_tag"] for e in payload["sources"]] == ["default", "dc"]
    assert entries["default"]["rule_ids"] == ["a", "c"]
    assert entries["default"]["rule_count"] == 2
    assert entries["dc"]["rule_ids"] == ["b"]


def test_sources_follow_first_appearance_order(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "z-first"},
        {"rule_id": "r2", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "m-second"},
        {"rule_id": "r3", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "a-third"},
        {"rule_id": "r4", "cidr": "10.2.0.0/16", "action": "deny", "source_tag": "z-first"},
    ])
    payload = _inventory(client, aid)

    assert [e["source_tag"] for e in payload["sources"]] == ["z-first", "m-second", "a-third"]
    # Rule ids inside a source keep the original submission order.
    assert payload["sources"][0]["rule_ids"] == ["r1", "r4"]
    assert payload["analysis_id"] == aid
    saved = client.get(f"/api/analyses/{aid}").json()
    assert payload["ruleset_hash"] == saved["ruleset_hash"]
    assert payload["analyzer_version"] == saved["analyzer_version"]


def test_inventory_never_persists_anything(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "hq"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit", "source_tag": "old"},
    ])
    first = _inventory(client, aid)
    second = _inventory(client, aid)
    assert first == second  # deterministic

    listing = client.get("/api/analyses").json()
    assert listing["total"] == 1
    assert listing["analyses"][0]["id"] == aid
    # The stored version is untouched.
    assert len(client.get(f"/api/analyses/{aid}").json()["rules"]) == 2
    # The publication pointer is untouched.
    assert client.get("/api/active").json() == {"active_id": None, "revision": 0}


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.get("/api/analyses/an_0000000000000000/source-retirement")
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]
