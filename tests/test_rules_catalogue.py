"""references/rules.json is the complete rule catalogue (readable on its own); it and the generated
blocks of references/rules.md must match RULES."""

import importlib.util
import json
import re
import string
from datetime import UTC, datetime
from pathlib import Path

import pytest
import vault_ops as vo

ROOT = Path(__file__).resolve().parents[1]
REFERENCES = ROOT / "skills/vault-ops/references"
CATALOGUE = vo.rules_catalogue()


def _export_rules():
    spec = importlib.util.spec_from_file_location("export_rules", ROOT / "scripts/export_rules.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


export_rules = _export_rules()


def fields(command: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(command) if name is not None}


def test_rules_json_matches_rules():
    committed = json.loads((REFERENCES / "rules.json").read_text())
    assert committed == CATALOGUE, "references/rules.json is stale: run `task rules:export`"


def test_rules_md_generated_blocks_match_rules():
    text = (REFERENCES / "rules.md").read_text()
    assert export_rules.update_rules_md(text) == text, "references/rules.md is stale: run `task rules:export`"


def test_rules_md_has_no_repo_references():
    text = (REFERENCES / "rules.md").read_text()
    assert not re.search(r"\btask\b|\.env\b", text)


def test_catalogue_uses_known_severities():
    assert {r["severity"] for r in CATALOGUE["rules"].values()} <= set(vo.SEVERITIES)


def test_every_rule_documented():
    documented = re.findall(r"^\| (VT-[A-Z]+-\d+) \|", (REFERENCES / "rules.md").read_text(), re.MULTILINE)
    assert sorted(documented) == sorted(vo.RULES)  # each exactly once


@pytest.mark.parametrize("rule_id", sorted(vo.RULES))
def test_rule_has_remediation(rule_id):
    rule = vo.RULES[rule_id]
    assert rule.meaning.strip() and rule.watch_out.strip()
    assert rule.commands or rule.action.strip()
    for text in (rule.meaning, rule.action, rule.watch_out, *rule.commands):
        assert "\n" not in text and "|" not in text  # one table cell each, no Markdown table syntax


@pytest.mark.parametrize("rule_id", sorted(vo.RULES))
def test_command_placeholders_are_declared(rule_id):
    for command in vo.RULES[rule_id].commands:
        assert command.startswith("vault ")
        assert fields(command) <= set(vo.PLACEHOLDERS), command
        command.format_map(dict.fromkeys(vo.PLACEHOLDERS, "x"))  # valid template: no stray braces


def test_every_placeholder_is_used():
    used = set().union(*(fields(c) for r in vo.RULES.values() for c in r.commands))
    assert used == set(vo.PLACEHOLDERS)
    assert CATALOGUE["placeholders"] == list(vo.PLACEHOLDERS)


def test_nsflag_expands_to_a_namespace_flag():
    command = vo.RULES["VT-MOUNT-006"].commands[0]
    assert command.format_map({"nsflag": "-namespace=team-a/ ", "path": "kv/"}) == "vault kv enable-versioning -namespace=team-a/ kv/"
    assert command.format_map({"nsflag": "", "path": "kv/"}) == "vault kv enable-versioning kv/"


def test_rank_order_is_a_permutation_sorted_by_tier():
    assert sorted(vo.RANK_ORDER) == sorted(vo.RULES) and len(set(vo.RANK_ORDER)) == len(vo.RULES)
    assert CATALOGUE["rank_order"] == list(vo.RANK_ORDER)
    tiers = [CATALOGUE["rules"][rid]["rank_tier"] for rid in CATALOGUE["rank_order"]]
    assert tiers == sorted(tiers) and set(tiers) == {2, 3, 4, 5}


def test_info_rules_rank_last():
    assert set(vo.RANK_TIERS[5]) == {rid for rid, r in vo.RULES.items() if r.severity == "info"}


def test_ranking_guidance_matches_rank_tiers():
    text = (REFERENCES / "rules.md").read_text()
    guidance = text[text.index("## Severity ranking guidance") :]
    for tier, ids in vo.RANK_TIERS.items():
        line = re.search(rf"^{tier}\. (.*)$", guidance, re.MULTILINE).group(1)
        assert tuple(re.findall(r"VT-[A-Z]+-\d+", line)) == ids, f"tier {tier}"
        assert not re.search(r"VT-[A-Z]+-\d+(/|\.\.)", line), "no shorthand: name every rule"


def test_every_rule_has_a_valid_scope():
    assert {r.scope for r in vo.RULES.values()} == set(vo.SCOPES)
    assert CATALOGUE["scopes"] == vo.SCOPES
    assert all(CATALOGUE["rules"][rid]["scope"] == r.scope for rid, r in vo.RULES.items())
    assert all(rid.startswith("VT-CLI-") for rid, r in vo.RULES.items() if r.scope == "token_namespace")


def test_root_only_rules_cannot_fire_with_a_child_namespace_token(health):
    """collect_health leaves these blocks None for a child-namespace token (`scoped`): then no root_only rule may fire."""
    now = datetime(2026, 11, 4, tzinfo=UTC)
    root_only = {rid for rid, r in vo.RULES.items() if r.scope == "root_only"}
    assert root_only & {f.rule_id for f in vo.health_findings(health, now=now)}  # the fixture does fire them unscoped
    scoped = {**health, **dict.fromkeys(("license", "raft", "lease_ttls", "audit_devices", "snapshots", "metrics"))}
    for kind in ("dr", "performance"):
        if isinstance((scoped.get("replication") or {}).get(kind), dict):
            scoped["replication"] = {**scoped["replication"], kind: {k: v for k, v in scoped["replication"][kind].items() if k != "paths_filters"}}
    assert not root_only & {f.rule_id for f in vo.health_findings(scoped, now=now)}
