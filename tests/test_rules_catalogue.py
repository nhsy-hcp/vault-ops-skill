"""references/rules.json must match RULES; it is the copy other tools (vault-tools) check for drift."""

import json
import re
from pathlib import Path

import vault_ops as vo

REFERENCES = Path(__file__).resolve().parents[1] / "skills/vault-ops/references"


def test_rules_json_matches_rules():
    committed = json.loads((REFERENCES / "rules.json").read_text())
    assert committed == vo.rules_catalogue(), "references/rules.json is stale: run `task rules:export`"


def test_catalogue_uses_known_severities():
    assert {r["severity"] for r in vo.rules_catalogue()["rules"].values()} <= set(vo.SEVERITIES)


def test_every_rule_documented():
    documented = set(re.findall(r"^\| (VT-[A-Z]+-\d+) \|", (REFERENCES / "rules.md").read_text(), re.MULTILINE))
    assert documented == set(vo.RULES)
