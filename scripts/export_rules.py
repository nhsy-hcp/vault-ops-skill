#!/usr/bin/env python3
"""Write references/rules.json and the generated blocks of references/rules.md from vault_ops.RULES (run via `task rules:export`)."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/vault-ops/scripts"))

import vault_ops  # noqa: E402

REFERENCES = ROOT / "skills/vault-ops/references"
RULES_JSON = REFERENCES / "rules.json"
RULES_MD = REFERENCES / "rules.md"

# rules.md tables, in RULES order. Anything not claimed by a later table goes in "core".
TABLES = {
    "core": lambda rid: True,
    "clients": lambda rid: rid.startswith("VT-CLI-") or rid in ("VT-ID-004", "VT-ID-005"),
    "acl": lambda rid: rid.startswith("VT-POL-"),
    "sentinel": lambda rid: rid in ("VT-SNT-005", "VT-SNT-006", "VT-SNT-007"),
}
# Every scope but `namespace` (the default: judged in each walked namespace) is listed in rules.md; render_scopes fails on a scope without a label.
SCOPE_LABELS = {
    "root_only": "**Not judged** (`root_only`)",
    "health": "**Judged from `sys/health` and status reads**, whatever the token's namespace (`health`)",
    "token_namespace": "**Judged in the token's namespace** (`token_namespace`)",
}
BLOCK = re.compile(r"(<!-- BEGIN GENERATED (?P<name>[a-z]+)[^>]*-->\n)(?P<body>.*?)(<!-- END GENERATED (?P=name) -->)", re.DOTALL)


def render() -> str:
    return json.dumps(vault_ops.rules_catalogue(), indent=2) + "\n"


def table_of(rid: str) -> str:
    return next(name for name, claims in reversed(TABLES.items()) if claims(rid))


def remediation(rule: vault_ops.Rule) -> str:
    commands = "; ".join(f"`{c}`" for c in rule.commands)
    if not commands:
        return f"No catalogue command. {rule.action}"
    return f"{rule.action} {commands}" if rule.action else commands


def render_table(name: str) -> str:
    lines = ["| rule_id | Sev | What it means | Draft remediation | Watch out for |", "| --- | --- | --- | --- | --- |"]
    for rid, rule in vault_ops.RULES.items():
        if table_of(rid) == name:
            # Rule text never holds `|` (tested), so cells need no escaping.
            lines.append(f"| {rid} | {rule.severity} | {rule.meaning} | {remediation(rule)} | {rule.watch_out} |")
    return "\n".join(lines) + "\n"


def render_placeholders() -> str:
    return "".join(f"- `{{{name}}}`: {text}\n" for name, text in vault_ops.PLACEHOLDERS.items())


def render_scopes() -> str:
    lines = []
    for scope in vault_ops.SCOPES:
        if scope == "namespace":
            continue
        if scope not in SCOPE_LABELS:
            raise SystemExit(f"export_rules.py: no SCOPE_LABELS entry for scope {scope!r}")
        ids = sorted(rid for rid, rule in vault_ops.RULES.items() if rule.scope == scope)
        lines.append(f"- {SCOPE_LABELS[scope]}: {', '.join(ids)}.")
    notes: dict[str, list[str]] = {}
    for rid, rule in sorted(vault_ops.RULES.items()):
        if rule.scope_note:
            notes.setdefault(rule.scope_note, []).append(rid)
    lines.extend(f"- {', '.join(ids)}: {note}" for note, ids in notes.items())
    return "\n".join(lines) + "\n"


def blocks() -> dict[str, str]:
    return {"placeholders": render_placeholders(), "scopes": render_scopes(), **{f"table{name}": render_table(name) for name in TABLES}}


def update_rules_md(text: str) -> str:
    """Replace every generated block's body; fails if a block is missing or unknown, so the file and the code can't diverge silently."""
    wanted = blocks()
    seen: set[str] = set()

    def sub(m: re.Match[str]) -> str:
        name = m.group("name")
        if name not in wanted:
            raise SystemExit(f"rules.md: unknown generated block {name!r}")
        if name in seen:
            raise SystemExit(f"rules.md: generated block {name!r} appears twice")
        seen.add(name)
        return m.group(1) + wanted[name] + m.group(4)

    out = BLOCK.sub(sub, text)
    if missing := set(wanted) - seen:
        raise SystemExit(f"rules.md: missing generated blocks {sorted(missing)}")
    return out


if __name__ == "__main__":
    RULES_JSON.write_text(render())
    RULES_MD.write_text(update_rules_md(RULES_MD.read_text()))
    print(RULES_JSON.relative_to(ROOT))
    print(RULES_MD.relative_to(ROOT))
