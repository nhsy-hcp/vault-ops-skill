"""Optimise the vault-ops SKILL.md body with GEPA, scored by `claude plugin eval`.

Each candidate body is written into a copy of the plugin under the run dir, and every
offline eval case is run against that copy (no baseline arm). Failed graders feed the
reflection model, which is `claude -p` on the operator's own Claude credential.

Output (`.tmp/gepa/<timestamp>/`): `best/SKILL.md`, `best.diff`, `summary.json`, `spend.json`,
`evals.jsonl` (one row per case evaluation or rejected candidate), per-case eval JSON under
`runs/`. Nothing in the repo is changed: apply `best.diff` by hand.

The budget is cumulative per run dir: `spend.json` carries it across `--resume`.

Usage: task eval:gepa -- [--budget-usd 40] [--max-metric-calls N] [--reflection-model opus] [--resume DIR]
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SKILL_REL = Path("skills/vault-ops/SKILL.md")
COMPONENT = "skill_body"
# Guardrail cases gate acceptance: GEPA only keeps candidates that score on these.
VAL_CASES = ["refuse-write", "no-token-hunt", "partial-coverage", "interpret-last-audit", "sealed-node"]
REQUIRED = [
    (r"\$\{CLAUDE_SKILL_DIR\}/scripts/vault_ops\.py", "the `${CLAUDE_SKILL_DIR}/scripts/vault_ops.py` script call"),
    (r"NEVER make changes", "the 'NEVER make changes' read-only rule"),
    (r"references/setup\.md", "the link to references/setup.md"),
    (r"references/replication\.md", "the link to references/replication.md"),
    (r"references/rules\.md", "the link to references/rules.md"),
    (r"## Setup problems", "the 'Setup problems' section"),
    (r"for an operator to run", "labelling drafted commands 'for an operator to run'"),
]
FORBIDDEN = [
    (r"\btask (?:eval|skill|up|seed|token|lint|test)\b|Taskfile", "Taskfile commands (the published skill must not depend on this repo)"),
    (r"\.tmp/audit-token|~/Projects|vault-ops-skill/", "this repo's paths"),
    (r"```", "triple backticks (they break the reflection output parser)"),
]
MAX_GROWTH = 1.25
# Stop after this many evaluate() calls in a row that ran no new eval (e.g. every minibatch already perfect, so GEPA proposes nothing).
STALL_LIMIT = 30
# Reserved per agent run before launching an eval, and passed as that eval's --max-cost-usd.
# Observed: median $0.22, max $0.51 per run (agent + judges), so graders are never skipped for cost.
PER_RUN_USD = 0.75
EVIDENCE_CHARS = 3000

REFLECTION_TEMPLATE = """You are improving the body of a Claude Code skill file (SKILL.md, the part after the YAML frontmatter)
for a READ-ONLY HashiCorp Vault operations skill. Claude reads it whenever the skill triggers, then runs a bundled script and reports on its JSON output.

Current body:
```
<curr_param>
```

Below are eval cases run with this body: the user prompt, Claude's final answer (truncated), and feedback naming each failed check with the grader's requirements:
```
<side_info>
```

Write an improved body that fixes the failures without breaking what already passes.
- Fix root causes with general rules, not case-specific answers: never mention eval case names, fixture values or grader wording.
- Keep every hard rule: read-only (never change Vault, never run remediation, never mint tokens),
  the `${CLAUDE_SKILL_DIR}/scripts/vault_ops.py` call, the Setup problems section, and the links to references/setup.md, references/replication.md and references/rules.md.
- Never mention Taskfile commands, .tmp/audit-token or any repository path. Never use triple backticks inside the body.
- Keep it concise: the body is loaded into context on every trigger; it must stay within 25% of its current length, and shorter is better.

Return only the new body inside a single ``` block."""


def split_skill(text: str) -> tuple[str, str]:
    """Split SKILL.md into (frontmatter including both --- lines and trailing newline, body)."""
    m = re.match(r"^(---\n.*?\n---\n)(.*)$", text, re.S)
    if not m:
        raise ValueError("SKILL.md has no YAML frontmatter")
    return m.group(1), m.group(2)


def check_guardrails(body: str, seed_body: str) -> list[str]:
    """Return guardrail violations for a candidate body (empty when it is acceptable)."""
    problems = [f"Removed {why}." for pat, why in REQUIRED if re.search(pat, seed_body) and not re.search(pat, body)]
    problems += [f"Added {why}." for pat, why in FORBIDDEN if re.search(pat, body) and not re.search(pat, seed_body)]
    if len(body) > MAX_GROWTH * len(seed_body):
        problems.append(f"Body is {len(body)} chars, over the {int(MAX_GROWTH * len(seed_body))} limit ({MAX_GROWTH}x the original).")
    return problems


def body_sha(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()[:12]


def strip_frontmatter(text: str) -> str:
    m = re.match(r"^---\n.*?\n---\n(.*)$", text, re.S)
    return (m.group(1) if m else text).strip()


def offline_cases(evals_dir: Path) -> list[str]:
    """Case dirs whose prompt.md frontmatter tags include `offline` (what `task eval` runs)."""
    names = []
    for prompt in sorted(evals_dir.glob("*/prompt.md")):
        head = prompt.read_text().split("\n---", 1)[0]
        if re.search(r"^tags:.*\boffline\b", head, re.M):
            names.append(prompt.parent.name)
    return names


def run_cost(agg: dict[str, Any]) -> float:
    judge = sum(r.get("judgeCostUsd") or 0 for c in agg.get("cases", []) for runs in c.get("arms", {}).values() for r in runs)
    return float(agg.get("costUsd") or 0) + judge


def is_skipped(grader: dict[str, Any]) -> bool:
    """A grader the eval did not judge (e.g. `skipped: cost ceiling`): neither a pass nor a fail."""
    return str(grader.get("explanation") or "").lower().startswith("skipped")


def run_score(run: dict[str, Any]) -> float | None:
    """Weighted pass rate of one agent run over its graded checks; 0 on a run error, None if nothing was graded."""
    if run.get("error"):
        return 0.0
    graded = [g for g in run.get("graders", []) if g.get("scored", True) and not is_skipped(g)]
    total = sum(float(g.get("weight", 1)) for g in graded)
    if not total:
        return None
    return sum(float(g.get("weight", 1)) for g in graded if g.get("passed")) / total


def parse_case_result(agg: dict[str, Any], case_dir: Path) -> tuple[float | None, dict[str, str]]:
    """Score (0..1, mean over runs of graded checks only; None if no run was graded) and a GEPA reflective record."""
    case = agg["cases"][0]
    runs = case.get("arms", {}).get("with", [])
    run_scores = [s for s in (run_score(r) for r in runs) if s is not None]
    score = sum(run_scores) / len(run_scores) if run_scores else None
    failed: dict[str, str] = {}
    skipped = 0
    answer = ""
    errors = []
    for run in runs:
        if run.get("error"):
            errors.append(str(run["error"])[:300])
        for g in run.get("graders", []):
            if g.get("evidence") and not answer:
                answer = g["evidence"]
            if is_skipped(g):
                skipped += 1
            elif g.get("scored", True) and not g.get("passed"):
                failed.setdefault(g["name"], g.get("explanation") or "failed")
                answer = g.get("evidence") or answer
    lines = [f"Score {score:.2f} over {len(run_scores)} graded run(s)." if score is not None else "No graded checks: score unknown."]
    lines += [f"Run error: {e}" for e in errors]
    if skipped:
        lines.append(f"{skipped} check(s) skipped by the eval (not judged, not counted).")
    for name, why in failed.items():
        grader = case_dir / "graders" / f"{name}.md"
        req = strip_frontmatter(grader.read_text()) if grader.exists() else ""
        lines.append(f"FAILED check '{name}' ({why}). Requirement: {req}")
    if not failed and not errors and score is not None:
        lines.append("All checks passed; keep this behaviour.")
    prompt = case_dir / "prompt.md"
    return score, {
        "Inputs": strip_frontmatter(prompt.read_text()) if prompt.exists() else case_dir.name,
        "Generated Outputs": answer[:EVIDENCE_CHARS] or "(no answer captured)",
        "Feedback": "\n".join(lines),
    }


class BudgetExhausted(RuntimeError):
    """Raised instead of scoring a case that the remaining budget can't pay for."""


class Budget:
    """Cumulative spend cap. With `path`, spend is persisted there and reloaded, so `--resume` continues the tally.

    Evals reserve their worst-case cost before launch (`reserve`) and `settle` the actual cost after, so
    concurrent evals can't jointly overrun the limit. `exhausted` once less than `min_launch` is left.
    """

    def __init__(self, limit: float, path: Path | None = None, min_launch: float = 0.0) -> None:
        self.limit = limit
        self.path = path
        self.min_launch = min_launch
        self.reserved = 0.0
        self.lock = threading.Lock()
        self.spent = float(json.loads(path.read_text()).get("spent_usd", 0)) if path and path.exists() else 0.0

    def _save(self) -> None:
        if self.path:
            self.path.write_text(json.dumps({"spent_usd": round(self.spent, 6), "limit_usd": self.limit}) + "\n")

    def add(self, usd: float) -> None:
        with self.lock:
            self.spent += usd
            self._save()

    def reserve(self, usd: float) -> bool:
        with self.lock:
            if self.limit - self.spent - self.reserved < usd:
                return False
            self.reserved += usd
            return True

    def settle(self, reserved: float, actual: float) -> None:
        with self.lock:
            self.reserved -= reserved
            self.spent += actual
            self._save()

    @property
    def remaining(self) -> float:
        return max(self.limit - self.spent - self.reserved, 0.0)

    @property
    def exhausted(self) -> bool:
        return self.limit - self.spent < max(self.min_launch, 1e-9)

    def stopper(self, _state: Any) -> bool:
        return self.exhausted


class ClaudeEvalAdapter:
    """GEPAAdapter: DataInst = case name, candidate = {COMPONENT: SKILL.md body}."""

    # GEPA reads this attribute directly; None means "use reflection_lm with the prompt template".
    propose_new_texts = None

    def __init__(self, run_dir: Path, frontmatter: str, seed_body: str, budget: Budget, train_runs: int, val_runs: int, concurrency: int, model: str | None) -> None:
        self.run_dir = run_dir
        self.frontmatter = frontmatter
        self.seed_body = seed_body
        self.budget = budget
        self.train_runs = train_runs
        self.val_runs = val_runs
        self.concurrency = concurrency
        self.model = model
        self.log = (run_dir / "evals.jsonl").open("a")
        self.log_lock = threading.Lock()
        self.ran_new = False
        self.idle_evals = 0

    def stalled(self) -> bool:
        return self.idle_evals >= STALL_LIMIT

    def stopper(self, _state: Any) -> bool:
        """GEPA stop callback: budget spent, or nothing new evaluated for STALL_LIMIT calls."""
        if self.stalled():
            print(f"[gepa] stopping: {STALL_LIMIT} evaluations in a row ran nothing new (all sampled cases already pass)", file=sys.stderr)
        return self.budget.exhausted or self.stalled()

    def _log(self, row: dict[str, Any]) -> None:
        with self.log_lock:
            self.log.write(json.dumps({**row, "spent_usd": round(self.budget.spent, 4)}) + "\n")
            self.log.flush()

    def _plugin_copy(self, body: str) -> tuple[str, Path]:
        sha = body_sha(body)
        dest = self.run_dir / "cand" / sha
        if not dest.exists():
            tmp = dest.with_suffix(".partial")
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.copytree(ROOT / ".claude-plugin", tmp / ".claude-plugin")
            shutil.copytree(ROOT / "skills", tmp / "skills", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "evals", tmp / "evals", symlinks=True, ignore=shutil.ignore_patterns("results"))
            (tmp / SKILL_REL).write_text(self.frontmatter + body)
            tmp.rename(dest)
        return sha, dest

    def _run_case(self, sha: str, plugin: Path, case: str) -> tuple[float, dict[str, str]]:
        case_dir = plugin / "evals" / case
        out_dir = self.run_dir / "runs" / sha / case
        out_json = out_dir / "result.json"
        if not out_json.exists():
            runs = self.val_runs if case in VAL_CASES else self.train_runs
            reserve = PER_RUN_USD * runs
            if not self.budget.reserve(reserve):
                self._log({"candidate": sha, "case": case, "status": "budget_exhausted"})
                raise BudgetExhausted(f"${self.budget.remaining:.2f} left, ${reserve:.2f} needed for {case}")
            out_dir.mkdir(parents=True, exist_ok=True)
            cmd = ["claude", "plugin", "eval", str(plugin), "--case", case, "--scaffold", "--trust-plugin", "--no-publish", "--ablation", "none"]
            cmd += ["--runs", str(runs), "--max-cost-usd", f"{reserve:.2f}", "--json", str(out_json), "--output-dir", str(out_dir)]
            cmd += ["--report", str(out_dir / "report.html")]
            if self.model:
                cmd += ["--model", self.model]
            self.ran_new = True
            actual = 0.0
            try:
                with (out_dir / "eval.log").open("w") as logf:
                    subprocess.run(cmd, cwd=ROOT, stdout=logf, stderr=subprocess.STDOUT, check=False)
                if out_json.exists():
                    actual = run_cost(json.loads(out_json.read_text()))
            finally:
                self.budget.settle(reserve, actual)
            if not out_json.exists():
                self._log({"candidate": sha, "case": case, "status": "eval_failed"})
                return 0.0, {"Inputs": case, "Generated Outputs": "", "Feedback": f"Eval run failed; see {out_dir / 'eval.log'}."}
        score, record = parse_case_result(json.loads(out_json.read_text()), case_dir)
        self._log({"candidate": sha, "case": case, "status": "scored" if score is not None else "ungraded", "score": score})
        shown = f"{score:.2f}" if score is not None else "ungraded"
        print(f"[gepa] {sha} {case}: {shown} (spent ${self.budget.spent:.2f} of ${self.budget.limit:.2f})", file=sys.stderr)
        return (score if score is not None else 0.0), record

    def evaluate(self, batch: list[str], candidate: dict[str, str], capture_traces: bool = False):
        from gepa import EvaluationBatch

        body = candidate[COMPONENT]
        self.ran_new = False
        problems = check_guardrails(body, self.seed_body)
        if problems:
            self._log({"candidate": body_sha(body), "status": "rejected", "problems": problems})
            print(f"[gepa] {body_sha(body)} rejected: {' '.join(problems)}", file=sys.stderr)
            fb = "Candidate rejected before running (score 0): " + " ".join(problems)
            records = [{"Inputs": c, "Generated Outputs": "", "Feedback": fb} for c in batch]
        else:
            sha, plugin = self._plugin_copy(body)
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                results = list(pool.map(lambda c: self._run_case(sha, plugin, c), batch))
            records = [r for _, r in results]
        scores = [0.0] * len(batch) if problems else [s for s, _ in results]
        self.idle_evals = 0 if (self.ran_new or problems) else self.idle_evals + 1
        return EvaluationBatch(outputs=records, scores=scores, trajectories=records if capture_traces else None)

    def make_reflective_dataset(self, candidate: dict[str, str], eval_batch, components_to_update: list[str]):
        return {comp: list(eval_batch.trajectories or []) for comp in components_to_update}


def claude_reflection_lm(model: str, budget: Budget, cwd: Path):
    """Reflection LM as `claude -p` (no tools) on the operator's credential; cost counts against the budget."""

    def call(prompt: str) -> str:
        if budget.exhausted:
            raise BudgetExhausted("no budget left for reflection")
        cmd = ["claude", "-p", "--model", model, "--output-format", "json", "--tools", "", "--no-session-persistence", "--strict-mcp-config", "--disable-slash-commands"]
        cmd += ["--system-prompt", "You rewrite instruction documents for AI agents. Follow the user's output format exactly."]
        proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, cwd=cwd, check=False, timeout=900)
        if proc.returncode != 0:
            raise RuntimeError(f"claude -p failed with exit {proc.returncode}")
        out = json.loads(proc.stdout)
        budget.add(float(out.get("total_cost_usd") or 0))
        return out.get("result") or ""

    return call


def remove_plugin_copies(run_dir: Path) -> None:
    """Delete cand/ (full plugin copies). Left in the repo, `claude plugin eval .` discovers and tests them too."""
    shutil.rmtree(run_dir / "cand", ignore_errors=True)


def optimise(args: argparse.Namespace, run_dir: Path, train: list[str], val: list[str], skill_text: str, budget: Budget, adapter: ClaudeEvalAdapter) -> int:
    """Run GEPA and write best/SKILL.md, best.diff and summary.json into run_dir."""
    import gepa

    frontmatter, seed_body = split_skill(skill_text)
    try:
        result = gepa.optimize(
            seed_candidate={COMPONENT: seed_body},
            trainset=train,
            valset=val,
            adapter=adapter,
            reflection_lm=claude_reflection_lm(args.reflection_model, budget, run_dir),
            reflection_prompt_template=REFLECTION_TEMPLATE,
            reflection_minibatch_size=args.minibatch,
            max_metric_calls=args.max_metric_calls,
            stop_callbacks=[adapter.stopper],
            run_dir=str(run_dir / "gepa"),
            raise_on_exception=False,
            seed=0,
        )
    except BudgetExhausted as e:  # only reachable before GEPA's own loop (seed evaluation); inside it, raise_on_exception=False
        print(f"[gepa] budget exhausted before the seed evaluation finished: {e}", file=sys.stderr)
        return 1

    best_body = result.best_candidate[COMPONENT].rstrip("\n") + "\n"
    (run_dir / "best").mkdir(exist_ok=True)
    (run_dir / "best" / "SKILL.md").write_text(frontmatter + best_body)
    diff = difflib.unified_diff(skill_text.splitlines(keepends=True), (frontmatter + best_body).splitlines(keepends=True), f"a/{SKILL_REL}", f"b/{SKILL_REL}")
    (run_dir / "best.diff").write_text("".join(diff))
    summary = {
        "best_idx": result.best_idx,
        "val_scores": result.val_aggregate_scores,
        "seed_val_score": result.val_aggregate_scores[0],
        "best_val_score": result.val_aggregate_scores[result.best_idx],
        "candidates": len(result.candidates),
        "spent_usd": round(budget.spent, 2),
        "train": train,
        "val": val,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"[gepa] seed {summary['seed_val_score']:.3f} -> best {summary['best_val_score']:.3f} (candidate {result.best_idx}); spent ${budget.spent:.2f}", file=sys.stderr)
    print(run_dir / "best.diff")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--budget-usd", type=float, default=40.0, help="ceiling for eval runs + reflection, cumulative across --resume (default 40)")
    ap.add_argument("--max-metric-calls", type=int, default=None, help="optional GEPA cap on case evaluations")
    ap.add_argument("--reflection-model", default="opus", help="model for `claude -p` reflection (default opus)")
    ap.add_argument("--model", default=None, help="override the agent model in eval runs")
    ap.add_argument("--train-runs", type=int, default=3, help="agent runs per training case (default 3; 1 hides flaky failures)")
    ap.add_argument("--val-runs", type=int, default=3, help="agent runs per validation case (default 3)")
    ap.add_argument("--minibatch", type=int, default=3, help="reflection minibatch size (default 3)")
    ap.add_argument("-j", "--concurrency", type=int, default=4)
    ap.add_argument(
        "--train-on-val",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="also put the validation cases in the trainset, so their failures drive reflection (default on; GEPA reflects only on train failures)",
    )
    ap.add_argument("--resume", type=Path, default=None, help="existing run dir to resume (reuses cached case results and spend)")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    skill_text = (ROOT / SKILL_REL).read_text()
    frontmatter, seed_body = split_skill(skill_text)
    cases = offline_cases(ROOT / "evals")
    val = [c for c in VAL_CASES if c in cases]
    train = cases if args.train_on_val else [c for c in cases if c not in val]
    if len(val) != len(VAL_CASES) or not train:
        print(f"[gepa] unexpected case set: {cases}", file=sys.stderr)
        return 1

    run_dir = args.resume or ROOT / ".tmp" / "gepa" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    budget = Budget(args.budget_usd, run_dir / "spend.json", min_launch=PER_RUN_USD * min(args.train_runs, args.val_runs))
    adapter = ClaudeEvalAdapter(run_dir, frontmatter, seed_body, budget, args.train_runs, args.val_runs, args.concurrency, args.model)
    print(f"[gepa] run dir {run_dir}; train {train}; val {val}; budget ${args.budget_usd:.2f} (${budget.spent:.2f} already spent)", file=sys.stderr)
    if budget.exhausted:
        print("[gepa] budget already spent for this run dir; raise --budget-usd to continue", file=sys.stderr)
        return 1

    try:
        return optimise(args, run_dir, train, val, skill_text, budget, adapter)
    finally:
        remove_plugin_copies(run_dir)


if __name__ == "__main__":
    sys.exit(main())
