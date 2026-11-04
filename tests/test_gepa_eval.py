"""Unit tests for scripts/gepa_eval.py (no API calls, no eval runs)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import gepa_eval as ge  # noqa: E402

SKILL = (ROOT / ge.SKILL_REL).read_text()
FRONT, BODY = ge.split_skill(SKILL)


def agg(score, graders, cost=0.5, judge=0.01, error=None):
    run = {"score": score, "error": error, "judgeCostUsd": judge, "graders": graders}
    return {"costUsd": cost, "cases": [{"name": "partial-coverage", "aggregates": {"score": score}, "arms": {"with": [run]}}]}


def test_split_skill_roundtrip():
    assert FRONT.startswith("---\nname: vault-ops\n") and FRONT.endswith("---\n")
    assert FRONT + BODY == SKILL


def test_split_skill_requires_frontmatter():
    with pytest.raises(ValueError):
        ge.split_skill("# no frontmatter\n")


def test_seed_body_passes_guardrails():
    assert ge.check_guardrails(BODY, BODY) == []


@pytest.mark.parametrize(
    "mutate, expect",
    [
        (lambda b: b.replace("${CLAUDE_SKILL_DIR}/scripts/vault_ops.py", "vault_ops.py"), "CLAUDE_SKILL_DIR"),
        (lambda b: b.replace("NEVER make changes", "Avoid changes"), "NEVER make changes"),
        (lambda b: b.replace("## Setup problems", "## Setup"), "Setup problems"),
        (lambda b: b + "\nRun `task skill:run -- audit`.\n", "Taskfile"),
        (lambda b: b + "\nToken: .tmp/audit-token\n", "repo's paths"),
        (lambda b: b + "\n```\nvault status\n```\n", "triple backticks"),
        (lambda b: b + "x" * len(b), "limit"),
    ],
)
def test_guardrail_violations(mutate, expect):
    problems = ge.check_guardrails(mutate(BODY), BODY)
    assert any(expect in p for p in problems), problems


def test_offline_cases_match_task_eval():
    cases = ge.offline_cases(ROOT / "evals")
    assert set(ge.VAL_CASES) <= set(cases)
    assert len(cases) >= len(ge.VAL_CASES) + 3


def test_parse_case_result_failed_grader_feedback():
    graders = [
        {"name": "names-policy", "passed": True, "scored": True, "evidence": "answer text"},
        {"name": "partial-first", "passed": False, "scored": True, "explanation": "judge votes: FAIL FAIL PASS", "evidence": "The licence expires soon."},
    ]
    score, rec = ge.parse_case_result(agg(0.5, graders), ROOT / "evals" / "partial-coverage")
    assert score == 0.5
    assert rec["Generated Outputs"] == "The licence expires soon."
    assert "FAILED check 'partial-first'" in rec["Feedback"] and "partial or incomplete" in rec["Feedback"]
    assert "names-policy" not in rec["Feedback"]
    assert rec["Inputs"] and not rec["Inputs"].startswith("---")


def test_parse_case_result_all_pass_and_truncation():
    graders = [{"name": "names-policy", "passed": True, "scored": True, "evidence": "y" * 10_000}]
    score, rec = ge.parse_case_result(agg(1, graders), ROOT / "evals" / "partial-coverage")
    assert score == 1.0 and "All checks passed" in rec["Feedback"]
    assert len(rec["Generated Outputs"]) == ge.EVIDENCE_CHARS


def test_parse_case_result_run_error():
    score, rec = ge.parse_case_result(agg(0, [], error="timeout"), ROOT / "evals" / "partial-coverage")
    assert score == 0 and "Run error: timeout" in rec["Feedback"]


def test_run_cost_includes_judge():
    assert ge.run_cost(agg(1, [], cost=0.5, judge=0.25)) == pytest.approx(0.75)


def test_budget():
    b = ge.Budget(1.0)
    b.add(0.4)
    assert b.remaining == pytest.approx(0.6) and not b.stopper(None)
    b.add(0.6)
    assert b.exhausted and b.stopper(None) and b.remaining == 0


def test_rejected_candidate_runs_nothing(tmp_path, monkeypatch):
    pytest.importorskip("gepa")
    monkeypatch.setattr(ge.subprocess, "run", lambda *a, **k: pytest.fail("eval must not run"))
    adapter = ge.ClaudeEvalAdapter(tmp_path, FRONT, BODY, ge.Budget(1), 1, 2, 2, None)
    batch = adapter.evaluate(["refuse-write"], {ge.COMPONENT: BODY.replace("NEVER make changes", "")}, capture_traces=True)
    assert batch.scores == [0.0]
    assert "rejected" in batch.trajectories[0]["Feedback"]
    assert adapter.make_reflective_dataset({}, batch, [ge.COMPONENT]) == {ge.COMPONENT: batch.trajectories}


def test_stall_stopper_on_cached_results(tmp_path, monkeypatch):
    pytest.importorskip("gepa")
    adapter = ge.ClaudeEvalAdapter(tmp_path, FRONT, BODY, ge.Budget(1), 1, 2, 1, None)
    monkeypatch.setattr(adapter, "_run_case", lambda sha, plugin, case: (1.0, {"Inputs": case, "Generated Outputs": "", "Feedback": "ok"}))
    for _ in range(ge.STALL_LIMIT - 1):
        adapter.evaluate(["refuse-write"], {ge.COMPONENT: BODY})
    assert not adapter.stopper(None)
    adapter.evaluate(["refuse-write"], {ge.COMPONENT: BODY})
    assert adapter.stopper(None)
    assert not adapter.budget.exhausted


def test_rejected_candidate_resets_stall(tmp_path):
    pytest.importorskip("gepa")
    adapter = ge.ClaudeEvalAdapter(tmp_path, FRONT, BODY, ge.Budget(1), 1, 2, 1, None)
    adapter.idle_evals = ge.STALL_LIMIT - 1
    adapter.evaluate(["refuse-write"], {ge.COMPONENT: ""})
    assert adapter.idle_evals == 0


def test_optimize_proposes_and_accepts_rewrite(tmp_path, monkeypatch):
    """End-to-end GEPA loop with a fake eval and fake reflection LM: a failing case must yield a rewrite."""
    gepa = pytest.importorskip("gepa")
    fixed = BODY + "\nAlways state partial coverage first.\n"
    adapter = ge.ClaudeEvalAdapter(tmp_path, FRONT, BODY, ge.Budget(1), 1, 1, 1, None)

    def fake_case(sha, plugin, case):
        score = 1.0 if "partial coverage first" in (plugin / ge.SKILL_REL).read_text() or case != "partial-coverage" else 0.0
        return score, {"Inputs": case, "Generated Outputs": "answer", "Feedback": f"Score {score}"}

    prompts = []

    def fake_lm(prompt):
        prompts.append(prompt)
        return "```\n" + fixed + "```"

    monkeypatch.setattr(adapter, "_run_case", fake_case)
    result = gepa.optimize(
        seed_candidate={ge.COMPONENT: BODY},
        trainset=["partial-coverage", "refuse-write"],
        valset=["partial-coverage", "refuse-write"],
        adapter=adapter,
        reflection_lm=fake_lm,
        reflection_prompt_template=ge.REFLECTION_TEMPLATE,
        reflection_minibatch_size=2,
        max_metric_calls=12,
        stop_callbacks=[adapter.stopper],
        run_dir=str(tmp_path / "gepa"),
        raise_on_exception=True,
    )
    assert prompts and "Score 0.0" in prompts[0]
    assert result.best_candidate[ge.COMPONENT].strip() == fixed.strip()
    assert result.val_aggregate_scores[result.best_idx] == 1.0


# --- fixes from .plans/gepa-recommendations.md section 4 ---


def g(name, passed, explanation="judge votes", weight=1):
    return {"name": name, "passed": passed, "scored": True, "weight": weight, "explanation": explanation, "evidence": f"{name} answer"}


def test_skipped_grader_not_counted_as_failure():
    """Run 3: `skipped: cost ceiling` dropped trigger-audit to 0.83 although every judged check passed."""
    runs = [[g("skill-fired", True), g("no-fabrication", True)]] * 2 + [[g("skill-fired", True), g("no-fabrication", False, "skipped: cost ceiling")]]
    data = {"costUsd": 1, "cases": [{"aggregates": {"score": 0.83}, "arms": {"with": [{"error": None, "graders": r} for r in runs]}}]}
    score, rec = ge.parse_case_result(data, ROOT / "evals" / "trigger-audit")
    assert score == 1.0
    assert "FAILED" not in rec["Feedback"] and "1 check(s) skipped" in rec["Feedback"]


def test_all_skipped_is_ungraded_not_zero():
    score, rec = ge.parse_case_result(agg(0, [g("a", False, "skipped: cost ceiling")]), ROOT / "evals" / "partial-coverage")
    assert score is None and "score unknown" in rec["Feedback"]
    assert ge.run_score({"error": None, "graders": [g("a", False, "skipped")]}) is None


def test_run_score_weights_and_unscored():
    graders = [g("a", True, weight=3), g("b", False, weight=1), {**g("c", False), "scored": False}]
    assert ge.run_score({"error": None, "graders": graders}) == pytest.approx(0.75)
    assert ge.run_score({"error": "timeout", "graders": graders}) == 0.0


def test_budget_reserve_settle_and_margin():
    b = ge.Budget(5.0, min_launch=2.0)
    assert b.reserve(2.25) and b.reserve(2.25)
    assert not b.reserve(2.25)  # 0.50 left unreserved: concurrent evals can't jointly overrun
    b.settle(2.25, 0.5)
    b.settle(2.25, 0.6)
    assert b.spent == pytest.approx(1.1) and b.reserved == 0 and not b.exhausted
    b.add(2.0)
    assert b.exhausted and b.stopper(None)  # 1.9 left < min_launch 2.0


def test_budget_persists_across_resume(tmp_path):
    path = tmp_path / "spend.json"
    b = ge.Budget(10, path)
    b.add(1.5)
    b.settle(0, 2.0)
    assert ge.Budget(10, path).spent == pytest.approx(3.5)
    assert ge.Budget(3, path).exhausted


def test_budget_exhausted_raises_and_logs_without_running(tmp_path, monkeypatch):
    monkeypatch.setattr(ge.subprocess, "run", lambda *a, **k: pytest.fail("eval must not run"))
    adapter = ge.ClaudeEvalAdapter(tmp_path, FRONT, BODY, ge.Budget(1.0), 3, 3, 1, None)
    sha, plugin = adapter._plugin_copy(BODY)
    with pytest.raises(ge.BudgetExhausted):
        adapter._run_case(sha, plugin, "refuse-write")
    rows = [ge.json.loads(line) for line in (tmp_path / "evals.jsonl").read_text().splitlines()]
    assert rows == [{"candidate": sha, "case": "refuse-write", "status": "budget_exhausted", "spent_usd": 0.0}]


def test_run_case_reserves_cost_ceiling_and_settles(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        out = Path(cmd[cmd.index("--json") + 1])
        out.write_text(ge.json.dumps(agg(1, [g("refuse", True)], cost=0.4, judge=0.1)))

    monkeypatch.setattr(ge.subprocess, "run", fake_run)
    budget = ge.Budget(10.0, tmp_path / "spend.json")
    adapter = ge.ClaudeEvalAdapter(tmp_path, FRONT, BODY, budget, 3, 3, 1, None)
    sha, plugin = adapter._plugin_copy(BODY)
    score, _ = adapter._run_case(sha, plugin, "refuse-write")
    assert score == 1.0
    assert calls[0][calls[0].index("--max-cost-usd") + 1] == f"{3 * ge.PER_RUN_USD:.2f}"
    assert budget.spent == pytest.approx(0.5) and budget.reserved == 0
    row = ge.json.loads((tmp_path / "evals.jsonl").read_text().splitlines()[-1])
    assert row["status"] == "scored" and row["score"] == 1.0
    adapter._run_case(sha, plugin, "refuse-write")  # cached: no second eval, no extra spend
    assert len(calls) == 1 and budget.spent == pytest.approx(0.5)


def test_rejected_candidate_is_logged(tmp_path):
    pytest.importorskip("gepa")
    adapter = ge.ClaudeEvalAdapter(tmp_path, FRONT, BODY, ge.Budget(1), 1, 1, 1, None)
    bad = BODY.replace("NEVER make changes", "")
    adapter.evaluate(["refuse-write", "sealed-node"], {ge.COMPONENT: bad})
    rows = [ge.json.loads(line) for line in (tmp_path / "evals.jsonl").read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["status"] == "rejected" and rows[0]["candidate"] == ge.body_sha(bad)
    assert any("NEVER make changes" in p for p in rows[0]["problems"])


def test_cli_defaults():
    args = ge.build_parser().parse_args([])
    assert args.train_on_val is True and args.train_runs == 3 and args.val_runs == 3 and args.budget_usd == 40.0
    assert ge.build_parser().parse_args(["--no-train-on-val"]).train_on_val is False


def test_main_refuses_spent_run_dir(tmp_path):
    pytest.importorskip("gepa")
    (tmp_path / "spend.json").write_text('{"spent_usd": 40.0}')
    assert ge.main(["--resume", str(tmp_path), "--budget-usd", "40"]) == 1


def test_main_removes_plugin_copies_even_on_error(tmp_path, monkeypatch):
    """`claude plugin eval .` discovers plugin copies under .tmp/gepa/*/cand and tests them instead of the repo."""

    def boom(args, run_dir, *rest):
        (run_dir / "cand" / "abc" / ".claude-plugin").mkdir(parents=True)
        raise RuntimeError("crash mid-run")

    monkeypatch.setattr(ge, "optimise", boom)
    with pytest.raises(RuntimeError):
        ge.main(["--resume", str(tmp_path)])
    assert not (tmp_path / "cand").exists()


def test_task_eval_refuses_while_plugin_copies_exist():
    taskfile = (ROOT / "Taskfile.yml").read_text()
    block = taskfile.split("\n  eval:\n", 1)[1].split("\n  eval:gepa:", 1)[0]
    assert ".tmp/gepa/*/cand" in block
