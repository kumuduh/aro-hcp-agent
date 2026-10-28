"""Tests for the CLI's confirmation gates.

The safety model is: nothing is written without `--apply` *and* a human
saying yes. These check the "saying yes" half — in particular that it is
asked exactly once, since a prompt per phase is what trained people to
answer on autopilot.
"""

from __future__ import annotations

import builtins

import pytest

from aro_hcp.azure import AzCli
from aro_hcp.cli import _confirm_apply, build_parser
from aro_hcp.config import ClusterConfig
from aro_hcp.executor import Executor
from aro_hcp.plan import build_plan
from aro_hcp.state import RunState


def make_config(**overrides) -> ClusterConfig:
    base = dict(
        cluster_name="demo",
        location="eastus2",
        resource_group="demo-rg",
        cluster_version="4.22",
        nodepool_version="4.22.1",
        subscription_id="00000000-0000-0000-0000-000000000000",
    )
    base.update(overrides)
    return ClusterConfig(**base)


def make_executor(tmp_path) -> Executor:
    config = make_config()
    return Executor(
        config, build_plan(config),
        AzCli(config.subscription_id, dry_run=True),
        RunState(path=tmp_path / "state.json"),
        apply=True,
    )


@pytest.fixture
def answers(monkeypatch):
    """Drive input() from a list, recording how many times it was asked."""
    asked: list[str] = []

    def fake_input(prompt=""):
        asked.append(prompt)
        return queue.pop(0) if queue else ""

    queue: list[str] = []
    monkeypatch.setattr(builtins, "input", fake_input)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    return type("Answers", (), {"queue": queue, "asked": asked})()


def test_apply_asks_exactly_once_for_the_whole_run(tmp_path, answers, capsys):
    """Eight phases, one prompt. A prompt per phase is how people learn to
    hit `y` without reading it."""
    answers.queue.append("y")
    assert _confirm_apply(make_executor(tmp_path), None) is True
    assert len(answers.asked) == 1


def test_declining_once_stops_everything(tmp_path, answers):
    answers.queue.append("n")
    assert _confirm_apply(make_executor(tmp_path), None) is False


def test_anything_but_yes_declines(tmp_path, answers):
    for reply in ("", "no", "Y E S", "yolo"):
        answers.queue.clear()
        answers.queue.append(reply)
        assert _confirm_apply(make_executor(tmp_path), None) is (reply == "y")


def test_confirmation_names_the_cluster_and_what_it_costs(tmp_path, answers, capsys):
    """One prompt has to carry what the per-phase prompts used to."""
    answers.queue.append("y")
    _confirm_apply(make_executor(tmp_path), None)
    out = capsys.readouterr().out
    assert "demo" in out and "eastus2" in out and "demo-rg" in out
    assert "billable" in out
    assert "Create the ARO HCP cluster (15-20 minutes)" in out
    assert "only confirmation" in out


def test_nothing_pending_asks_nothing(tmp_path, answers):
    """Re-running a finished apply must not prompt about an empty run."""
    executor = make_executor(tmp_path)
    for step in executor.plan:
        executor.state.record(step.id, "done")
    assert _confirm_apply(executor, None) is True
    assert answers.asked == []


def test_a_phase_scoped_run_only_counts_that_phase(tmp_path, answers, capsys):
    answers.queue.append("y")
    _confirm_apply(make_executor(tmp_path), ["network"])
    out = capsys.readouterr().out
    assert "network:" in out
    assert "identities:" not in out
    # The cluster is not in scope, so it must not be advertised as billable.
    assert "Create the ARO HCP cluster" not in out


def test_non_tty_declines_rather_than_guessing(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        builtins, "input",
        lambda *_a: pytest.fail("prompted without a TTY"),
    )
    assert _confirm_apply(make_executor(tmp_path), None) is False


def test_per_phase_confirmation_is_opt_in():
    args = build_parser().parse_args(["apply", "-c", "cluster.yaml"])
    assert args.confirm_each_phase is False
    assert args.yes is False
