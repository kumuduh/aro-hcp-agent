"""Regression tests for the executor, state, teardown and CLI fixes.

Each test names the QA finding it pins down (D#/O#/N#). The fake Azure below
is stateful: creates make resources exist, deletes remove them, so the tests
exercise the same probe-then-act logic a live run does.
"""

from __future__ import annotations

import json
import sys

import pytest

from aro_hcp import cli
from aro_hcp import state as state_mod
from aro_hcp.azure import AzCli, AzResult
from aro_hcp.config import ClusterConfig
from aro_hcp.destroy import build_destroy_plan
from aro_hcp.executor import Executor, StepBlocked
from aro_hcp.plan import build_plan
from aro_hcp.state import RunState, StateError, destroy_state_path

SUB = "00000000-0000-0000-0000-000000000000"


def make_config(**overrides) -> ClusterConfig:
    base = dict(
        cluster_name="demo", location="eastus2", resource_group="demo-rg",
        cluster_version="4.22", nodepool_version="4.22.1", subscription_id=SUB,
    )
    base.update(overrides)
    return ClusterConfig(**base)


class FakeAzure(AzCli):
    """A tiny model of Azure keyed by the resource name in the argv."""

    def __init__(self, existing: dict[str, str] | None = None, errors: dict[str, tuple] | None = None):
        super().__init__(SUB)
        #: name -> probe output (an id, or a provisioning state)
        self.existing = dict(existing or {})
        #: substring -> (rc, stdout, stderr) override for any matching call
        self.errors = dict(errors or {})
        self.calls: list[list[str]] = []

    @staticmethod
    def _key(argv: list[str]) -> str:
        """``<command group>:<name>``, e.g. ``aro hcp cluster:demo``."""
        path = []
        for token in argv:
            if token.startswith("-"):
                break
            path.append(token)
        group = " ".join(path[:-1])  # drop the verb
        args = list(argv)
        name = args[args.index("--name") + 1] if "--name" in args else ""
        if "--cluster-name" in args:
            name = args[args.index("--cluster-name") + 1] + "/" + name
        return f"{group}:{name}"

    def run(self, args, *, check=True, timeout=0, force=False):
        argv = list(args)
        self.calls.append(argv)
        joined = " ".join(argv)
        for needle, response in self.errors.items():
            if needle in joined:
                return AzResult(argv, *response)
        verbs = [a for a in argv if not a.startswith("-")]
        key = self._key(argv)
        if "show" in verbs or "list" in verbs or "list-deleted" in verbs:
            if key in self.existing:
                return AzResult(argv, 0, self.existing[key], "")
            return AzResult(argv, 3, "", "(ResourceNotFound) not found")
        if "create" in verbs:
            self.existing[key] = "Succeeded" if "aro" in argv else f"/subscriptions/{SUB}/{key}"
            return AzResult(argv, 0, self.existing[key], "")
        if "delete" in verbs or "purge" in verbs:
            self.existing.pop(key, None)
            return AzResult(argv, 0, "", "")
        return AzResult(argv, 0, "x", "")


def executor(tmp_path, plan=None, az=None, apply=True, config=None, state_name="s.json", **kw):
    config = config or make_config()
    az = az or FakeAzure()
    run_state = RunState.load(tmp_path / state_name)
    return Executor(config, plan or build_plan(config), az, run_state, apply=apply,
                    retry_delays=(), sleep=lambda _s: None, poll_interval=0, **kw)


def step(ex, step_id):
    return ex.steps_by_id()[step_id]


# -- D2: provisioning state ------------------------------------------------------


@pytest.mark.parametrize("state", ["Failed", "Canceled", "Deleting"])
def test_D2_terminal_cluster_state_is_a_failure_not_done(tmp_path, state):
    az = FakeAzure({"aro hcp cluster:demo": state})
    ex = executor(tmp_path, az=az)
    ex.context.update({k: "v" for k in step(ex, "cluster-create").requires})
    outcome = ex.run_step(step(ex, "cluster-create"))
    assert outcome.status == "failed"
    assert state in outcome.message


def test_D2_in_progress_cluster_halts_the_run_without_claiming_success(tmp_path):
    az = FakeAzure({"aro hcp cluster:demo": "Provisioning"})
    ex = executor(tmp_path, az=az)
    ex.context.update({k: "v" for k in step(ex, "cluster-create").requires})
    outcome = ex.run_step(step(ex, "cluster-create"))
    assert outcome.status == "pending" and ex.halted
    assert not ex.state.is_complete("cluster-create")


def test_D2_node_pool_is_blocked_until_the_cluster_is_ready(tmp_path):
    az = FakeAzure({"aro hcp cluster:demo": "Provisioning"})
    ex = executor(tmp_path, az=az)
    with pytest.raises(StepBlocked):
        ex.run_step(step(ex, "nodepool-create"))
    assert not any("nodepool" in c and "create" in c for c in az.calls)


# -- D3: benign "already exists" -------------------------------------------------


def test_D3_already_exists_for_another_resource_is_a_failure(tmp_path):
    az = FakeAzure(errors={"keyvault create": (1, "", "(VaultAlreadyExists) The vault name 'demo-kv' is already in use")})
    ex = executor(tmp_path, az=az)
    outcome = ex.run_step(step(ex, "keyvault-create"))
    assert outcome.status == "failed"


def test_D3_role_assignment_exists_is_trusted_only_when_the_probe_agrees(tmp_path):
    ex = executor(tmp_path, az=FakeAzure(errors={
        "role assignment create": (1, "", "(RoleAssignmentExists) The role assignment already exists."),
        "role assignment list": (0, "", ""),
    }))
    first = next(s for s in ex.plan if s.phase == "role-assignments")
    ex.context.update({k: "v" for k in first.requires})
    outcome = ex.run_step(first)
    # The step has a probe, and the probe finds no assignment: the conflict
    # was about something else, so it is not "already done".
    assert outcome.status == "failed"


# -- D15 / O4: probe errors are unknown ------------------------------------------


@pytest.mark.parametrize("err", [
    (1, "", "(AuthorizationFailed) The client does not have authorization"),
    (1, "", "(TooManyRequests) throttled"),
    (124, "", "timed out after 300s"),
])
def test_D15_a_failed_delete_probe_is_not_already_gone(tmp_path, err):
    az = FakeAzure(errors={"nsg show": err})
    ex = executor(tmp_path, plan=build_destroy_plan(make_config()), az=az)
    ex.state.record("vnet-delete", "done")
    outcome = ex.run_step(step(ex, "nsg-delete"))
    assert outcome.status == "failed"
    assert not any("delete" in c for c in az.calls)


@pytest.mark.parametrize("err", [
    (1, "", "(AuthorizationFailed) no"),
    (124, "", "timed out"),
])
def test_O4_a_failed_create_probe_does_not_trigger_a_create(tmp_path, err):
    az = FakeAzure(errors={"network nsg show": err})
    ex = executor(tmp_path, az=az)
    outcome = ex.run_step(step(ex, "nsg-create"))
    assert outcome.status == "failed"
    assert not any(c[:3] == ["network", "nsg", "create"] for c in az.calls)


def test_N1_exhausted_retry_on_delete_is_not_reported_gone(tmp_path):
    az = FakeAzure({"identity:demo-cp-kms": "/id"},
                   errors={"identity delete": (1, "", "Principal does not exist in the directory")})
    ex = executor(tmp_path, plan=build_destroy_plan(make_config()), az=az)
    ex.state.record("cluster-delete", "done")
    outcome = ex.run_step(step(ex, "identity-delete-cp-kms"))
    assert outcome.status == "failed"


# -- D1: second lifecycle --------------------------------------------------------


def test_D1_recorded_deletes_are_reverified_and_redone(tmp_path):
    config = make_config()
    plan = build_destroy_plan(config)
    stale = RunState(path=tmp_path / "d.json")
    for s in plan:
        stale.record(s.id, "done")
    stale.save()
    az = FakeAzure({"aro hcp cluster:demo": "/cluster"})
    ex = executor(tmp_path, plan=plan, az=az, state_name="d.json")
    ex.run_all()
    assert any(c[:4] == ["aro", "hcp", "cluster", "delete"] for c in az.calls)


def test_D1_cli_destroy_removes_both_state_files(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   f"cluster_version: '4.22'\nnodepool_version: '4.22.1'\nsubscription_id: {SUB}\n")
    az = FakeAzure()
    monkeypatch.setattr(cli, "AzCli", lambda *a, **k: az)
    build = tmp_path / "st" / "demo.state.json"
    build.parent.mkdir()
    build.write_text(json.dumps({"version": 1, "cluster_name": "demo", "steps": {}}))
    rc = cli.main(["destroy", "-c", str(cfg), "--state-dir", str(tmp_path / "st"), "--apply", "-y", "-q"])
    assert rc == 0
    assert not build.exists()
    assert not (tmp_path / "st" / "demo.destroy.state.json").exists()


# -- D26: teardown order is enforced per step -------------------------------------


@pytest.mark.parametrize("step_id", ["keyvault-delete", "keyvault-purge", "identity-delete-cp-kms",
                                     "vnet-delete", "resource-group-delete"])
def test_D26_nothing_after_the_cluster_runs_while_it_exists(tmp_path, step_id):
    az = FakeAzure({"aro hcp cluster:demo": "/cluster", "keyvault:demo-kv": "/kv"})
    ex = executor(tmp_path, plan=build_destroy_plan(make_config()), az=az)
    with pytest.raises(StepBlocked):
        ex.run_step(step(ex, step_id))


def test_D26_keep_going_past_a_failed_cluster_delete_purges_nothing(tmp_path):
    az = FakeAzure({"aro hcp cluster:demo": "/cluster", "keyvault:demo-kv": "/kv"},
                   errors={"aro hcp cluster delete": (1, "", "InternalServerError")})
    ex = executor(tmp_path, plan=build_destroy_plan(make_config()), az=az)
    ex.run_all(stop_on_error=False)
    assert not any(c[:2] == ["keyvault", "purge"] or c[:2] == ["keyvault", "delete"] for c in az.calls)


# -- D7: private endpoint teardown ------------------------------------------------


def test_D7_private_endpoint_and_dns_are_deleted_before_the_vnet():
    ids = [s.id for s in build_destroy_plan(make_config())]
    for pre in ("keyvault-private-endpoint-delete", "keyvault-dns-link-delete"):
        assert ids.index(pre) < ids.index("vnet-delete")


# -- N5 / EXE-19 / EXE-24 ---------------------------------------------------------


def test_N5_capture_returning_nothing_is_a_failure(tmp_path):
    az = FakeAzure(errors={"network nsg show": (0, "", "")})
    ex = executor(tmp_path, az=az)
    outcome = ex.run_step(step(ex, "nsg-id"))
    assert outcome.status == "failed" and not ex.state.is_complete("nsg-id")


def test_EXE19_unknown_runner_is_a_step_failure(tmp_path):
    from dataclasses import replace

    ex = executor(tmp_path)
    odd = replace(step(ex, "nsg-create"), runner="nope")
    assert ex.run_step(odd).status == "failed"


def test_EXE24_existing_subnet_with_other_prefix_is_a_conflict(tmp_path):
    az = FakeAzure(errors={"vnet subnet show": (0, "10.0.9.0/24 none", "")})
    ex = executor(tmp_path, az=az)
    outcome = ex.run_step(step(ex, "vnet-integration-subnet"))
    assert outcome.status == "failed" and "different settings" in outcome.message


# -- O9: a declined phase ends the run -------------------------------------------


def test_O9_declining_a_phase_stops_everything_after_it(tmp_path):
    asked = []
    az = FakeAzure()
    ex = executor(tmp_path, az=az, confirm=lambda phase, steps: asked.append(phase) or False)
    ex.run_all()
    assert asked == ["providers"]
    assert not any("create" in c for c in az.calls)


# -- D25 / STA-15 / O1: state binding and locking ---------------------------------


def test_D25_state_for_another_cluster_is_refused(tmp_path):
    other = RunState(path=tmp_path / "s.json", cluster_name="other")
    other.record("x", "done")
    other.save()
    with pytest.raises(StateError):
        executor(tmp_path)


def test_STA15_changed_settings_after_progress_are_refused(tmp_path):
    first = executor(tmp_path, fingerprint={"location": "eastus2"})
    first.state.record("resource-group", "done")
    first.state.save()
    with pytest.raises(StateError):
        executor(tmp_path, config=make_config(location="uksouth"), fingerprint={"location": "uksouth"})


def test_O1_second_concurrent_run_fails_fast(tmp_path):
    a = RunState(path=tmp_path / "s.json")
    b = RunState(path=tmp_path / "s.json")
    with a.lock():
        with pytest.raises(state_mod.StateLocked):
            with b.lock():
                pass


def test_corrupt_state_is_a_clean_usage_error(tmp_path, capsys):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   f"cluster_version: '4.22'\nnodepool_version: '4.22.1'\nsubscription_id: {SUB}\n")
    (tmp_path / "bad.json").write_text("{not json")
    rc = cli.main(["status", "-c", str(cfg), "--state", str(tmp_path / "bad.json")])
    assert rc == cli.EXIT_USAGE
    assert "unreadable" in capsys.readouterr().err


def test_custom_state_pairs_with_its_own_teardown_file(tmp_path):
    assert destroy_state_path(tmp_path / "x.json").name == "x.json.destroy"
    assert destroy_state_path(tmp_path / "x.tf.state.json").name == "x.tf.destroy.state.json"


def test_secrets_are_redacted_and_state_is_private(tmp_path):
    s = RunState(path=tmp_path / "d" / "s.json")
    s.record("x", "failed", detail="AccountKey=abc123; password: hunter2")
    s.save()
    text = s.path.read_text()
    assert "abc123" not in text and "hunter2" not in text
    assert oct(s.path.stat().st_mode)[-3:] == "600"


# -- D10 / CLI-14: phase-scoped runs ----------------------------------------------


def test_D10_phase_scoped_pending_counts_only_that_phase(tmp_path):
    ex = executor(tmp_path)
    ex.run_all(["providers"])
    assert ex.pending(["providers"]) == []
    assert ex.pending()  # the rest of the plan is legitimately pending


def test_CLI14_phase_from_the_other_backend_is_rejected(tmp_path, capsys, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   f"cluster_version: '4.22'\nnodepool_version: '4.22.1'\nsubscription_id: {SUB}\n")
    monkeypatch.setattr(cli, "AzCli", lambda *a, **k: FakeAzure())
    rc = cli.main(["plan", "-c", str(cfg), "--phase", "init", "--state-dir", str(tmp_path)])
    assert rc == cli.EXIT_USAGE and "not a az-cli" in capsys.readouterr().err


# -- D24: mixed backends ------------------------------------------------------------


def test_D24_unreadable_other_backend_state_fails_closed(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   f"cluster_version: '4.22'\nnodepool_version: '4.22.1'\nsubscription_id: {SUB}\n"
                   "backend: terraform\n")
    (tmp_path / "demo.state.json").write_text("garbage")
    monkeypatch.setattr(cli, "AzCli", lambda *a, **k: FakeAzure())
    monkeypatch.setattr(cli, "run_preflight", lambda *a, **k: pytest.fail("must refuse first"))
    rc = cli.main(["apply", "-c", str(cfg), "--state-dir", str(tmp_path), "-y"])
    assert rc == cli.EXIT_USAGE


def test_D24_az_apply_over_a_terraform_cluster_is_refused(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   f"cluster_version: '4.22'\nnodepool_version: '4.22.1'\nsubscription_id: {SUB}\n")
    tf = RunState(path=tmp_path / "demo.tf.state.json", cluster_name="demo")
    tf.record("tf-apply", "done")
    tf.save()
    monkeypatch.setattr(cli, "AzCli", lambda *a, **k: FakeAzure())
    rc = cli.main(["apply", "-c", str(cfg), "--state-dir", str(tmp_path), "-y"])
    assert rc == cli.EXIT_USAGE


# -- D9: agent runs pass the deterministic gates ----------------------------------


def test_D9_agent_destroy_apply_without_tty_declines_before_the_model(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   f"cluster_version: '4.22'\nnodepool_version: '4.22.1'\nsubscription_id: {SUB}\n")
    monkeypatch.setattr(cli, "AzCli", lambda *a, **k: FakeAzure())
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    import aro_hcp.agent as agent

    monkeypatch.setattr(agent, "run_agent", lambda *a, **k: pytest.fail("model must not start"))
    rc = cli.main(["agent", "--destroy", "--apply", "-c", str(cfg), "--state-dir", str(tmp_path)])
    assert rc == cli.EXIT_DECLINED


# -- D20: tags on the az-cli backend --------------------------------------------------


def test_D20_az_creates_carry_config_tags():
    plan = build_plan(make_config(tags={"env": "qa"}))
    creates = [s for s in plan if s.args[-2:] == ["--tags", "env=qa"] or "env=qa" in s.args]
    names = {s.id for s in creates}
    assert {"resource-group", "nsg-create", "vnet-create", "keyvault-create", "cluster-create"} <= names
