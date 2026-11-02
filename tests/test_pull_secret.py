"""The pull_secret_path input: config, plans, tfvars, the apply action, preflight."""

from __future__ import annotations

import base64
import json
import re
import subprocess
from pathlib import Path

import pytest

from aro_hcp import pullsecret
from aro_hcp.azure import AzCli, AzResult
from aro_hcp.config import ClusterConfig
from aro_hcp.executor import Executor
from aro_hcp.plan import build_plan
from aro_hcp.preflight import FAIL, OK, WARN, check_pull_secret
from aro_hcp.state import RunState
from aro_hcp.terraform import build_terraform_destroy_plan, build_terraform_plan, render_tfvars

SUB = "00000000-0000-0000-0000-000000000000"
SECRET = {"auths": {"registry.redhat.io": {"auth": "c2VjcmV0LXRva2VuLXZhbHVl", "email": "a@b.c"}}}


@pytest.fixture
def secret_file(tmp_path):
    path = tmp_path / "pull-secret.json"
    path.write_text(json.dumps(SECRET))
    return path


def make_config(**overrides) -> ClusterConfig:
    base = dict(cluster_name="demo", location="eastus2", resource_group="demo-rg",
                cluster_version="4.22", nodepool_version="4.22.1", subscription_id=SUB)
    base.update(overrides)
    return ClusterConfig(**base)


# -- config -----------------------------------------------------------------------


def test_relative_path_is_relative_to_the_config_file(tmp_path, secret_file, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   "cluster_version: '4.22'\nnodepool_version: '4.22.1'\n"
                   "pull_secret_path: pull-secret.json\n")
    monkeypatch.chdir(Path("/"))
    config = ClusterConfig.load(cfg)
    assert config.pull_secret_path == str(secret_file.resolve())
    assert not config.validate()


def test_home_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert make_config(pull_secret_path="~/ps.json").pull_secret_path == str(tmp_path / "ps.json")


@pytest.mark.parametrize("content, problem", [
    (None, "cannot read"),
    ("not json", "not valid JSON"),
    (json.dumps({"auth": {}}), '"auths"'),
    (json.dumps({"auths": {}}), '"auths"'),
])
def test_unusable_file_is_a_config_problem(tmp_path, content, problem):
    path = tmp_path / "ps.json"
    if content is not None:
        path.write_text(content)
    problems = make_config(pull_secret_path=str(path)).validate()
    assert any(problem in p for p in problems)


def test_a_missing_file_never_blocks_a_teardown(tmp_path):
    config = make_config(pull_secret_path=str(tmp_path / "gone.json"))
    assert config.validate() and not config.validate(teardown=True)


def test_problems_never_quote_the_secret(tmp_path):
    path = tmp_path / "ps.json"
    path.write_text('{"auths": "c2VjcmV0LXRva2VuLXZhbHVl"}')
    assert not any("c2VjcmV0" in p for p in make_config(pull_secret_path=str(path)).validate())


# -- plans and tfvars -------------------------------------------------------------


def test_no_step_without_a_pull_secret():
    assert pullsecret.STEP_ID not in {s.id for s in build_plan(make_config())}
    assert pullsecret.STEP_ID not in {s.id for s in build_terraform_plan(make_config())}


@pytest.mark.parametrize("skip, after", [(False, ("cluster-create", "nodepool-create")),
                                         (True, ("cluster-create",))])
def test_az_cli_step_runs_last_after_the_cluster(secret_file, skip, after):
    plan = build_plan(make_config(pull_secret_path=str(secret_file), skip_nodepool=skip))
    assert plan[-1].id == pullsecret.STEP_ID and plan[-1].after == after
    assert plan[-1].mutating


def test_terraform_step_runs_after_the_apply(secret_file, tmp_path):
    plan = build_terraform_plan(make_config(backend="terraform",
                                            pull_secret_path=str(secret_file)), tmp_path)
    assert plan[-1].id == pullsecret.STEP_ID and plan[-1].after == ("tf-apply",)
    assert pullsecret.STEP_ID not in {s.id for s in build_terraform_destroy_plan(
        make_config(backend="terraform", pull_secret_path=str(secret_file)), tmp_path)}


def test_tfvars_hand_the_path_to_the_module_but_not_on_teardown(secret_file):
    config = make_config(backend="terraform", pull_secret_path=str(secret_file))
    assert re.search(rf'^pull_secret_path\s+= "{re.escape(str(secret_file))}"$',
                     render_tfvars(config), re.M)
    assert re.search(r'^pull_secret_path\s+= ""$', render_tfvars(config, teardown=True), re.M)
    assert "c2VjcmV0" not in render_tfvars(config)


# -- the apply action -------------------------------------------------------------


class CredentialAz(AzCli):
    """request-credential writes a kubeconfig to --file, like the real one."""

    def __init__(self, rc=0):
        super().__init__(SUB)
        self.rc = rc
        self.kubeconfig: Path | None = None

    def run(self, args, *, check=True, timeout=0, force=False):
        argv = list(args)
        if argv[:4] == ["aro", "hcp", "cluster", "request-credential"]:
            if self.rc == 0:
                self.kubeconfig = Path(argv[argv.index("--file") + 1])
                self.kubeconfig.write_text("apiVersion: v1\nkind: Config\n")
                return AzResult(argv, 0, "", "")
            return AzResult(argv, self.rc, "", "(Forbidden) no")
        return AzResult(argv, 0, "", "")


class Kubectl:
    def __init__(self, *responses):
        self.responses = list(responses) or [(0, "secret/additional-pull-secret created\n", "")]
        self.calls: list[tuple[list[str], str]] = []

    def __call__(self, argv, *, input=None, **kw):
        self.calls.append((list(argv), input))
        rc, out, err = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        return subprocess.CompletedProcess(argv, rc, out, err)


def executor_for(tmp_path, config, az):
    plan = build_plan(config)
    run_state = RunState(path=tmp_path / "s.json")
    for step in plan[:-1]:
        run_state.record(step.id, "done")
    return Executor(config, plan, az, run_state, apply=True,
                    retry_delays=(1, 2), sleep=lambda _s: None, poll_interval=0)


@pytest.fixture
def kubectl(monkeypatch):
    fake = Kubectl()
    monkeypatch.setattr(pullsecret.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(pullsecret.subprocess, "run", fake)
    return fake


def test_secret_goes_to_the_cluster_on_stdin_only(tmp_path, secret_file, kubectl):
    az = CredentialAz()
    config = make_config(pull_secret_path=str(secret_file))
    ex = executor_for(tmp_path, config, az)
    outcome = ex.run_step(ex.steps_by_id()[pullsecret.STEP_ID])
    assert outcome.status == "done"

    argv, stdin = kubectl.calls[0]
    assert argv[0] == "/usr/bin/oc" and argv[-3:] == ["apply", "-f", "-"]
    body = json.loads(stdin)
    assert body["metadata"] == {"name": "additional-pull-secret", "namespace": "kube-system"}
    assert body["type"] == "kubernetes.io/dockerconfigjson"
    assert base64.b64decode(body["data"][".dockerconfigjson"]) == secret_file.read_bytes()
    assert not any("c2VjcmV0" in a for a in argv)
    # The admin kubeconfig does not outlive the step, and only a digest is kept.
    assert az.kubeconfig is not None and not az.kubeconfig.parent.exists()
    assert ex.state.get(pullsecret.DIGEST_KEY) == pullsecret.digest(secret_file.read_bytes())
    assert "c2VjcmV0" not in json.dumps(ex.state.steps) + json.dumps(ex.state.context)


def test_a_fresh_credential_is_retried_until_accepted(tmp_path, secret_file, kubectl):
    kubectl.responses = [(1, "", "error: You must be logged in to the server (Unauthorized)"),
                         (0, "secret/additional-pull-secret configured\n", "")]
    ex = executor_for(tmp_path, make_config(pull_secret_path=str(secret_file)), CredentialAz())
    assert ex.run_step(ex.steps_by_id()[pullsecret.STEP_ID]).status == "done"
    assert len(kubectl.calls) == 2


def test_a_real_failure_is_reported_with_the_secret_redacted(tmp_path, secret_file, kubectl):
    leaked = base64.b64encode(secret_file.read_bytes()).decode()
    kubectl.responses = [(1, "", f'The Secret is invalid: data: Invalid value: "{leaked}"')]
    ex = executor_for(tmp_path, make_config(pull_secret_path=str(secret_file)), CredentialAz())
    outcome = ex.run_step(ex.steps_by_id()[pullsecret.STEP_ID])
    assert outcome.status == "failed" and len(kubectl.calls) == 1
    assert leaked not in outcome.stderr + outcome.message + json.dumps(ex.state.steps)


def test_no_credential_no_kubectl_call(tmp_path, secret_file, kubectl):
    ex = executor_for(tmp_path, make_config(pull_secret_path=str(secret_file)), CredentialAz(rc=1))
    assert ex.run_step(ex.steps_by_id()[pullsecret.STEP_ID]).status == "failed"
    assert not kubectl.calls


def test_without_oc_or_kubectl_the_step_fails(tmp_path, secret_file, monkeypatch):
    monkeypatch.setattr(pullsecret.shutil, "which", lambda name: None)
    ex = executor_for(tmp_path, make_config(pull_secret_path=str(secret_file)), CredentialAz())
    outcome = ex.run_step(ex.steps_by_id()[pullsecret.STEP_ID])
    assert outcome.status == "failed" and "kubectl" in outcome.stderr + outcome.message


# -- rotation ---------------------------------------------------------------------


def test_a_changed_file_reopens_the_step(tmp_path, secret_file):
    config = make_config(pull_secret_path=str(secret_file))
    state = RunState(path=tmp_path / "s.json")
    state.record(pullsecret.STEP_ID, "done")
    state.set_context(pullsecret.DIGEST_KEY, pullsecret.digest(secret_file.read_bytes()))
    pullsecret.invalidate_if_changed(config, state)
    assert state.is_complete(pullsecret.STEP_ID)

    secret_file.write_text(json.dumps({"auths": {"quay.io": {"auth": "eA=="}}}))
    pullsecret.invalidate_if_changed(config, state)
    assert not state.is_complete(pullsecret.STEP_ID)


# -- preflight --------------------------------------------------------------------


def test_preflight_fails_without_a_kube_client(secret_file, monkeypatch):
    monkeypatch.setattr(pullsecret.shutil, "which", lambda name: None)
    findings = check_pull_secret(make_config(pull_secret_path=str(secret_file)))
    assert [f.status for f in findings] == [FAIL]


def test_preflight_warns_about_a_private_api(secret_file, monkeypatch):
    monkeypatch.setattr(pullsecret.shutil, "which", lambda name: f"/usr/bin/{name}")
    findings = check_pull_secret(make_config(pull_secret_path=str(secret_file),
                                             api_visibility="Private"))
    assert [f.status for f in findings] == [OK, WARN]


def test_status_works_after_the_secret_file_is_deleted(tmp_path, secret_file, monkeypatch):
    from aro_hcp import cli
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"cluster_name: demo\nlocation: eastus2\nresource_group: demo-rg\n"
                   f"cluster_version: '4.22'\nnodepool_version: '4.22.1'\n"
                   f"subscription_id: {SUB}\npull_secret_path: pull-secret.json\n")
    secret_file.unlink()
    monkeypatch.setattr(cli, "AzCli", lambda *a, **k: CredentialAz())
    assert cli.main(["status", "-c", str(cfg), "--state-dir", str(tmp_path / "st")]) == cli.EXIT_OK
    assert cli.main(["plan", "-c", str(cfg), "--state-dir", str(tmp_path / "st")]) == cli.EXIT_USAGE
