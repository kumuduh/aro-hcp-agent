"""Regression tests for the agent fixes: inspect_azure policy, redaction,
prompt/plan consistency, tool argument caps, interlock refusals and the
AgentResult fields the CLI decides its exit code from.

No Anthropic API call is made; run_agent tests replace anthropic.Anthropic
with a scripted fake.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

anthropic = pytest.importorskip("anthropic")

from aro_hcp import agent as agent_mod  # noqa: E402
from aro_hcp import executor as executor_mod  # noqa: E402
from aro_hcp.agent import AgentResult, build_tools, redact, run_agent, system_prompt  # noqa: E402
from aro_hcp.azure import AzCli, AzResult  # noqa: E402
from aro_hcp.config import ClusterConfig  # noqa: E402
from aro_hcp.destroy import DESTROY_PHASES, build_destroy_plan  # noqa: E402
from aro_hcp.executor import Executor  # noqa: E402
from aro_hcp.plan import PHASES, build_plan  # noqa: E402
from aro_hcp.state import RunState  # noqa: E402
from aro_hcp.terraform import (  # noqa: E402
    TERRAFORM_DESTROY_PHASES,
    TERRAFORM_PHASES,
    build_terraform_destroy_plan,
    build_terraform_plan,
)

SUB = "00000000-0000-0000-0000-000000000000"
OTHER_SUB = "99999999-9999-9999-9999-999999999999"


def make_config(**overrides) -> ClusterConfig:
    base = dict(
        cluster_name="demo",
        location="eastus2",
        resource_group="demo-rg",
        cluster_version="4.22",
        nodepool_version="4.22.1",
        subscription_id=SUB,
    )
    base.update(overrides)
    return ClusterConfig(**base)


class RecordingAz(AzCli):
    """Never spawns a process; records argv and returns a canned result."""

    def __init__(self, stdout: str = "", stderr: str = ""):
        super().__init__(SUB)
        self.calls: list[list[str]] = []
        self.stdout, self.stderr = stdout, stderr

    def run(self, args, *, check=True, timeout=0, force=False):
        self.calls.append(list(args))
        return AzResult(list(args), 0, self.stdout, self.stderr)


def make_tools(tmp_path, *, plan=None, config=None, az=None, apply=False, runners=None):
    config = config or make_config()
    az = az or RecordingAz()
    executor = Executor(config, plan if plan is not None else build_plan(config), az,
                        RunState(path=tmp_path / "s.json"), apply=apply, runners=runners)
    return {t.name: t for t in build_tools(executor, config)}, az, executor


def inspect(tmp_path, args, **kwargs):
    tools, az, _ = make_tools(tmp_path, **kwargs)
    return tools["inspect_azure"].call({"args": args}), az


def prompt_phases(text: str) -> list[str]:
    m = re.search(r"Phases, in order[^\n]*:\n((?:  \S[^\n]*\n)+)", text)
    assert m, "no phase list in prompt"
    return [line.split()[0] for line in m.group(1).splitlines()]


# -- inspect_azure: secret-bearing commands ----------------------------------


@pytest.mark.parametrize("args", [
    "keyvault secret show --vault-name v --name s",
    "keyvault secret list --vault-name v",
    "keyvault certificate show --vault-name v --name c",
    "keyvault certificate download --vault-name v --name c --file x",
    "keyvault key download --vault-name v --name k --file x",
    "storage account keys list --account-name s",
    "storage account show-connection-string --name s",
    "cosmosdb keys list --name c -g demo-rg",
    "acr credential show --name r",
    "ad sp credential list --id x",
    "account get-access-token",
    "aks get-credentials --name a -g demo-rg",
    "webapp config appsettings list --name w -g demo-rg",
    "webapp deployment list-publishing-profiles --name w -g demo-rg",
    "webapp list-connection-strings --name w -g demo-rg",
    "containerapp secret list --name c -g demo-rg",
    "aro hcp cluster list-admin-credentials --name demo -g demo-rg",
    "identity federated-credential list --identity-name i -g demo-rg",
])
def test_inspect_rejects_secret_families(tmp_path, args):
    result, az = inspect(tmp_path, args)
    assert result.startswith("rejected")
    assert az.calls == []


@pytest.mark.parametrize("args", [
    "group show --name demo-rg",
    "az group list",
    "network vnet subnet show --name worker-subnet --vnet-name v -g demo-rg",
    "network nsg show --name demo-nsg -g demo-rg",
    "identity list -g demo-rg",
    f"role assignment list --scope /subscriptions/{SUB}/resourceGroups/demo-rg",
    "role definition list --name Owner",
    "keyvault show --name demo-kv",
    "keyvault list-deleted",
    "keyvault key show --vault-name demo-kv --name etcd-kms-key",
    "aro hcp cluster show --name demo -g demo-rg",
    "aro hcp cluster nodepool list --cluster-name demo -g demo-rg",
    "aro hcp get-versions --location eastus2 --control-plane",
    "vm list-usage --location eastus2",
    "vm list-skus --location eastus2 --size Standard_D8s_v6",
    "provider show --namespace Microsoft.RedHatOpenShift",
    "account show",
    "monitor activity-log list -g demo-rg --offset 1h",
    f"resource show --ids /subscriptions/{SUB}/resourceGroups/demo-rg",
    f"group list --subscription {SUB}",
])
def test_inspect_allows_aro_hcp_metadata_reads(tmp_path, args):
    result, az = inspect(tmp_path, args)
    assert not result.startswith("rejected"), result
    assert len(az.calls) == 1


@pytest.mark.parametrize("args", [
    "group create --name show",
    "aro hcp cluster delete --name demo -g demo-rg",
    "role assignment create --role Owner --scope /subscriptions/x",
    "keyvault purge --name demo-kv",
    "rest --method get --url https://management.azure.com/x",
    "storage blob list --account-name s --container-name c",
])
def test_inspect_rejects_anything_off_the_allowlist(tmp_path, args):
    result, az = inspect(tmp_path, args)
    assert result.startswith("rejected")
    assert az.calls == []


# -- inspect_azure: flags, @file, scope, size ----------------------------------


@pytest.mark.parametrize("args", [
    "group list --debug",
    "group list --verbose",
    "group show --name demo-rg --output-file /tmp/x",
    "group show --name demo-rg --output-file=/tmp/x",
    "group show --name @/home/op/.azure/msal_token_cache.json",
    "group show --name=@~/.azure/azureProfile.json",
])
def test_inspect_rejects_logging_and_file_flags(tmp_path, args):
    result, az = inspect(tmp_path, args)
    assert result.startswith("rejected")
    assert az.calls == []


def test_inspect_allows_only_show_errors(tmp_path):
    result, az = inspect(tmp_path, "group list --only-show-errors")
    assert not result.startswith("rejected")


@pytest.mark.parametrize("args", [
    f"group list --subscription {OTHER_SUB}",
    f"group list --subscription={OTHER_SUB}",
    f"resource show --ids /subscriptions/{OTHER_SUB}/resourceGroups/x",
    f"role assignment list --scope /SUBSCRIPTIONS/{OTHER_SUB}",
])
def test_inspect_pins_subscription(tmp_path, args):
    result, az = inspect(tmp_path, args)
    assert result.startswith("rejected")
    assert az.calls == []


def test_inspect_caps_input_without_echoing_it(tmp_path):
    result, az = inspect(tmp_path, "group show --name " + "A" * 100_000)
    assert result.startswith("rejected")
    assert len(result) < 300
    assert az.calls == []


def test_unknown_phase_and_step_are_clipped(tmp_path):
    tools, az, _ = make_tools(tmp_path)
    huge = "B" * 100_000
    for result in (tools["execute_phase"].call({"phase": huge}),
                   tools["show_plan"].call({"phase": huge}),
                   tools["execute_step"].call({"step_id": huge})):
        assert result.startswith("unknown")
        assert len(result) < 1000
    assert az.calls == []


# -- redaction -------------------------------------------------------------------


def test_redact_json_keys_and_text_patterns():
    payload = {
        "id": f"/subscriptions/{SUB}/resourceGroups/demo-rg/providers/"
              "Microsoft.Network/virtualNetworks/demo-vnet/subnets/worker-subnet",
        "name": "demo-cluster-control-plane-cluster-api-azure-identity",
        "primaryKey": "SENTINEL-PRIMARY==",
        "connectionString": "DefaultEndpointsProtocol=https;AccountKey=SENTINEL-AK==",
        "accessToken": "eyJ0eXAiOiJKV1QiSENTINEL",
        "properties": {
            "clientSecret": "SENTINEL-CS",
            "activeKey": {"name": "etcd-kms-key", "vaultName": "demo-kv"},
            "notes": "sig=SENTINEL-SIG&se=2026 Bearer eyJhbGciOiJSUzI1NiJ9.SENTINELpayload.x",
            "blob": "Q2xhdWRlU0VOVElORUwxMjM0NTY3ODkwYWJjZGVmZ2hpams=",
        },
    }
    out = redact(json.dumps(payload))
    assert "SENTINEL" not in out
    parsed = json.loads(out)
    assert parsed["id"] == payload["id"]
    assert parsed["name"] == payload["name"]
    assert parsed["properties"]["activeKey"] == {"name": "etcd-kms-key", "vaultName": "demo-kv"}


def test_redact_plain_text():
    out = redact("ERROR: AccountKey=SENTINEL123== rejected; token eyJ0eXAiOiJKV1QiSENTINEL")
    assert "SENTINEL" not in out
    assert "ERROR" in out


def test_inspect_output_is_redacted(tmp_path):
    az = RecordingAz(stdout=json.dumps({"password": "SENTINEL-PW"}),
                     stderr="Bearer eyJ0eXAiOiJKV1QiSENTINEL")
    result, _ = inspect(tmp_path, "group show --name demo-rg", az=az)
    assert "SENTINEL" not in result


# -- prompts and tool descriptions follow the plan -------------------------------


def test_prompt_phase_lists_match_code():
    assert prompt_phases(agent_mod.SYSTEM_PROMPT) == list(PHASES)
    assert prompt_phases(agent_mod.DESTROY_SYSTEM_PROMPT) == list(DESTROY_PHASES)
    assert prompt_phases(agent_mod.TERRAFORM_NOTE) == list(TERRAFORM_PHASES)
    assert prompt_phases(agent_mod.TERRAFORM_DESTROY_NOTE) == list(TERRAFORM_DESTROY_PHASES)


def test_every_phase_has_a_prompt_note():
    for kind, phases in (("build", PHASES), ("destroy", DESTROY_PHASES),
                         ("tf-build", TERRAFORM_PHASES), ("tf-destroy", TERRAFORM_DESTROY_PHASES)):
        assert set(phases) <= set(agent_mod._PHASE_NOTES[kind]), kind


def test_destroy_prompt_forbids_a_nodepool_delete():
    text = agent_mod.DESTROY_SYSTEM_PROMPT
    assert "OCPBUGS-86702" in text
    assert "Never add, offer or suggest a node-pool" in text
    assert "nodepool" not in prompt_phases(text)


def test_terraform_destroy_prompt_names_its_phases():
    text = system_prompt(destroy=True, backend="terraform")
    assert text.endswith(agent_mod.TERRAFORM_DESTROY_NOTE)
    for phase in TERRAFORM_DESTROY_PHASES:
        assert phase in agent_mod.TERRAFORM_DESTROY_NOTE
    for phase in TERRAFORM_DESTROY_PHASES:
        assert phase in agent_mod.TERRAFORM_NOTE


def test_runtime_prompt_uses_the_loaded_plan():
    config = make_config(skip_nodepool=True)
    phases = tuple(dict.fromkeys(s.phase for s in build_plan(config)))
    assert "nodepool" not in prompt_phases(system_prompt(phases=phases))


def _description(tool) -> str:
    return json.dumps(tool.to_dict())


def test_tool_descriptions_follow_destroy_plan(tmp_path):
    tools, *_ = make_tools(tmp_path, plan=build_destroy_plan(make_config()))
    for name in ("execute_phase", "show_plan"):
        text = _description(tools[name])
        assert "providers" not in text and "nodepool" not in text
        for phase in DESTROY_PHASES:
            assert phase in text


def test_tool_descriptions_follow_terraform_plans(tmp_path):
    config = make_config(backend="terraform")
    for plan, phases in ((build_terraform_plan(config, tmp_path), TERRAFORM_PHASES),
                         (build_terraform_destroy_plan(config, tmp_path), TERRAFORM_DESTROY_PHASES)):
        tools, *_ = make_tools(tmp_path, plan=plan, config=config,
                               runners={"terraform": RecordingAz()})
        text = _description(tools["execute_phase"])
        for phase in phases:
            assert phase in text
        assert "role-assignments" not in text


# -- interlock refusals -----------------------------------------------------------


class _Blocked(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def test_step_blocked_becomes_a_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(executor_mod, "StepBlocked", _Blocked, raising=False)
    tools, az, executor = make_tools(tmp_path)

    def blocked(*a, **k):
        raise _Blocked("preflight has not passed")

    monkeypatch.setattr(executor, "run_step", blocked)
    monkeypatch.setattr(executor, "run_phase", blocked)
    step = tools["execute_step"].call({"step_id": "resource-group"})
    phase = tools["execute_phase"].call({"phase": "resource-group"})
    for result in (step, phase):
        assert result.startswith("refused:")
        assert "preflight has not passed" in result


def test_other_executor_errors_still_propagate(tmp_path, monkeypatch):
    monkeypatch.setattr(executor_mod, "StepBlocked", _Blocked, raising=False)
    tools, az, executor = make_tools(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(executor, "run_step", boom)
    with pytest.raises(RuntimeError):
        tools["execute_step"].call({"step_id": "resource-group"})


# -- AgentResult and run_agent ------------------------------------------------------


@pytest.mark.parametrize("kwargs,ok", [
    (dict(stop_reason="end_turn"), True),
    (dict(stop_reason="end_turn", pending=["x"]), True),           # plan mode
    (dict(stop_reason="end_turn", pending=["x"], apply=True), False),
    (dict(stop_reason="end_turn", apply=True), True),
    (dict(stop_reason="refusal"), False),
    (dict(stop_reason="max_tokens"), False),
    (dict(stop_reason="tool_use"), False),
    (dict(stop_reason=None), False),
    (dict(stop_reason="end_turn", hit_turn_limit=True), False),
])
def test_agent_result_ok(kwargs, ok):
    assert AgentResult(text="", turns=1, **kwargs).ok is ok


class FakeClient:
    def __init__(self, messages):
        self.messages = messages
        self.kwargs: dict = {}
        self.beta = SimpleNamespace(messages=SimpleNamespace(tool_runner=self._runner))

    def _runner(self, **kwargs):
        self.kwargs = kwargs
        return iter(self.messages)


def _msg(stop_reason, text="", explanation=None):
    content = [SimpleNamespace(type="text", text=text)] if text else []
    details = SimpleNamespace(explanation=explanation) if explanation else None
    return SimpleNamespace(content=content, stop_reason=stop_reason, stop_details=details)


@pytest.fixture
def fake_client(monkeypatch):
    holder = {}

    def install(messages):
        holder["client"] = FakeClient(messages)
        monkeypatch.setattr(anthropic, "Anthropic", lambda *a, **k: holder["client"])
        return holder["client"]

    return install


def _executor(tmp_path, apply=False, destroy=False):
    config = make_config()
    plan = build_destroy_plan(config) if destroy else build_plan(config)
    return Executor(config, plan, RecordingAz(), RunState(path=tmp_path / "s.json"),
                    apply=apply), config


@pytest.mark.parametrize("value", [0, -1])
def test_max_turns_below_one_raises_before_any_call(tmp_path, monkeypatch, value):
    def no_client(*a, **k):
        raise AssertionError("client constructed")

    monkeypatch.setattr(anthropic, "Anthropic", no_client)
    executor, config = _executor(tmp_path)
    with pytest.raises(ValueError):
        run_agent(executor, config, "x", max_turns=value)


def test_model_env_override(tmp_path, monkeypatch, fake_client):
    client = fake_client([_msg("end_turn", "ok")])
    monkeypatch.setenv("ARO_HCP_MODEL", "claude-from-env")
    executor, config = _executor(tmp_path)
    run_agent(executor, config, "x")
    assert client.kwargs["model"] == "claude-from-env"
    run_agent(executor, config, "x", model="claude-explicit")
    assert client.kwargs["model"] == "claude-explicit"
    monkeypatch.delenv("ARO_HCP_MODEL")
    run_agent(executor, config, "x")
    assert client.kwargs["model"] == agent_mod.MODEL


def test_destroy_run_gets_destroy_phases(tmp_path, fake_client):
    client = fake_client([_msg("end_turn", "ok")])
    executor, config = _executor(tmp_path, destroy=True)
    run_agent(executor, config, "x", destroy=True)
    assert prompt_phases(client.kwargs["system"]) == list(DESTROY_PHASES)


def test_refusal_explanation_reaches_on_text_and_text(tmp_path, fake_client):
    fake_client([_msg("refusal", explanation="EXPLAINED")])
    executor, config = _executor(tmp_path)
    seen = []
    result = run_agent(executor, config, "x", on_text=seen.append)
    assert result.stop_reason == "refusal" and not result.ok
    assert "EXPLAINED" in result.text
    assert any("EXPLAINED" in s for s in seen)


def test_turn_limit_and_pending_reported(tmp_path, fake_client):
    fake_client([_msg("tool_use")] * 3 + [_msg("end_turn", "done")])
    executor, config = _executor(tmp_path, apply=True)
    result = run_agent(executor, config, "x", max_turns=2)
    assert result.hit_turn_limit and result.turns == 2 and not result.ok
    assert result.pending == [s.id for s in executor.plan]


def test_finishing_on_the_last_allowed_turn_is_not_a_limit_hit(tmp_path, fake_client):
    fake_client([_msg("end_turn", "done")])
    executor, config = _executor(tmp_path)
    result = run_agent(executor, config, "x", max_turns=1)
    assert not result.hit_turn_limit and result.ok


def test_apply_with_pending_steps_is_not_ok(tmp_path, fake_client):
    fake_client([_msg("end_turn", "Everything is done.")])
    executor, config = _executor(tmp_path, apply=True)
    assert not run_agent(executor, config, "x").ok


def test_empty_run_is_not_ok(tmp_path, fake_client):
    fake_client([])
    executor, config = _executor(tmp_path)
    result = run_agent(executor, config, "x")
    assert result.stop_reason is None and not result.ok
