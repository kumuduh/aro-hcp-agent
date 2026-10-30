from __future__ import annotations

import pytest

from aro_hcp import roles
from aro_hcp.azure import AzCli
from aro_hcp.config import ClusterConfig
from aro_hcp.executor import Executor
from aro_hcp.plan import PHASES, build_plan
from aro_hcp.state import RunState


def make_config(**overrides) -> ClusterConfig:
    base = dict(
        cluster_name="demo",
        location="eastus",
        resource_group="demo-rg",
        cluster_version="4.22",
        nodepool_version="4.22.1",
        subscription_id="00000000-0000-0000-0000-000000000000",
    )
    base.update(overrides)
    return ClusterConfig(**base)


def make_executor(tmp_path, config=None) -> Executor:
    config = config or make_config()
    az = AzCli(config.subscription_id, dry_run=True)
    state = RunState(path=tmp_path / "state.json")
    return Executor(config, build_plan(config), az, state, apply=False)


# -- config -----------------------------------------------------------------


def test_defaults_are_derived_from_cluster_name():
    config = make_config()
    assert config.nsg_name == "demo-nsg"
    assert config.vnet_name == "demo-vnet"
    assert config.managed_resource_group == "demo-managed-rg"
    assert config.keyvault_name == "demo-kv"
    assert config.validate() == []


def test_subnet_outside_vnet_is_rejected():
    problems = make_config(worker_subnet_prefix="192.168.0.0/24").validate()
    assert any("not inside" in p for p in problems)


def test_overlapping_subnets_are_rejected():
    problems = make_config(vnet_integration_subnet_prefix="10.0.0.0/25").validate()
    assert any("overlaps" in p for p in problems)


def test_nodepool_version_must_match_cluster_stream():
    problems = make_config(nodepool_version="4.23.1").validate()
    assert any("not in the 4.22 stream" in p for p in problems)


def test_managed_rg_must_differ_from_customer_rg():
    problems = make_config(managed_resource_group="demo-rg").validate()
    assert any("must differ" in p for p in problems)


def test_private_endpoint_forces_private_vault_visibility():
    config = make_config(keyvault_private_endpoint=True)
    assert config.vault_visibility == "Private"
    assert config.validate() == []


# -- plan shape --------------------------------------------------------------


def test_plan_covers_every_phase_in_order():
    phases = []
    for step in build_plan(make_config()):
        if step.phase not in phases:
            phases.append(step.phase)
    assert phases == list(PHASES)


def test_plan_creates_every_documented_identity():
    created = {
        s.id.removeprefix("identity-create-")
        for s in build_plan(make_config())
        if s.id.startswith("identity-create-")
    }
    expected = (
        {suffix for _k, suffix, _p in roles.CONTROL_PLANE_IDENTITIES}
        | {suffix for _k, suffix, _p in roles.DATA_PLANE_IDENTITIES}
        | {roles.SERVICE_IDENTITY[0], roles.KMS_IDENTITY[0]}
    )
    assert created == expected
    assert len(created) == 13


def test_plan_has_every_documented_role_assignment():
    assignments = [s for s in build_plan(make_config()) if "role-assignment" in s.tags]
    # 10 control plane + 10 service (2 scopes + 8 readers) + 6 data plane
    # + 1 service-reader-on-KMS + Crypto Officer + Crypto User
    assert len(assignments) == 29


def test_every_step_id_is_unique():
    ids = [s.id for s in build_plan(make_config())]
    assert len(ids) == len(set(ids))


def test_private_endpoint_adds_keyvault_networking_steps():
    public = {s.id for s in build_plan(make_config())}
    private = {s.id for s in build_plan(make_config(keyvault_private_endpoint=True))}
    assert private - public == {
        "keyvault-disable-public",
        "keyvault-private-endpoint",
        "keyvault-dns-zone",
        "keyvault-dns-link",
        "keyvault-dns-zone-group",
    }


def test_skip_nodepool_drops_the_nodepool_phase():
    steps = build_plan(make_config(skip_nodepool=True))
    assert not any(s.phase == "nodepool" for s in steps)


# -- rendering ---------------------------------------------------------------


def test_cluster_create_renders_all_identity_assignments(tmp_path):
    executor = make_executor(tmp_path)
    step = executor.steps_by_id()["cluster-create"]
    args = step.args
    assert args.count("--assign-control-plane-operator-identity") == 9  # 8 + kms
    assert args.count("--assign-data-plane-operator-identity") == 3
    assert "--assign-service-managed-identity" in args


def test_kms_active_key_braces_survive_substitution(tmp_path):
    executor = make_executor(tmp_path)
    executor.state.set_context("KMS_KEY_VERSION", "abc123")
    rendered = executor.steps_by_id()["cluster-create"].render(executor.context)
    assert "{name:etcd-kms-key,version:abc123}" in rendered


def test_unresolved_variables_render_as_placeholders(tmp_path):
    executor = make_executor(tmp_path)
    rendered = executor.steps_by_id()["cluster-create"].render(executor.context)
    assert "${SUBNET_ID}" in rendered


def test_subscription_is_appended_to_mutating_commands(tmp_path):
    executor = make_executor(tmp_path)
    command = executor.render(executor.steps_by_id()["resource-group"])
    assert "--subscription 00000000-0000-0000-0000-000000000000" in command
    assert "--only-show-errors" in command


#: Steps that create something with no location of its own. Everything else
#: must pass --location explicitly — see the test below.
_LOCATION_FREE_CREATES = {
    "vnet-integration-subnet",   # subnets inherit the VNet's location
    "kms-key-create",            # lives in the vault
    "keyvault-dns-zone",         # private DNS zones are global
    "keyvault-dns-link",
    "keyvault-dns-zone-group",
}


def test_every_regional_create_passes_an_explicit_location():
    """`az configure --defaults location=<x>` beats the resource group's
    location, so an omitted --location silently builds in the wrong region.
    That is how a node pool ended up rejected for 'eastus' while its cluster
    was in 'eastus2'."""
    missing = [
        step.id
        for step in build_plan(make_config(keyvault_private_endpoint=True,
                                           vault_visibility="Private"))
        if "create" in step.args
        and "role" != step.args[0]           # role assignments have no location
        and "--location" not in step.args
        and step.id not in _LOCATION_FREE_CREATES
    ]
    assert missing == []


def test_account_commands_do_not_get_a_subscription_flag():
    az = AzCli("sub-id", dry_run=True)
    assert "--subscription" not in az.build(["account", "show"])
    assert az.build(["--version"]) == ["az", "--version"]


# -- executor behaviour ------------------------------------------------------


def test_dry_run_only_spawns_read_only_probes(tmp_path, monkeypatch):
    """A dry run may look resources up, but must never create one."""
    import subprocess

    spawned: list[list[str]] = []

    def fake_run(argv, **kwargs):
        spawned.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "ResourceNotFound")

    executor = make_executor(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)

    outcome = executor.run_step(executor.steps_by_id()["resource-group"])

    assert outcome.status == "pending"
    assert "dry run" in outcome.message
    assert spawned == [[
        "az", "group", "show", "--name", "demo-rg", "--query", "id",
        "--output", "tsv", "--only-show-errors",
        "--subscription", "00000000-0000-0000-0000-000000000000",
    ]]
    assert not (tmp_path / "state.json").exists()


def test_dry_run_reports_unresolved_dependencies_without_failing(tmp_path):
    executor = make_executor(tmp_path)
    outcome = executor.run_step(executor.steps_by_id()["cluster-create"])
    assert outcome.status == "pending"
    assert "SUBNET_ID" in outcome.message


def test_completed_steps_are_skipped_on_resume(tmp_path):
    executor = make_executor(tmp_path)
    executor.state.record("resource-group", "done")
    outcome = executor.run_step(executor.steps_by_id()["resource-group"])
    assert outcome.status == "done"
    assert "already recorded" in outcome.message


def test_state_round_trips(tmp_path):
    path = tmp_path / "state.json"
    state = RunState(path=path)
    state.cluster_name = "demo"
    state.set_context("VNET_ID", "/subscriptions/x/vnet")
    state.record("vnet-create", "done", command="az network vnet create")
    state.save()

    reloaded = RunState.load(path)
    assert reloaded.get("VNET_ID") == "/subscriptions/x/vnet"
    assert reloaded.is_complete("vnet-create")
    assert reloaded.summary()["done"] == 1


def test_kms_key_version_is_the_last_segment_of_the_key_id(tmp_path):
    """`az` can only return the full key identifier; the version is its tail."""
    from aro_hcp.azure import AzResult

    executor = make_executor(tmp_path)
    executor.apply = True
    executor.persist = False
    kid = "https://kh-demo-kv.vault.azure.net/keys/etcd-kms-key/3d77adb0c7084c6b9585f6ed54b55dcc"
    executor.az.run = lambda *a, **k: AzResult(["az"], 0, kid, "")

    executor.run_step(executor.steps_by_id()["kms-key-version"])

    assert executor.context["KMS_KEY_VERSION"] == "3d77adb0c7084c6b9585f6ed54b55dcc"


def test_no_step_uses_a_nonexistent_jmespath_function():
    """JMESPath has no split()/join-style helpers; `az` rejects the query."""
    for step in build_plan(make_config()):
        for source in (step.args, step.exists or []):
            if "--query" not in source:
                continue
            query = source[source.index("--query") + 1]
            assert "split(" not in query, f"{step.id} uses split() in --query"


def test_rbac_propagation_is_retried_then_succeeds(tmp_path):
    """The Key Vault data plane lags the grant; the step must not fail for it."""
    from aro_hcp.azure import AzResult

    forbidden = AzResult(["az"], 1, "", (
        "ERROR: (Forbidden) Caller is not authorized to perform action on resource. "
        "If role assignments, deny assignments or role definitions were changed "
        "recently, please observe propagation time.\n"
        'Inner error: {"code": "ForbiddenByRbac"}'
    ))
    executor = make_executor(tmp_path)
    executor.apply = True
    executor.persist = False
    slept: list[float] = []
    executor.sleep = slept.append
    executor.state.set_context("KMS_KEY_VERSION", "")

    results = [forbidden, forbidden, AzResult(["az"], 0, "abc123", "")]
    executor.az.run = lambda *a, **k: results.pop(0)

    step = executor.steps_by_id()["kms-key-version"]
    outcome = executor.run_step(step)

    assert outcome.status == "done"
    assert executor.context["KMS_KEY_VERSION"] == "abc123"
    assert slept == [15, 30], "should back off between attempts, not spin"


def test_a_real_permissions_error_is_not_retried(tmp_path):
    """AuthorizationFailed means the operator lacks the role — report it now."""
    from aro_hcp.azure import AzResult

    executor = make_executor(tmp_path)
    executor.apply = True
    executor.persist = False
    slept: list[float] = []
    executor.sleep = slept.append

    attempts = []

    def fail(*a, **k):
        attempts.append(a)
        return AzResult(["az"], 1, "", "ERROR: (AuthorizationFailed) does not have "
                                       "authorization to perform action")

    executor.az.run = fail
    outcome = executor.run_step(executor.steps_by_id()["kms-key-version"])

    assert outcome.status == "failed"
    assert slept == []
    assert len(attempts) == 1


def test_transient_classification():
    from aro_hcp.azure import AzResult

    assert Executor._is_transient(AzResult(["az"], 1, "", "ForbiddenByRbac"))
    assert Executor._is_transient(AzResult(["az"], 1, "", "PrincipalNotFound"))
    assert not Executor._is_transient(AzResult(["az"], 1, "", "AuthorizationFailed"))
    assert not Executor._is_transient(AzResult(["az"], 1, "", "ResourceNotFound"))


def test_benign_already_exists_counts_as_skipped():
    from aro_hcp.azure import AzResult

    result = AzResult(["az"], 1, "", "RoleAssignmentExists: already there")
    assert Executor._is_benign(result)
    assert not Executor._is_benign(AzResult(["az"], 1, "", "AuthorizationFailed"))


# -- teardown ----------------------------------------------------------------


def make_destroy_executor(tmp_path, config=None) -> Executor:
    from aro_hcp.destroy import build_destroy_plan

    config = config or make_config()
    az = AzCli(config.subscription_id, dry_run=True)
    state = RunState(path=tmp_path / "destroy.json")
    return Executor(config, build_destroy_plan(config), az, state, apply=False)


def test_every_created_resource_has_a_teardown_step():
    """Anything build_plan creates must be removable, or it leaks."""
    from aro_hcp.destroy import build_destroy_plan

    created = {
        s.id.removeprefix("identity-create-")
        for s in build_plan(make_config()) if s.id.startswith("identity-create-")
    }
    deleted = {
        s.id.removeprefix("identity-delete-")
        for s in build_destroy_plan(make_config()) if s.id.startswith("identity-delete-")
    }
    assert created == deleted

    ids = {s.id for s in build_destroy_plan(make_config())}
    assert {"cluster-delete", "keyvault-delete", "keyvault-purge",
            "vnet-delete", "nsg-delete", "resource-group-delete",
            "managed-rg-delete"} <= ids


def test_teardown_never_deletes_a_node_pool():
    """OCPBUGS-86702: the RP rejects DELETE of a cluster's last node pool, and
    this tool only ever creates one — so the request could never succeed.
    Deleting the cluster cascades them instead."""
    from aro_hcp.destroy import DESTROY_PHASES, build_destroy_plan

    for config in (make_config(), make_config(skip_nodepool=True)):
        for step in build_destroy_plan(config):
            assert "nodepool" not in step.args, step.id
    assert "nodepool" not in DESTROY_PHASES


def test_identity_delete_targets_the_name_that_was_created():
    """A mismatch here silently leaves 13 identities behind."""
    from aro_hcp.destroy import build_destroy_plan

    config = make_config()
    context = config.base_context()
    created = {
        tuple(s.render(context))[3]
        for s in build_plan(config) if s.id.startswith("identity-create-")
    }
    deleted = {
        tuple(s.render(context))[3]
        for s in build_destroy_plan(config) if s.id.startswith("identity-delete-")
    }
    assert created == deleted
    assert "demo-cp-kms" in deleted


def test_teardown_order_respects_dependencies():
    from aro_hcp.destroy import build_destroy_plan

    order = [s.id for s in build_destroy_plan(make_config())]
    pos = {sid: i for i, sid in enumerate(order)}
    # The cluster still uses the etcd key while it exists.
    assert pos["cluster-delete"] < pos["keyvault-delete"]
    assert pos["keyvault-delete"] < pos["keyvault-purge"]
    # The NSG is attached to the VNet's subnet.
    assert pos["vnet-delete"] < pos["nsg-delete"]
    # Everything else first; the group is the backstop.
    assert pos["resource-group-delete"] == len(order) - 1


def test_every_teardown_step_is_marked_as_a_delete():
    from aro_hcp.destroy import build_destroy_plan

    for step in build_destroy_plan(make_config()):
        assert step.deletes, step.id
        assert "destructive" in step.tags
        assert step.exists, f"{step.id} has no probe, so it cannot be resumed"


def test_teardown_providers_are_never_unregistered():
    """Resource providers are subscription-wide; other workloads need them."""
    from aro_hcp.destroy import build_destroy_plan

    for step in build_destroy_plan(make_config()):
        assert "unregister" not in step.args


def test_absent_resource_counts_as_already_torn_down(tmp_path):
    """The exists probe inverts for deletes: nothing found means done."""
    from aro_hcp.azure import AzResult

    executor = make_destroy_executor(tmp_path)
    executor.apply = True
    executor.persist = False
    executor.az.run = lambda *a, **k: AzResult(["az"], 1, "", "ResourceNotFound")

    outcome = executor.run_step(executor.steps_by_id()["nsg-delete"])
    assert outcome.status == "skipped"
    assert outcome.message == "already gone"


def test_present_resource_is_actually_deleted(tmp_path):
    from aro_hcp.azure import AzResult

    executor = make_destroy_executor(tmp_path)
    executor.apply = True
    executor.persist = False
    calls: list[list[str]] = []
    deleted: set[str] = set()

    def run(args, **kwargs):
        calls.append(list(args))
        # The VNet is already gone (nsg-delete depends on it), and the NSG
        # disappears once its delete has run (teardown verifies that).
        if "show" in args and "nsg" in args and "nsg" not in deleted:
            return AzResult(["az"], 0, "/subscriptions/x/nsg", "")
        if "delete" in args and "nsg" in args:
            deleted.add("nsg")
        return AzResult(["az"], 0, "", "")

    executor.az.run = run
    outcome = executor.run_step(executor.steps_by_id()["nsg-delete"])
    assert outcome.status == "done"
    assert ["network", "nsg", "delete", "--name", "demo-nsg",
            "--resource-group", "demo-rg"] in calls


def test_dry_run_destroy_deletes_nothing(tmp_path, monkeypatch):
    import subprocess

    spawned: list[list[str]] = []

    def fake_run(argv, **kwargs):
        spawned.append(argv)
        return subprocess.CompletedProcess(argv, 0, "/subscriptions/x/thing", "")

    executor = make_destroy_executor(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)
    outcomes = executor.run_all()

    assert all(o.status == "pending" for o in outcomes)
    assert all("delete" not in argv and "purge" not in argv for argv in spawned)
    assert not (tmp_path / "destroy.json").exists()


def test_already_gone_errors_are_benign_only_for_deletes():
    from aro_hcp.azure import AzResult

    gone = AzResult(["az"], 1, "", "ERROR: (ResourceNotFound) could not be found")
    assert Executor._is_benign(gone, deletes=True)
    assert not Executor._is_benign(gone)
    # A delete refused for permissions is still a real failure.
    denied = AzResult(["az"], 1, "", "ERROR: (AuthorizationFailed)")
    assert not Executor._is_benign(denied, deletes=True)


def test_destroy_uses_a_separate_state_file():
    from aro_hcp.state import default_state_path

    assert default_state_path("demo", "/tmp").name == "demo.state.json"
    assert default_state_path("demo", "/tmp", suffix="destroy").name == (
        "demo.destroy.state.json"
    )


# -- preflight helpers -------------------------------------------------------


def test_vm_family_mapping():
    from aro_hcp.preflight import _vm_family

    assert _vm_family("Standard_D8s_v6") == "standardDSv6Family"
    assert _vm_family("Standard_D16s_v5") == "standardDSv5Family"
    assert _vm_family("garbage") == ""


def test_az_version_parsing():
    from aro_hcp.preflight import _parse_version

    assert _parse_version("azure-cli                         2.85.0 *") == (2, 85, 0)
    assert _parse_version("nothing here") is None


# -- agent guardrails --------------------------------------------------------


def _inspect_tool(tmp_path):
    from aro_hcp.agent import build_tools

    executor = make_executor(tmp_path)
    tools = {t.name: t for t in build_tools(executor, executor.config)}
    return tools["inspect_azure"]


@pytest.mark.parametrize("args", [
    "group create --name pwned --location eastus2",
    "aro hcp cluster delete --name demo",
    "role assignment create --role Owner --scope /subscriptions/x",
    # A write whose *arguments* contain a read-only verb must still be rejected.
    "group create --name show --location list",
    "keyvault key rotate --name show",
])
def test_inspect_azure_rejects_writes(tmp_path, args):
    assert "rejected" in _inspect_tool(tmp_path).call({"args": args})


@pytest.fixture
def no_az(monkeypatch):
    """Stub out subprocess so tests never depend on a real `az` or a login."""
    import subprocess

    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "ResourceNotFound")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


@pytest.mark.parametrize("args", [
    "group show --name demo-rg",
    "network vnet subnet show --name worker-subnet --vnet-name v -g rg",
    "vm list-usage --location eastus2",
    "aro hcp get-versions --location eastus2 --control-plane",
])
def test_inspect_azure_allows_lookups(tmp_path, no_az, args):
    assert "rejected" not in _inspect_tool(tmp_path).call({"args": args})
    assert no_az, "an allowed lookup should actually have been dispatched"


def test_agent_tools_cannot_write_in_plan_mode(tmp_path, no_az):
    import json as _json
    from aro_hcp.agent import build_tools

    executor = make_executor(tmp_path)
    tools = {t.name: t for t in build_tools(executor, executor.config)}
    result = _json.loads(tools["execute_phase"].call({"phase": "resource-group"}))
    assert all(o["status"] == "pending" for o in result["outcomes"])
    assert all("dry run" in o["message"] for o in result["outcomes"])
    # Only the read-only existence probe may have been dispatched.
    assert all("create" not in argv for argv in no_az)


def test_supported_locations_parsed_from_provider_error():
    from aro_hcp.preflight import _supported_locations

    error = (
        "ERROR: (NoRegisteredProviderFound) No registered resource provider found for "
        "location 'eastus' and API version '2026-09-01-preview'. The supported "
        "locations are 'uksouth, canadacentral, eastus2'."
    )
    assert _supported_locations(error) == ["uksouth", "canadacentral", "eastus2"]
    assert _supported_locations("something else entirely") == []


class FakeAz:
    """Stands in for AzCli, returning canned responses keyed by a marker arg."""

    def __init__(self, responses: dict[str, tuple[int, str, str]]):
        self.responses = responses

    def run(self, args, **kwargs):
        from aro_hcp.azure import AzResult

        for marker, (code, out, err) in self.responses.items():
            if marker in args:
                return AzResult(list(args), code, out, err)
        return AzResult(list(args), 1, "", "unexpected command")


def test_unsupported_region_is_a_blocking_finding():
    from aro_hcp.preflight import FAIL, check_versions

    az = FakeAz({"--control-plane": (
        1, "",
        "(NoRegisteredProviderFound) ... The supported locations are 'eastus2, uksouth'.",
    )})
    findings = check_versions(az, make_config(location="eastus"))
    assert [f.status for f in findings] == [FAIL]
    assert findings[0].check == "region"
    assert "eastus2, uksouth" in findings[0].remedy


def test_version_offered_in_a_different_channel_group_fails():
    from aro_hcp.preflight import FAIL, check_versions

    az = FakeAz({
        "--control-plane": (0, '[{"Name": "4.22", "ChannelGroup": "candidate"}]', ""),
        "--node-pools": (0, '[{"Name": "4.22.1", "ChannelGroup": "candidate"}]', ""),
    })
    findings = check_versions(az, make_config())
    version_finding = next(f for f in findings if f.check == "cluster-version")
    assert version_finding.status == FAIL
    assert "candidate" in version_finding.message


def test_available_versions_pass():
    from aro_hcp.preflight import OK, check_versions

    az = FakeAz({
        "--control-plane": (
            0, '[{"Name": "4.21", "ChannelGroup": "stable"},'
               ' {"Name": "4.22", "ChannelGroup": "stable"}]', "",
        ),
        "--node-pools": (0, '[{"Name": "4.22.1", "ChannelGroup": "stable"}]', ""),
    })
    findings = check_versions(az, make_config())
    assert all(f.status == OK for f in findings)
    assert {f.check for f in findings} == {"region", "cluster-version", "nodepool-version"}
