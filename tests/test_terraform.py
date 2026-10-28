"""Tests for the Terraform backend.

Everything here is hermetic: no `terraform`, no `git`, no Azure. The one thing
these cannot prove is that the generated tfvars satisfy the upstream module —
only a real `terraform plan` does that, and the README says how to run one.
"""

from __future__ import annotations

import subprocess

import pytest

from aro_hcp.azure import AzCli
from aro_hcp.config import BACKENDS, ClusterConfig, ConfigError
from aro_hcp.executor import Executor
from aro_hcp.plan import build_plan
from aro_hcp.runner import TerraformCli
from aro_hcp.state import RunState
from aro_hcp.terraform import (
    TERRAFORM_PHASES,
    build_terraform_destroy_plan,
    build_terraform_plan,
    layout,
    render_tfvars,
)


def make_config(**overrides) -> ClusterConfig:
    base = dict(
        cluster_name="demo",
        location="eastus",
        resource_group="demo-rg",
        cluster_version="4.22",
        nodepool_version="4.22.1",
        subscription_id="00000000-0000-0000-0000-000000000000",
        backend="terraform",
    )
    base.update(overrides)
    return ClusterConfig(**base)


def make_executor(tmp_path, config=None, *, destroy=False, apply=False) -> Executor:
    config = config or make_config()
    build = build_terraform_destroy_plan if destroy else build_terraform_plan
    plan = build(config, tmp_path)
    return Executor(
        config, plan,
        AzCli(config.subscription_id, dry_run=not apply),
        RunState(path=tmp_path / "state.json"),
        apply=apply,
        runners={"terraform": TerraformCli(
            layout(config, tmp_path).module, config.subscription_id, dry_run=not apply
        )},
    )


# -- config -----------------------------------------------------------------


def test_backend_defaults_to_az_cli():
    assert make_config(backend="az-cli").backend == "az-cli"
    assert ClusterConfig(
        cluster_name="d", location="eastus", resource_group="rg",
        cluster_version="4.22", nodepool_version="4.22.1",
    ).backend == "az-cli"


def test_unknown_backend_is_rejected():
    problems = make_config(backend="pulumi").validate()
    assert any("backend 'pulumi'" in p for p in problems)
    assert "terraform" in BACKENDS and "az-cli" in BACKENDS


@pytest.mark.parametrize("key", ["keyvault_name", "kms_key_name", "keyvault_private_endpoint"])
def test_removed_keys_are_rejected_by_name(key):
    """A silently ignored key would leave the file describing a cluster you
    did not get, so the error has to name the key and the replacement."""
    with pytest.raises(ConfigError) as exc:
        ClusterConfig.from_dict({
            "cluster_name": "demo", "location": "eastus", "resource_group": "rg",
            "cluster_version": "4.22", "nodepool_version": "4.22.1",
            key: "whatever" if key != "keyvault_private_endpoint" else True,
        })
    assert key in str(exc.value)
    assert "no longer accepted" in str(exc.value)


def test_removed_keys_are_still_derived_internally():
    """The az plan still templates these; they just stop being inputs."""
    config = make_config(backend="az-cli", cluster_name="demo")
    assert config.keyvault_name == "demo-kv"
    assert config.kms_key_name == "etcd-kms-key"
    assert config.base_context()["KEYVAULT_NAME"] == "demo-kv"


def test_removed_keys_are_not_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("ARO_CLUSTER_NAME", "demo")
    monkeypatch.setenv("ARO_LOCATION", "eastus")
    monkeypatch.setenv("ARO_RESOURCE_GROUP", "demo-rg")
    monkeypatch.setenv("ARO_CLUSTER_VERSION", "4.22")
    monkeypatch.setenv("ARO_NODEPOOL_VERSION", "4.22.1")
    monkeypatch.setenv("ARO_KEYVAULT_NAME", "hijacked")
    assert ClusterConfig.from_env().keyvault_name == "demo-kv"


def test_private_endpoint_is_rejected_for_terraform():
    """The upstream module has no private-endpoint variable, so accepting the
    flag here would silently build a public vault."""
    config = make_config()
    config.keyvault_private_endpoint = True
    assert any("not supported by the terraform backend" in p for p in config.validate())


def test_private_endpoint_is_still_allowed_for_az_cli():
    config = make_config(backend="az-cli")
    config.keyvault_private_endpoint = True
    config.vault_visibility = "Private"
    assert config.validate() == []


def test_terraform_dir_must_look_like_a_module(tmp_path):
    empty = tmp_path / "nope"
    empty.mkdir()
    assert any("no variables.tf" in p for p in make_config(terraform_dir=str(empty)).validate())
    (empty / "variables.tf").write_text("")
    assert make_config(terraform_dir=str(empty)).validate() == []


def test_terraform_dir_is_ignored_by_the_az_backend(tmp_path):
    config = make_config(backend="az-cli", terraform_dir=str(tmp_path / "missing"))
    assert config.validate() == []


# -- tfvars -----------------------------------------------------------------


def _tfvars(config) -> dict[str, str]:
    """Parse the generated file into {name: literal}, ignoring comments."""
    out = {}
    for line in render_tfvars(config).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        out[name.strip()] = value.strip()
    return out


def test_tfvars_uses_the_modules_variable_names():
    """Upstream names several of these differently from us; a typo here is a
    `terraform plan` error about an undeclared variable."""
    values = _tfvars(make_config())
    assert values["resource_group_name"] == '"demo-rg"'
    assert values["managed_resource_group_name"] == '"demo-managed-rg"'
    assert values["subnet_name"] == '"worker-subnet"'  # ours: worker_subnet_name
    assert values["address_prefix"] == '"10.0.0.0/16"'  # ours: vnet_address_prefix
    assert values["subnet_prefix"] == '"10.0.0.0/24"'  # ours: worker_subnet_prefix
    assert values["node_pool_version"] == '"4.22.1"'
    assert "keyvault_name" not in values
    assert "kms_key_name" not in values


def test_tfvars_carries_the_channel_to_both_consumers():
    values = _tfvars(make_config(channel_group="candidate"))
    assert values["cluster_channel"] == '"candidate"'
    assert values["node_pool_channel"] == '"candidate"'


def test_tfvars_builds_the_node_pool_map():
    values = _tfvars(make_config(nodepool_name="pool-a", nodepool_replicas=3))
    assert values["node_pools"] == (
        '{ "pool-a" = { "vm_size" = "Standard_D8s_v6", "replicas" = 3 } }'
    )


def test_skip_nodepool_empties_the_node_pool_map():
    assert _tfvars(make_config(skip_nodepool=True))["node_pools"] == "{}"


def test_tfvars_pins_the_defaults_that_would_widen_scope():
    """external auth registers an Entra application, which the az path never
    does; jumpbox and pull secret are simply out of scope."""
    values = _tfvars(make_config())
    assert values["enable_external_auth"] == "false"
    assert values["enable_jumpbox"] == "false"
    assert values["pull_secret_path"] == '""'


def test_tfvars_escapes_hcl_interpolation():
    """A tag value containing ${...} would otherwise be read as a reference to
    something that does not exist."""
    body = render_tfvars(make_config(tags={"owner": "${var.whoever}"}))
    assert "$${var.whoever}" in body


def test_tfvars_renders_booleans_and_numbers_unquoted():
    values = _tfvars(make_config())
    assert values["tags"] == "{}"
    assert '"replicas" = 2' in values["node_pools"]


# -- plan shape -------------------------------------------------------------


def test_plan_phases_are_in_order():
    phases = list(dict.fromkeys(s.phase for s in build_terraform_plan(make_config())))
    assert phases == list(TERRAFORM_PHASES)


def test_every_terraform_step_uses_the_terraform_runner():
    for step in build_terraform_plan(make_config()) + build_terraform_destroy_plan(make_config()):
        assert step.runner == "terraform", step.id


def test_az_plan_steps_still_use_the_az_runner():
    for step in build_plan(make_config(backend="az-cli")):
        assert step.runner == "az", step.id


def test_only_apply_is_mutating():
    """Everything up to apply touches only the local work directory, which is
    what lets `plan` run a real terraform plan."""
    mutating = [s.id for s in build_terraform_plan(make_config()) if s.mutating]
    assert mutating == ["tf-apply"]


def test_apply_is_tagged_billable():
    apply = next(s for s in build_terraform_plan(make_config()) if s.id == "tf-apply")
    assert "billable" in apply.tags


def test_apply_does_not_use_a_saved_plan_file():
    """A resumed run must not be able to apply a diff computed against state
    that has since moved on."""
    apply = next(s for s in build_terraform_plan(make_config()) if s.id == "tf-apply")
    assert not any(a.startswith("-out") or a.endswith(".tfplan") for a in apply.args)
    assert any(a.startswith("-var-file=") for a in apply.args)


def test_rendered_argv_has_chdir_before_the_subcommand(tmp_path):
    """-chdir is a global option; terraform rejects it after the subcommand."""
    executor = make_executor(tmp_path)
    step = next(s for s in executor.plan if s.id == "tf-plan")
    argv = executor.runner_for(step).build(step.render(executor.context))
    assert argv[0] == "terraform"
    assert argv[1].startswith("-chdir=")
    assert argv[2] == "plan"


def test_action_steps_do_not_render_as_terraform_commands(tmp_path):
    executor = make_executor(tmp_path)
    step = next(s for s in executor.plan if s.id == "tf-write-tfvars")
    assert not executor.render(step).startswith("terraform")


def test_state_and_data_dir_are_per_cluster(tmp_path):
    a = layout(make_config(cluster_name="alpha"), tmp_path)
    b = layout(make_config(cluster_name="beta"), tmp_path)
    assert a.tfstate != b.tfstate and a.data_dir != b.data_dir
    # One checkout backs both, which is the point of splitting them out.
    assert a.module == b.module


def test_configured_terraform_dir_is_used_instead_of_a_checkout(tmp_path):
    mine = tmp_path / "mine"
    mine.mkdir()
    paths = layout(make_config(terraform_dir=str(mine)), tmp_path)
    assert paths.module == mine.resolve()


# -- runner -----------------------------------------------------------------


def test_subscription_is_passed_through_the_environment(tmp_path, monkeypatch):
    """The upstream provider block sets no subscription_id, and azurerm v4
    requires one, so it has to arrive as ARM_SUBSCRIPTION_ID."""
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs.get("env") or {})
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/terraform")
    cli = TerraformCli(tmp_path, "sub-123", data_dir=tmp_path / "dd")
    cli.run(["plan"], check=False)
    assert seen["ARM_SUBSCRIPTION_ID"] == "sub-123"
    assert seen["TF_DATA_DIR"] == str(tmp_path / "dd")
    assert seen["TF_IN_AUTOMATION"] == "1"


def test_runner_does_not_spawn_in_dry_run(tmp_path, monkeypatch):
    def explode(*_args, **_kwargs):
        raise AssertionError("a dry run must not spawn terraform")

    monkeypatch.setattr(subprocess, "run", explode)
    result = TerraformCli(tmp_path, dry_run=True).run(["apply"], check=False)
    assert result.ok and result.stdout == ""


def test_unknown_runner_is_an_explicit_error(tmp_path):
    from aro_hcp.plan import Step

    executor = make_executor(tmp_path)
    with pytest.raises(KeyError, match="pulumi"):
        executor.runner_for(Step(id="x", phase="p", description="d", args=[], runner="pulumi"))


# -- execution --------------------------------------------------------------


def test_dry_run_does_not_apply(tmp_path, monkeypatch):
    """The standing rule for this tool: no writes without --apply."""
    monkeypatch.setattr(
        subprocess, "run",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("spawned a process")),
    )
    executor = make_executor(tmp_path)
    step = next(s for s in executor.plan if s.id == "tf-apply")
    outcome = executor.run_step(step)
    assert outcome.status == "pending"
    assert "dry run" in outcome.message


def test_write_tfvars_action_is_idempotent(tmp_path):
    executor = make_executor(tmp_path, apply=True)
    step = next(s for s in executor.plan if s.id == "tf-write-tfvars")
    first = executor.run_step(step)
    assert "wrote" in first.stdout
    executor.state.reset(step.id)
    assert "already up to date" in executor.run_step(step).stdout
    assert layout(executor.config, tmp_path).tfvars.read_text() == render_tfvars(executor.config)


def test_a_failing_action_is_reported_as_a_step_failure(tmp_path):
    """An action raising must surface as a failed step, not a traceback."""
    from aro_hcp import terraform as tf_mod

    executor = make_executor(tmp_path, apply=True)
    step = next(s for s in executor.plan if s.id == "tf-write-tfvars")
    original = tf_mod.ACTIONS["write-tfvars"]
    tf_mod.ACTIONS["write-tfvars"] = lambda *_a: (_ for _ in ()).throw(OSError("disk full"))
    try:
        outcome = executor.run_step(step)
    finally:
        tf_mod.ACTIONS["write-tfvars"] = original
    assert outcome.status == "failed"
    assert "OSError: disk full" in outcome.message


# -- teardown ---------------------------------------------------------------


def test_destroy_removes_node_pools_from_state_before_destroying():
    """OCPBUGS-86702: the RP rejects DELETE of the last node pool, so a bare
    `terraform destroy` fails. Order here is the workaround."""
    steps = build_terraform_destroy_plan(make_config())
    ids = [s.id for s in steps]
    assert ids.index("tf-state-rm-node-pools") < ids.index("tf-destroy")


def test_destroy_refetches_the_module_and_tfvars():
    """destroy needs both to resolve what it is destroying, and a teardown
    often runs against a fresh checkout."""
    ids = [s.id for s in build_terraform_destroy_plan(make_config())]
    assert ids[:3] == ["tf-fetch-module", "tf-write-tfvars", "tf-init"]


def test_destroy_steps_are_marked_as_deletes():
    for step in build_terraform_destroy_plan(make_config()):
        if step.phase in ("nodepool-state", "destroy"):
            assert step.deletes, step.id
            assert "destructive" in step.tags, step.id


def test_dry_run_destroy_deletes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        subprocess, "run",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("spawned a process")),
    )
    executor = make_executor(tmp_path, destroy=True)
    for step in executor.plan:
        if step.phase in ("nodepool-state", "destroy"):
            assert executor.run_step(step).status == "pending"


def test_node_pool_address_pattern_matches_upstream_state_addresses():
    from aro_hcp.terraform import _NODE_POOL_ADDRESS

    assert _NODE_POOL_ADDRESS.match('module.cluster.azapi_resource.node_pool["np-1"]')
    assert _NODE_POOL_ADDRESS.match("module.cluster.azapi_resource.node_pool")
    # The cluster itself must never be dropped from state.
    assert not _NODE_POOL_ADDRESS.match("module.cluster.azapi_resource.cluster")
    assert not _NODE_POOL_ADDRESS.match("module.cluster.azapi_resource.node_pool_extra")
