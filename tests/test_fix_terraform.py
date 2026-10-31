"""Regression tests for the Terraform backend fixes (D14, D16, D28-D31, N2-N5,
TF-2, TF-23, TFX1, O8, NFR-8).

Hermetic like test_terraform.py: git and terraform are replaced by scripted
fakes, and nothing reaches Azure.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
from pathlib import Path

import pytest

from aro_hcp import terraform as tf_mod
from aro_hcp.azure import AzResult
from aro_hcp.config import TERRAFORM_REF, TERRAFORM_REPO, ClusterConfig
from aro_hcp.executor import Executor
from aro_hcp.roles import FILE_STORAGE_OPERATOR_ROLE, IMAGE_REGISTRY_OPERATOR_ROLE
from aro_hcp.runner import TerraformCli
from aro_hcp.state import RunState
from aro_hcp.terraform import (
    ALWAYS,
    BOOKKEEPING,
    D31_TAG,
    RERUN_ON_CHANGES,
    _hcl,
    build_terraform_destroy_plan,
    build_terraform_plan,
    error_excerpt,
    layout,
    plan_json,
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


NO_DELETES = json.dumps({"resource_changes": [
    {"address": "module.cluster.azapi_resource.hcp_cluster", "change": {"actions": ["create"]}}]})


class Fake:
    """Scripted runner: ``rules`` maps an argv prefix to (rc, stdout, stderr)."""

    def __init__(self, rules=(), program="terraform"):
        self.rules = list(rules)
        self.calls: list[list[str]] = []
        self.program = program

    def build(self, args):
        return [self.program, *args]

    def run(self, args, *, check=True, timeout=0, force=False):
        argv = list(args)
        self.calls.append(argv)
        joined = " ".join(argv)
        for prefix, (rc, out, err) in self.rules:
            if joined.startswith(prefix):
                return AzResult(argv, rc, out, err)
        return AzResult(argv, 0, "", "")


def make_executor(tmp_path, config=None, *, tf=None, az=None, destroy=False, apply=True):
    config = config or make_config()
    build = build_terraform_destroy_plan if destroy else build_terraform_plan
    return Executor(
        config, build(config, tmp_path), az or Fake(program="az"),
        RunState(path=tmp_path / "state.json"), apply=apply,
        runners={"terraform": tf or Fake()},
    )


def step(executor, step_id):
    return next(s for s in executor.plan if s.id == step_id)


class FakeGit:
    def __init__(self, head=TERRAFORM_REF, responses=None):
        self.head = head
        self.responses = dict(responses or {})
        self.calls: list[tuple] = []

    def __call__(self, *args, cwd=None):
        self.calls.append(args)
        for key, resp in self.responses.items():
            if " ".join(args).startswith(key):
                return subprocess.CompletedProcess(args, *resp)
        if args[0] == "rev-parse":
            return subprocess.CompletedProcess(args, 0, self.head + "\n", "")
        if args[0] == "remote":
            return subprocess.CompletedProcess(args, 0, TERRAFORM_REPO + "\n", "")
        if args[0] == "clone":
            target = Path(args[-1])
            (target / ".git").mkdir(parents=True)
            (target / "terraform").mkdir()
            (target / "terraform" / "variables.tf").write_text("")
        return subprocess.CompletedProcess(args, 0, "", "")

    def subcommands(self):
        return [c[0] for c in self.calls]


def cached_checkout(path: Path) -> Path:
    (path / ".git").mkdir(parents=True)
    (path / "terraform").mkdir()
    (path / "terraform" / "variables.tf").write_text("")
    return path


# -- D14 / N3 / N4: HCL rendering ---------------------------------------------


@pytest.mark.parametrize("value,literal", [
    ("bell\b", '"bell\\u0008"'),
    ("feed\f", '"feed\\u000c"'),
    ("emoji \U0001F600", '"emoji \U0001F600"'),  # never a surrogate pair
    ("%{ if x }", '"%%{ if x }"'),
    ("${var.x}", '"$${var.x}"'),
    ('say "hi"\n\t\\', '"say \\"hi\\"\\n\\t\\\\"'),
])
def test_hcl_strings_use_only_hcl_escapes(value, literal):
    assert _hcl(value) == literal


def test_hcl_keys_are_escaped_like_values():
    assert _hcl({"${a}": "b", "%{c}": "d"}) == '{ "$${a}" = "b", "%%{c}" = "d" }'


def test_tfvars_written_as_utf8(tmp_path):
    executor = make_executor(tmp_path, make_config(tags={"team": "café \U0001F600"}))
    tf_mod.action_write_tfvars(executor, step(executor, "tf-write-tfvars"))
    raw = layout(executor.config, tmp_path).tfvars.read_bytes()
    assert "café \U0001F600".encode() in raw


# -- TF-2: provenance and checkout verification -------------------------------


def test_custom_checkout_named_in_tfvars_header(tmp_path):
    body = render_tfvars(make_config(terraform_dir=str(tmp_path)))
    assert f"# Module: custom checkout at {tmp_path.resolve()}" in body
    assert TERRAFORM_REPO not in body


def test_cached_checkout_with_shared_prefix_is_not_accepted(tmp_path, monkeypatch):
    executor = make_executor(tmp_path)
    cached_checkout(layout(executor.config, tmp_path).checkout)
    git = FakeGit(head=TERRAFORM_REF[:7] + "0" * 33)
    monkeypatch.setattr(tf_mod, "_git", git)
    result = tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    # It fetched and checked out the real ref, then caught HEAD still wrong.
    assert ("checkout", "--quiet", "--detach", TERRAFORM_REF) in git.calls
    assert not result.ok and "expected " + TERRAFORM_REF in result.stderr


def test_cached_checkout_at_exact_ref_is_reused(tmp_path, monkeypatch):
    executor = make_executor(tmp_path)
    cached_checkout(layout(executor.config, tmp_path).checkout)
    git = FakeGit()
    monkeypatch.setattr(tf_mod, "_git", git)
    result = tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert result.ok and "already at" in result.stdout
    assert "fetch" not in git.subcommands() and "checkout" not in git.subcommands()


def test_dirty_checkout_refused(tmp_path, monkeypatch):
    executor = make_executor(tmp_path)
    cached_checkout(layout(executor.config, tmp_path).checkout)
    monkeypatch.setattr(tf_mod, "_git", FakeGit(responses={
        "status": (0, " M terraform/main.tf\n?? terraform/extra.tf\n", ""),
    }))
    result = tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert not result.ok and "local changes" in result.stderr
    assert "terraform/main.tf" in result.stderr


def test_foreign_origin_refused(tmp_path, monkeypatch):
    executor = make_executor(tmp_path)
    cached_checkout(layout(executor.config, tmp_path).checkout)
    monkeypatch.setattr(tf_mod, "_git", FakeGit(responses={
        "remote get-url origin": (0, "https://example.invalid/fork.git\n", ""),
    }))
    result = tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert not result.ok and "example.invalid" in result.stderr


def test_origin_url_comparison_ignores_dot_git_and_slash():
    assert tf_mod._same_repo(TERRAFORM_REPO, TERRAFORM_REPO.removesuffix(".git") + "/")
    assert not tf_mod._same_repo(TERRAFORM_REPO, "https://github.com/someone/else.git")


def test_branch_ref_resolves_through_origin(tmp_path, monkeypatch):
    """N5: `checkout main` would use the stale clone-time local branch."""
    moved = "c" * 40
    config = make_config(terraform_ref="main")
    executor = make_executor(tmp_path, config)
    cached_checkout(layout(config, tmp_path).checkout)
    git = FakeGit(head="a" * 40, responses={
        "rev-parse --verify --quiet origin/main^{commit}": (0, moved + "\n", ""),
    })
    monkeypatch.setattr(tf_mod, "_git", git)
    tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert "fetch" in git.subcommands()
    assert ("checkout", "--quiet", "--detach", moved) in git.calls


@pytest.mark.parametrize("name", ["zz.auto.tfvars", "terraform.tfvars", "x.auto.tfvars.json"])
def test_auto_loaded_var_files_in_custom_module_refused(tmp_path, name):
    module = tmp_path / "mod"
    module.mkdir()
    (module / "variables.tf").write_text("")
    (module / name).write_text("enable_external_auth = true\n")
    executor = make_executor(tmp_path, make_config(terraform_dir=str(module)))
    result = tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert not result.ok and name in result.stderr


# -- D29: one checkout per ref --------------------------------------------------


def test_checkout_is_per_ref(tmp_path):
    a = layout(make_config(cluster_name="one", terraform_ref="a" * 40), tmp_path)
    b = layout(make_config(cluster_name="two", terraform_ref="b" * 40), tmp_path)
    pinned = layout(make_config(), tmp_path)
    assert len({a.checkout, b.checkout, pinned.checkout}) == 3
    assert pinned.checkout == tmp_path.resolve() / "terraform-src"


def test_checkout_dir_for_branch_ref_is_a_single_path_segment(tmp_path):
    paths = layout(make_config(terraform_ref="feature/x"), tmp_path)
    assert paths.checkout.parent == tmp_path.resolve()


# -- D30 / NFR-8 / O8: runner ---------------------------------------------------


def test_runner_environment_is_an_allowlist(monkeypatch):
    for key, value in {
        "TF_CLI_ARGS": "-target=x", "TF_CLI_ARGS_apply": "-target=y",
        "TF_VAR_enable_jumpbox": "true", "TF_WORKSPACE": "other", "UNRELATED": "1",
        "ARM_CLIENT_ID": "cid", "AZURE_CONFIG_DIR": "/az", "TF_LOG": "DEBUG",
        "HTTPS_PROXY": "http://proxy", "TF_PLUGIN_CACHE_DIR": "/cache",
    }.items():
        monkeypatch.setenv(key, value)
    env = TerraformCli("/m", "sub").environ()
    for dropped in ("TF_CLI_ARGS", "TF_CLI_ARGS_apply", "TF_VAR_enable_jumpbox",
                    "TF_WORKSPACE", "UNRELATED"):
        assert dropped not in env, dropped
    for kept in ("ARM_CLIENT_ID", "AZURE_CONFIG_DIR", "TF_LOG", "HTTPS_PROXY",
                 "TF_PLUGIN_CACHE_DIR", "PATH"):
        assert kept in env, kept
    assert env["ARM_SUBSCRIPTION_ID"] == "sub"


@pytest.mark.parametrize("args,expected", [
    (["plan", "-input=false"], ["plan", "-no-color", "-input=false"]),
    (["state", "list"], ["state", "list", "-no-color"]),
    (["state", "rm", "a.b"], ["state", "rm", "-no-color", "a.b"]),
    (["output", "-raw", "api_url"], ["output", "-no-color", "-raw", "api_url"]),
    (["version"], ["version"]),
    (["plan", "-no-color"], ["plan", "-no-color"]),
])
def test_runner_disables_color(args, expected):
    assert TerraformCli("/m").build(args)[2:] == expected


def test_timeout_with_bytes_partial_output_is_text(tmp_path, monkeypatch):
    def boom(argv, **_kwargs):
        raise subprocess.TimeoutExpired(argv, 5, output=b"partial \xe2\x9c\x93", stderr=b"err")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/terraform")
    result = TerraformCli(tmp_path).run(["plan"], check=False, timeout=5)
    assert result.returncode == 124
    assert result.stdout == "partial ✓"
    assert "timed out after 5s" in result.stderr and "err" in result.stderr


# -- N2 / TF-51: state list ---------------------------------------------------------


@pytest.mark.parametrize("listed,ok", [
    ((1, "", "No state file was found!\n"), True),
    ((1, "", ""), False),
    ((1, "Error: backend unreachable", ""), False),
])
def test_state_list_failure_is_not_empty_state(tmp_path, listed, ok):
    tf = Fake([("state list", listed)])
    executor = make_executor(tmp_path, tf=tf, destroy=True)
    result = tf_mod.action_state_rm_node_pools(executor, step(executor, "tf-state-rm-node-pools"))
    assert result.ok is ok
    if not ok:
        assert result.stderr


# -- D16 / TF-44 / TF-45: re-running plan and apply ------------------------------


def _complete_everything(executor):
    for s in executor.plan:
        executor.state.record(s.id, "done")


def test_non_mutating_build_steps_are_tagged_always():
    plan = build_terraform_plan(make_config())
    always = {s.id for s in plan if ALWAYS in s.tags}
    assert {"tf-fetch-module", "tf-write-tfvars", "tf-init", "tf-plan"} <= always
    assert all(not s.mutating for s in plan if ALWAYS in s.tags)
    assert "tf-apply" not in always


def test_plan_with_changes_reopens_apply(tmp_path):
    tf = Fake([("plan", (2, "Plan: 0 to add, 1 to change, 0 to destroy.", "")),
               ("show", (0, NO_DELETES, ""))])
    executor = make_executor(tmp_path, tf=tf)
    _complete_everything(executor)
    outcome = executor.run_step(step(executor, "tf-plan"), force=True)
    assert outcome.status == "done" and "1 to change" in outcome.stdout
    assert "-detailed-exitcode" in tf.calls[0]
    assert not executor.state.is_complete("tf-apply")
    assert executor.context["TF_PLAN_HAS_CHANGES"] == "yes"


def test_plan_without_changes_leaves_apply_done(tmp_path):
    executor = make_executor(tmp_path, tf=Fake([("plan", (0, "No changes.", ""))]))
    _complete_everything(executor)
    executor.run_step(step(executor, "tf-plan"), force=True)
    assert executor.state.is_complete("tf-apply")


def test_plan_error_is_a_failure(tmp_path):
    executor = make_executor(tmp_path, tf=Fake([("plan", (1, "", "Error: bad"))]))
    outcome = executor.run_step(step(executor, "tf-plan"))
    assert outcome.status == "failed"


def test_plan_in_dry_run_still_runs_terraform(tmp_path):
    tf = Fake([("plan", (2, "Plan: 42 to add", ""))])
    executor = make_executor(tmp_path, tf=tf, apply=False)
    outcome = executor.run_step(step(executor, "tf-plan"))
    assert "Plan: 42 to add" in outcome.stdout and tf.calls


def test_changed_tfvars_reopen_apply(tmp_path):
    executor = make_executor(tmp_path)
    tfvars = step(executor, "tf-write-tfvars")
    tf_mod.action_write_tfvars(executor, tfvars)
    _complete_everything(executor)
    tf_mod.action_write_tfvars(executor, tfvars)  # unchanged
    assert executor.state.is_complete("tf-apply")
    executor.config.nodepool_replicas = 3
    tf_mod.action_write_tfvars(executor, tfvars)
    assert not executor.state.is_complete("tf-apply")


def test_moved_module_reopens_apply(tmp_path, monkeypatch):
    executor = make_executor(tmp_path)
    cached_checkout(layout(executor.config, tmp_path).checkout)
    git = FakeGit()
    heads = iter(["a" * 40, TERRAFORM_REF])  # before and after the checkout

    def fake(*args, cwd=None):
        if args == ("rev-parse", "HEAD"):
            return subprocess.CompletedProcess(args, 0, next(heads) + "\n", "")
        return git(*args, cwd=cwd)

    monkeypatch.setattr(tf_mod, "_git", fake)
    _complete_everything(executor)
    result = tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert result.ok, result.stderr
    assert not executor.state.is_complete("tf-apply")


# -- D31: data-plane VNet role workaround -------------------------------------------


def test_d31_steps_sit_between_plan_and_full_apply():
    ids = [s.id for s in build_terraform_plan(make_config())]
    order = ["tf-plan", "tf-apply-network-identities", "tf-d31-vnet-id",
             "tf-d31-pid-dp-file-csi-driver", "tf-d31-pid-dp-image-registry",
             "tf-d31-role-dp-file-csi-driver-vnet", "tf-d31-role-dp-image-registry-vnet",
             "tf-apply"]
    assert [i for i in ids if i in order] == order


def test_d31_stage_one_targets_network_and_identities_only(tmp_path):
    plan = build_terraform_plan(make_config(), tmp_path)
    stage1 = next(s for s in plan if s.id == "tf-apply-network-identities")
    assert stage1.runner == "terraform" and stage1.mutating
    assert [a for a in stage1.args if a.startswith("-target=")] == [
        "-target=module.network", "-target=module.identities",
    ]
    assert f"-var-file={layout(make_config(), tmp_path).tfvars}" in stage1.args
    upstream = Path("/tmp/aro-upstream/m/terraform/main.tf")
    if upstream.is_file():
        text = upstream.read_text()
        assert 'module "network"' in text and 'module "identities"' in text


def test_d31_steps_are_labelled_and_use_az_with_probes():
    for s in build_terraform_plan(make_config()):
        if D31_TAG not in s.tags:
            continue
        assert s.description.startswith("D31 workaround:"), s.id
        if s.id.startswith("tf-d31-role-"):
            assert s.runner == "az" and s.exists is not None
            assert s.requires and "--scope" in s.args


def test_d31_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(tf_mod, "D31_ROLE_WORKAROUND", False)
    plan = build_terraform_plan(make_config())
    assert not [s for s in plan if D31_TAG in s.tags]
    assert [s.id for s in plan if s.mutating] == ["tf-apply"]


def test_d31_grants_the_two_roles_on_the_vnet(tmp_path):
    vnet = "/subscriptions/x/resourceGroups/demo-rg/providers/Microsoft.Network/virtualNetworks/demo-vnet"
    az = Fake([
        ("network vnet show", (0, vnet, "")),
        ("identity show --name demo-dp-file-csi-driver", (0, "pid-file", "")),
        ("identity show --name demo-dp-image-registry", (0, "pid-registry", "")),
        ("role assignment list", (0, "", "")),  # not granted yet
    ], program="az")
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, NO_DELETES, ""))])
    executor = make_executor(tmp_path, tf=tf, az=az)
    executor.run_all(["apply"])
    creates = [c for c in az.calls if c[:3] == ["role", "assignment", "create"]]
    granted = {(c[c.index("--assignee-object-id") + 1], c[c.index("--role") + 1],
                c[c.index("--scope") + 1]) for c in creates}
    assert granted == {("pid-file", FILE_STORAGE_OPERATOR_ROLE, vnet),
                       ("pid-registry", IMAGE_REGISTRY_OPERATOR_ROLE, vnet)}
    applies = [c for c in tf.calls if c[0] == "apply"]
    assert len(applies) == 2 and "-target=module.network" in applies[0]
    assert not any(a.startswith("-target") for a in applies[1])


def test_d31_failed_lookup_stops_before_full_apply(tmp_path):
    az = Fake([("network vnet show", (3, "", "(ResourceNotFound)"))], program="az")
    tf = Fake()
    executor = make_executor(tmp_path, tf=tf, az=az)
    outcomes = executor.run_all(["apply"])
    assert outcomes[-1].status == "failed" and outcomes[-1].step.id == "tf-d31-vnet-id"
    applies = [c for c in tf.calls if c[0] == "apply"]
    # Only the targeted stage-1 apply ran; the full apply never started.
    assert len(applies) == 1 and "-target=module.network" in applies[0]


# -- TFX1: bookkeeping steps ----------------------------------------------------------


def test_destroy_bookkeeping_steps_tagged():
    plan = build_terraform_destroy_plan(make_config())
    tagged = {s.id for s in plan if BOOKKEEPING in s.tags}
    assert tagged == {"tf-fetch-module", "tf-write-tfvars", "tf-init", "tf-state-rm-node-pools"}


def test_rerun_tag_marks_only_apply_side_steps():
    plan = build_terraform_plan(make_config())
    for s in plan:
        if RERUN_ON_CHANGES in s.tags:
            assert s.phase == "apply", s.id


# -- KEYVAULT_NAME --------------------------------------------------------------------


def test_az_derived_vault_name_is_dropped_before_outputs(tmp_path):
    module = tmp_path / "mod"
    module.mkdir()
    (module / "variables.tf").write_text("")
    executor = make_executor(tmp_path, make_config(terraform_dir=str(module)))
    # The executor no longer seeds the az-derived name on this backend; a
    # state written by an older release may still carry it.
    assert "KEYVAULT_NAME" not in executor.context
    executor.state.set_context("KEYVAULT_NAME", "demo-kv")
    tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert "KEYVAULT_NAME" not in executor.context


def test_captured_vault_name_survives(tmp_path):
    module = tmp_path / "mod"
    module.mkdir()
    (module / "variables.tf").write_text("")
    executor = make_executor(tmp_path, make_config(terraform_dir=str(module)))
    executor.state.context["KEYVAULT_NAME"] = "cust-kv-abc"
    tf_mod.action_fetch_module(executor, step(executor, "tf-fetch-module"))
    assert executor.context["KEYVAULT_NAME"] == "cust-kv-abc"


# -- CLI helpers (D28, error truncation) ------------------------------------------------


def test_plan_json_shows_a_saved_plan(tmp_path):
    shown = {"format_version": "1.2", "resource_changes": []}
    tf = Fake([("show -json", (0, json.dumps(shown), ""))])
    out = plan_json(make_config(), tf, tmp_path)
    assert out == {"kind": "terraform-plan", "plan": shown}
    plan_call, show_call = tf.calls
    out_flag = next(a for a in plan_call if a.startswith("-out="))
    assert show_call[-1] == out_flag.removeprefix("-out=")
    assert not any(c[0] == "apply" for c in tf.calls)


def test_error_excerpt_starts_at_the_terraform_error():
    noise = "\n".join(f"module.x: Still creating... [{i}m elapsed]" for i in range(200))
    text = noise + "\nError: Failed to create/update resource\n\nMissingRequiredPermissions"
    excerpt = error_excerpt(text, limit=500)
    assert excerpt.startswith("Error: Failed to create/update resource")
    assert "MissingRequiredPermissions" in excerpt


def test_error_excerpt_without_error_keeps_the_tail():
    text = "x" * 100 + "the end"
    assert error_excerpt(text, limit=20).endswith("the end")


# -- PR review: teardown tfvars satisfy the module --------------------------------


@pytest.mark.parametrize("overrides", [dict(skip_nodepool=True), dict(nodepool_replicas=1)])
def test_teardown_tfvars_always_carry_a_valid_node_pool(overrides):
    from aro_hcp.terraform import _node_pools
    config = ClusterConfig(cluster_name="demo", location="eastus2", resource_group="demo-rg",
                           cluster_version="4.22", nodepool_version="4.22.1",
                           backend="terraform", **overrides)
    pools = _node_pools(config, teardown=True)
    assert len(pools) == 1 and all(p["replicas"] >= 2 for p in pools.values())


def test_teardown_tfvars_match_the_build_for_an_ordinary_config():
    from aro_hcp.terraform import render_tfvars
    config = ClusterConfig(cluster_name="demo", location="eastus2", resource_group="demo-rg",
                           cluster_version="4.22", nodepool_version="4.22.1", backend="terraform")
    assert render_tfvars(config, teardown=True) == render_tfvars(config)


def test_destroy_plan_writes_teardown_tfvars(tmp_path):
    from aro_hcp.terraform import build_terraform_destroy_plan
    config = ClusterConfig(cluster_name="demo", location="eastus2", resource_group="demo-rg",
                           cluster_version="4.22", nodepool_version="4.22.1", backend="terraform")
    write = next(s for s in build_terraform_destroy_plan(config, tmp_path) if s.id == "tf-write-tfvars")
    assert "--teardown" in write.args


# -- open decision 2: apply re-plans, so it refuses deletions unless allowed ------


def _deleting(*actions):
    return json.dumps({"resource_changes": [
        {"address": f"module.network.res_{i}", "change": {"actions": list(a)}}
        for i, a in enumerate(actions)]})


@pytest.mark.parametrize("actions", [(["delete"],), (["delete", "create"],),
                                     (["create", "delete"],)])
def test_apply_refuses_a_plan_that_deletes_or_replaces(tmp_path, actions):
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, _deleting(*actions), ""))])
    executor = make_executor(tmp_path, tf=tf)
    outcome = executor.run_step(step(executor, "tf-plan"), force=True)
    assert outcome.status == "failed"
    assert "module.network.res_0" in outcome.stderr + outcome.message
    assert "--allow-deletes" in outcome.stderr + outcome.message


def test_allow_deletes_lets_the_apply_proceed(tmp_path):
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, _deleting(["delete"]), ""))])
    executor = make_executor(tmp_path, tf=tf)
    executor.allow_deletes = True
    assert executor.run_step(step(executor, "tf-plan"), force=True).status == "done"


def test_dry_run_plan_only_warns_about_deletes(tmp_path):
    events = []
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, _deleting(["delete"]), ""))])
    executor = make_executor(tmp_path, tf=tf, apply=False)
    executor.on_event = events.append
    assert executor.run_step(step(executor, "tf-plan"), force=True).status == "done"
    assert any("would delete or replace" in e for e in events)


def test_an_uninspectable_plan_is_refused_on_apply(tmp_path):
    tf = Fake([("plan", (2, "changes", "")), ("show", (1, "", "boom"))])
    executor = make_executor(tmp_path, tf=tf)
    assert executor.run_step(step(executor, "tf-plan"), force=True).status == "failed"


def test_updates_and_creates_pass_the_delete_guard(tmp_path):
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, _deleting(["update"], ["create"]), ""))])
    executor = make_executor(tmp_path, tf=tf)
    assert executor.run_step(step(executor, "tf-plan"), force=True).status == "done"


def test_the_inspected_plan_file_is_removed(tmp_path):
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, NO_DELETES, ""))])
    executor = make_executor(tmp_path, tf=tf)
    plan_step = step(executor, "tf-plan")
    out = next(a for a in plan_step.args if a.startswith("-out="))
    Path(out.split("=", 1)[1]).parent.mkdir(parents=True, exist_ok=True)
    Path(out.split("=", 1)[1]).write_text("secret-bearing plan")
    executor.run_step(plan_step, force=True)
    assert not Path(out.split("=", 1)[1]).exists()


# -- open decision 3: a branch or tag must not move under a cluster ---------------


OLD_SHA = "a" * 40
NEW_SHA = "b" * 40


def _fetch_with(tmp_path, monkeypatch, ref, resolves_to, recorded=None):
    checkout = tmp_path / "src"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "terraform").mkdir()
    (checkout / "terraform" / "variables.tf").write_text("")
    git = FakeGit(head=resolves_to)
    monkeypatch.setattr(tf_mod, "_git", git)
    monkeypatch.setattr(tf_mod, "_verify_existing_checkout", lambda _c: "")
    monkeypatch.setattr(tf_mod, "_resolve_ref", lambda _c, _r: (resolves_to, ""))
    config = make_config(terraform_ref=ref)
    executor = make_executor(tmp_path, config, tf=Fake())
    if recorded:
        executor.state.set_context(tf_mod.MODULE_COMMIT, recorded)
    fetch = dataclasses.replace(step(executor, "tf-fetch-module"),
                                args=["fetch-module", str(checkout)])
    return executor, tf_mod.action_fetch_module(executor, fetch)


def test_a_moved_branch_is_refused(tmp_path, monkeypatch):
    executor, result = _fetch_with(tmp_path, monkeypatch, "main", NEW_SHA, recorded=OLD_SHA)
    assert not result.ok
    assert OLD_SHA in result.stderr and NEW_SHA in result.stderr
    assert executor.state.get(tf_mod.MODULE_COMMIT) == OLD_SHA


def test_the_first_fetch_records_the_commit(tmp_path, monkeypatch):
    executor, result = _fetch_with(tmp_path, monkeypatch, "main", NEW_SHA)
    assert result.ok and executor.state.get(tf_mod.MODULE_COMMIT) == NEW_SHA


def test_a_deliberate_full_sha_change_is_accepted(tmp_path, monkeypatch):
    executor, result = _fetch_with(tmp_path, monkeypatch, NEW_SHA, NEW_SHA, recorded=OLD_SHA)
    assert result.ok and executor.state.get(tf_mod.MODULE_COMMIT) == NEW_SHA


def test_cached_checkout_at_the_pinned_sha_still_refuses_auto_tfvars(tmp_path, monkeypatch):
    checkout = tmp_path / "src"
    (checkout / "terraform").mkdir(parents=True)
    (checkout / ".git").mkdir()
    (checkout / "terraform" / "variables.tf").write_text("")
    (checkout / "terraform" / "evil.auto.tfvars").write_text('cluster_name = "x"\n')
    monkeypatch.setattr(tf_mod, "_git", FakeGit(head=TERRAFORM_REF))
    monkeypatch.setattr(tf_mod, "_verify_existing_checkout", lambda _c: "")
    executor = make_executor(tmp_path, tf=Fake())
    fetch = dataclasses.replace(step(executor, "tf-fetch-module"),
                                args=["fetch-module", str(checkout)])
    result = tf_mod.action_fetch_module(executor, fetch)
    assert not result.ok and "evil.auto.tfvars" in result.stderr


# -- review of the guard: nothing may get past a refused plan ---------------------


def _applies(tf):
    return [c for c in tf.calls if c[:1] == ["apply"]]


def test_keep_going_does_not_get_past_a_refused_plan(tmp_path):
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, _deleting(["delete"]), ""))])
    executor = make_executor(tmp_path, tf=tf, az=Fake(program="az"))
    for s in executor.plan:
        if s.phase in ("workspace", "init"):
            executor.state.record(s.id, "done")
    executor.run_all(["plan", "apply"], stop_on_error=False)
    assert not _applies(tf)


def test_phase_apply_alone_still_plans_and_guards(tmp_path):
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, _deleting(["delete"]), ""))])
    executor = make_executor(tmp_path, tf=tf, az=Fake(program="az"))
    executor.state.record("tf-plan", "done")  # from an earlier run
    executor.run_all(["apply"], stop_on_error=False)
    assert not _applies(tf)


def test_running_the_apply_phase_directly_needs_a_plan_from_this_run(tmp_path):
    # The agent's execute_phase calls run_phase, which does not refresh the
    # plan the way run_all does; an earlier run's record must not stand in.
    tf = Fake([("plan", (2, "changes", "")), ("show", (0, NO_DELETES, ""))])
    executor = make_executor(tmp_path, tf=tf, az=Fake(program="az"))
    executor.state.record("tf-plan", "done")
    executor.run_phase("apply", stop_on_error=False)
    assert not _applies(tf)
    assert "succeed in this run" in executor.state.steps["tf-apply"]["detail"]


def test_teardown_checks_out_the_recorded_commit(tmp_path, monkeypatch):
    checkout = tmp_path / "src"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "terraform").mkdir()
    (checkout / "terraform" / "variables.tf").write_text("")
    resolved = []
    monkeypatch.setattr(tf_mod, "_git", FakeGit(head=NEW_SHA))
    monkeypatch.setattr(tf_mod, "_verify_existing_checkout", lambda _c: "")

    def resolve(_checkout, ref):
        resolved.append(ref)
        return ref, ""

    monkeypatch.setattr(tf_mod, "_resolve_ref", resolve)
    config = make_config(terraform_ref="main")
    executor = make_executor(tmp_path, config, tf=Fake(), destroy=True)
    executor.state.set_context(tf_mod.MODULE_COMMIT, OLD_SHA)
    fetch = dataclasses.replace(step(executor, "tf-fetch-module"),
                                args=["fetch-module", str(checkout), "--teardown"])
    git = FakeGit(head=NEW_SHA)  # the checkout sits where the branch moved to

    def checkout_moves_head(*args, cwd=None):
        if args[0] == "checkout":
            git.head = args[-1]
        return git(*args, cwd=cwd)

    monkeypatch.setattr(tf_mod, "_git", checkout_moves_head)
    result = tf_mod.action_fetch_module(executor, fetch)
    assert result.ok and resolved == [OLD_SHA] and git.head == OLD_SHA


def test_teardown_tfvars_replace_an_invalid_node_pool_name():
    from aro_hcp.terraform import _node_pools
    config = make_config(skip_nodepool=True, nodepool_name="np_1")
    assert list(_node_pools(config, teardown=True)) == ["np-1"]
