"""The Terraform backend: same cluster.yaml, a different way to build it.

Red Hat publishes a Terraform module for ARO HCP
(https://cloud.redhat.com/experts/aro/terraform-hcp/, implemented in
github.com/rh-mobb/validated-pattern-aro-hcp). That repository has no LICENSE
file, so the module is cloned at a pinned ref rather than vendored here, and
this module's job is to translate ``ClusterConfig`` into its tfvars and drive
it through the same ``Executor`` the az backend uses.

The two backends are **not interchangeable for one cluster**: upstream names
the Key Vault ``cust-kv-<random>`` and its identities ``<cluster>-service``
where the az path uses ``<cluster>-kv`` and ``<cluster>-service-managed-identity``.
Pointing this at a cluster built by the az backend creates a second,
overlapping set of resources.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .azure import DEFAULT_TIMEOUT, LONG_TIMEOUT, AzResult
from .config import TERRAFORM_REPO, ClusterConfig
from .plan import Step
from .runner import TerraformCli

TERRAFORM_PHASES = ("workspace", "init", "plan", "apply", "outputs")

TERRAFORM_DESTROY_PHASES = ("workspace", "init", "nodepool-state", "destroy")

#: Terraform state addresses for node pools. OCPBUGS-86702: the RP rejects
#: DELETE of the last node pool, so they are dropped from state before destroy
#: and left for ARM to cascade when the cluster goes.
_NODE_POOL_ADDRESS = re.compile(r'^module\.cluster\.azapi_resource\.node_pool(\[".+"\])?$')

#: Upstream defaults this backend overrides, with the reason, so the generated
#: file explains itself to whoever reads it next.
_PINNED_DEFAULTS = {
    "enable_external_auth": (
        False,
        "upstream defaults true, which registers an Entra application; the "
        "az-cli backend never asks for directory permissions",
    ),
    "enable_jumpbox": (False, "out of scope for this tool"),
    "pull_secret_path": ("", "no pull secret is managed here"),
}


# -- layout -----------------------------------------------------------------


@dataclass(frozen=True)
class Layout:
    """Where this backend keeps its files, all outside the module checkout."""

    root: Path
    checkout: Path
    module: Path
    tfvars: Path
    tfstate: Path
    data_dir: Path


def layout(config: ClusterConfig, directory: str | Path | None = None) -> Layout:
    root = Path(directory) if directory else Path.cwd() / ".aro-hcp"
    root = root.resolve()
    checkout = root / "terraform-src"
    # The module root is the repo's terraform/ subdirectory.
    module = Path(config.terraform_dir).resolve() if config.terraform_dir else checkout / "terraform"
    return Layout(
        root=root,
        checkout=checkout,
        module=module,
        tfvars=root / f"{config.cluster_name}.tfvars",
        tfstate=root / f"{config.cluster_name}.tfstate",
        # Per-cluster, so one checkout can back several clusters without their
        # provider caches and state pointers colliding.
        data_dir=root / f"{config.cluster_name}.terraform",
    )


def make_runner(
    config: ClusterConfig,
    *,
    directory: str | Path | None = None,
    dry_run: bool = False,
) -> TerraformCli:
    paths = layout(config, directory)
    return TerraformCli(
        paths.module,
        config.subscription_id,
        dry_run=dry_run,
        data_dir=paths.data_dir,
    )


# -- tfvars -----------------------------------------------------------------


def _hcl(value) -> str:
    """Render a Python value as an HCL literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        # JSON string escaping is HCL-compatible, except that HCL would read
        # ${...} inside a quoted string as an interpolation.
        return json.dumps(value).replace("${", "$${")
    if isinstance(value, dict):
        if not value:
            return "{}"
        body = ", ".join(f"{json.dumps(k)} = {_hcl(v)}" for k, v in value.items())
        return "{ " + body + " }"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_hcl(v) for v in value) + "]"
    raise TypeError(f"cannot render {type(value).__name__} as HCL")


def _node_pools(config: ClusterConfig) -> dict:
    if config.skip_nodepool:
        return {}
    return {
        config.nodepool_name: {
            "vm_size": config.nodepool_vm_size,
            "replicas": config.nodepool_replicas,
        }
    }


def render_tfvars(config: ClusterConfig) -> str:
    """Translate the cluster config into the upstream module's variables.

    Every name on the right is a variable in the module's variables.tf; where
    the names differ from ours it is because upstream chose a different one
    (``subnet_name`` for the worker subnet, ``address_prefix`` for the VNet).
    """
    values: list[tuple[str, object]] = [
        ("cluster_name", config.cluster_name),
        ("location", config.location),
        ("resource_group_name", config.resource_group),
        ("managed_resource_group_name", config.managed_resource_group),
        ("vnet_name", config.vnet_name),
        ("nsg_name", config.nsg_name),
        ("subnet_name", config.worker_subnet_name),
        ("vnet_integration_subnet_name", config.vnet_integration_subnet_name),
        ("address_prefix", config.vnet_address_prefix),
        ("subnet_prefix", config.worker_subnet_prefix),
        ("vnet_integration_subnet_prefix", config.vnet_integration_subnet_prefix),
        ("cluster_version", config.cluster_version),
        ("cluster_channel", config.channel_group),
        ("node_pool_version", config.nodepool_version),
        ("node_pool_channel", config.channel_group),
        ("api_visibility", config.api_visibility),
        ("ingress_visibility", config.ingress_visibility),
        ("vault_visibility", config.vault_visibility),
        ("tags", dict(config.tags)),
        ("node_pools", _node_pools(config)),
    ]

    lines = [
        "# Generated by aro-hcp from the cluster config. Do not edit:",
        "# `aro-hcp apply --backend terraform` overwrites this file.",
        f"# Module: {TERRAFORM_REPO} @ {config.terraform_ref}",
        "",
    ]
    width = max(len(name) for name, _ in values)
    for name, value in values:
        lines.append(f"{name.ljust(width)} = {_hcl(value)}")
    lines.append("")
    lines.append("# Pinned by aro-hcp so the terraform backend stays in scope")
    lines.append("# with the az-cli one.")
    width = max(len(name) for name in _PINNED_DEFAULTS)
    for name, (value, why) in _PINNED_DEFAULTS.items():
        lines.append(f"# {why}")
        lines.append(f"{name.ljust(width)} = {_hcl(value)}")
    if config.skip_nodepool:
        lines.insert(4, "# skip_nodepool is set: node_pools is empty.")
    return "\n".join(lines) + "\n"


# -- actions ----------------------------------------------------------------
#
# Steps that are not subprocess invocations. The executor dispatches to these
# by ``Step.action``; each returns an AzResult so it reports like any other
# step.


def _ok(argv: list[str], message: str) -> AzResult:
    return AzResult(argv, 0, message, "")


def _fail(argv: list[str], message: str) -> AzResult:
    return AzResult(argv, 1, "", message)


def _git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, check=False, timeout=600,
    )


def action_fetch_module(executor, step: Step) -> AzResult:
    """Clone the upstream Terraform module at the pinned ref.

    The target comes from the step's own arguments, not from recomputing the
    layout: the plan was rendered against one work directory and the action
    must not be able to pick a different one.
    """
    config = executor.config
    argv = step.render(executor.context)
    checkout = Path(argv[1])
    module = Path(config.terraform_dir) if config.terraform_dir else checkout / "terraform"

    if config.terraform_dir:
        if not (module / "variables.tf").is_file():
            return _fail(argv, f"terraform_dir {module} has no variables.tf")
        return _ok(argv, f"using the configured checkout at {module}")

    if shutil.which("git") is None:
        return _fail(argv, "`git` is not on PATH; it is needed to fetch the module")

    if (checkout / ".git").is_dir():
        head = _git("rev-parse", "HEAD", cwd=checkout)
        if head.returncode == 0 and head.stdout.strip().startswith(config.terraform_ref[:7]):
            return _ok(argv, f"{checkout} is already at {config.terraform_ref[:12]}")
        fetched = _git("fetch", "--quiet", "origin", cwd=checkout)
        if fetched.returncode != 0:
            return _fail(argv, f"git fetch failed: {fetched.stderr.strip()}")
    else:
        checkout.parent.mkdir(parents=True, exist_ok=True)
        # blob:none keeps the clone small; the pinned ref still has to be
        # reachable, so this is not a --depth 1 clone.
        cloned = _git(
            "clone", "--quiet", "--filter=blob:none", TERRAFORM_REPO, str(checkout),
        )
        if cloned.returncode != 0:
            return _fail(argv, f"git clone failed: {cloned.stderr.strip()}")

    out = _git("checkout", "--quiet", "--detach", config.terraform_ref, cwd=checkout)
    if out.returncode != 0:
        return _fail(argv, f"git checkout {config.terraform_ref} failed: {out.stderr.strip()}")
    if not (module / "variables.tf").is_file():
        return _fail(
            argv,
            f"{module} has no variables.tf; the upstream layout may have "
            f"changed at {config.terraform_ref}",
        )
    return _ok(argv, f"checked out {config.terraform_ref[:12]} in {checkout}")


def action_write_tfvars(executor, step: Step) -> AzResult:
    """Render the config into the module's tfvars file."""
    argv = step.render(executor.context)
    target = Path(argv[1])
    body = render_tfvars(executor.config)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_text() == body:
        return _ok(argv, f"{target} is already up to date")
    target.write_text(body)
    return _ok(argv, f"wrote {target} ({len(body.splitlines())} lines)")


def action_state_rm_node_pools(executor, step: Step) -> AzResult:
    """Drop node pools from Terraform state before destroying.

    OCPBUGS-86702: the resource provider rejects DELETE of a cluster's last
    node pool, which is the first thing `terraform destroy` would try. Removing
    them from state leaves ARM to cascade them when the cluster goes. This
    mirrors the upstream scripts/destroy.sh workaround; it is reimplemented
    rather than shelled out to because that script hardcodes the upstream
    repo's clusters/<name>/ layout, which this tool does not use.
    """
    runner = executor.runner_for(step)
    argv = step.render(executor.context)

    listed = runner.run(["state", "list"], check=False, force=True, timeout=step.timeout)
    if not listed.ok:
        # No state yet is not a failure: there is nothing to remove.
        if "No state file" in listed.stderr or not listed.stderr.strip():
            return _ok(argv, "no terraform state; nothing to remove")
        return _fail(argv, listed.stderr.strip())

    addresses = [a for a in listed.text.splitlines() if _NODE_POOL_ADDRESS.match(a.strip())]
    if not addresses:
        return _ok(argv, "no node pools in state; nothing to remove")

    removed = []
    for address in addresses:
        out = runner.run(["state", "rm", address.strip()], check=False, timeout=step.timeout)
        if not out.ok:
            return _fail(argv, f"state rm {address} failed: {out.stderr.strip()}")
        removed.append(address.strip())
    return _ok(argv, "removed from state (OCPBUGS-86702): " + ", ".join(removed))


ACTIONS = {
    "fetch-module": action_fetch_module,
    "write-tfvars": action_write_tfvars,
    "state-rm-node-pools": action_state_rm_node_pools,
}


# -- plans ------------------------------------------------------------------


def _workspace_steps(paths: Layout) -> list[Step]:
    """Fetch the module and write the tfvars.

    Both are marked non-mutating: they touch only the local work directory, so
    they run during a dry run too. That is what lets `plan --backend terraform`
    show a real `terraform plan` diff instead of a rendered command.
    """
    return [
        Step(
            id="tf-fetch-module",
            phase="workspace",
            description="Fetch the upstream Terraform module at the pinned ref",
            args=["fetch-module", str(paths.checkout)],
            action="fetch-module",
            runner="terraform",
            mutating=False,
            timeout=900,
        ),
        Step(
            id="tf-write-tfvars",
            phase="workspace",
            description="Write the cluster config as Terraform variables",
            args=["write-tfvars", str(paths.tfvars)],
            action="write-tfvars",
            runner="terraform",
            mutating=False,
        ),
    ]


def _init_step(paths: Layout) -> Step:
    return Step(
        id="tf-init",
        phase="init",
        description="Initialise Terraform and download providers",
        args=[
            "init", "-reconfigure", "-input=false",
            f"-backend-config=path={paths.tfstate}",
        ],
        runner="terraform",
        mutating=False,
        timeout=900,
    )


def build_terraform_plan(
    config: ClusterConfig, directory: str | Path | None = None
) -> list[Step]:
    """The Terraform equivalent of ``build_plan``."""
    paths = layout(config, directory)
    var_file = f"-var-file={paths.tfvars}"

    steps = _workspace_steps(paths)
    steps.append(_init_step(paths))
    steps.append(
        Step(
            id="tf-plan",
            phase="plan",
            description="Show what Terraform would change",
            args=["plan", "-input=false", var_file],
            runner="terraform",
            mutating=False,
            timeout=LONG_TIMEOUT,
        )
    )
    steps.append(
        Step(
            id="tf-apply",
            phase="apply",
            description="Create the cluster and everything it needs (15-20 minutes)",
            # No saved plan file on purpose: a resumed run would otherwise be
            # able to apply a diff computed against stale state.
            args=["apply", "-input=false", "-auto-approve", var_file],
            runner="terraform",
            timeout=LONG_TIMEOUT,
            tags=("billable",),
        )
    )
    for name, var in (
        ("api_url", "API_URL"),
        ("console_url", "CONSOLE_URL"),
        ("key_vault_name", "KEYVAULT_NAME"),
    ):
        steps.append(
            Step(
                id=f"tf-output-{name.replace('_', '-')}",
                phase="outputs",
                description=f"Read the {name} output",
                args=["output", "-raw", name],
                runner="terraform",
                capture=var,
                mutating=False,
                timeout=DEFAULT_TIMEOUT,
            )
        )
    return steps


def build_terraform_destroy_plan(
    config: ClusterConfig, directory: str | Path | None = None
) -> list[Step]:
    """The Terraform equivalent of ``build_destroy_plan``.

    The module and tfvars are refetched first: `terraform destroy` needs both
    to resolve what it is destroying, and a teardown often runs in a fresh
    checkout.
    """
    paths = layout(config, directory)

    steps = _workspace_steps(paths)
    steps.append(_init_step(paths))
    steps.append(
        Step(
            id="tf-state-rm-node-pools",
            phase="nodepool-state",
            description="Remove node pools from Terraform state (OCPBUGS-86702)",
            args=["state-rm-node-pools"],
            action="state-rm-node-pools",
            runner="terraform",
            deletes=True,
            timeout=LONG_TIMEOUT,
            tags=("destructive",),
        )
    )
    steps.append(
        Step(
            id="tf-destroy",
            phase="destroy",
            description=(
                "Destroy the cluster, Key Vault, identities, network and "
                "resource group (15-30 minutes)"
            ),
            args=[
                "destroy", "-input=false", "-auto-approve",
                f"-var-file={paths.tfvars}",
            ],
            runner="terraform",
            deletes=True,
            timeout=LONG_TIMEOUT,
            tags=("destructive", "billable"),
        )
    )
    return steps
