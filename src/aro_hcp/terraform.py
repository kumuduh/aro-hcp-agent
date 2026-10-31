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

import dataclasses
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import pullsecret, roles
from .azure import DEFAULT_TIMEOUT, LONG_TIMEOUT, AzResult
from .config import NODEPOOL_NAME_RE, TERRAFORM_REF, TERRAFORM_REPO, ClusterConfig
from .plan import Step, _role_assignment_step
from .runner import TerraformCli

TERRAFORM_PHASES = ("workspace", "init", "plan", "apply", "outputs", "pull-secret")

TERRAFORM_DESTROY_PHASES = ("workspace", "init", "nodepool-state", "destroy")

# -- step tags ----------------------------------------------------------------
#
# Plain strings in ``Step.tags`` rather than new Step fields, so the plan
# dataclass stays backend-neutral. The executor and CLI read them.

#: Run on every invocation even when state records the step complete. Only for
#: non-mutating steps: re-fetching the module, rewriting the tfvars, `init`,
#: `plan` and reading outputs are how a re-run notices drift, a changed setting
#: or a deleted checkout (D16). Recording them "done" froze the wrapper at the
#: first run's view of the world.
ALWAYS = "always"

#: Local bookkeeping, not a change to Azure. A teardown summary that counts
#: these as "deleted" reports work that never happened (TFX1).
BOOKKEEPING = "bookkeeping"

#: Steps that must run again when Terraform has something to change. The plan
#: action (and the tfvars/module actions, when their inputs changed) clears
#: their recorded completion, so a finished apply does not hide a new diff.
RERUN_ON_CHANGES = "rerun-on-changes"

#: State context key for the module commit a cluster was built from.
MODULE_COMMIT = "TF_MODULE_COMMIT"

#: Steps that exist only because of the D31 upstream gap; see below.
D31_TAG = "d31-workaround"

#: D31 WORKAROUND -- remove once the pinned module grants these itself.
#:
#: At the pinned ref the module's identities/locals.tf scopes the data-plane
#: file CSI driver's "Azure Red Hat OpenShift File Storage Operator" role to the
#: worker subnet and NSG only, and gives the data-plane image registry identity
#: no role at all. The ARO HCP RP now validates both on the VNet and fails
#: cluster creation ~11 minutes in (DataPlaneIdentitiesPermissionsValidation:
#: MissingRequiredPermissions, Microsoft.Network/virtualNetworks/join/action).
#: VNet scope also covers the worker subnet the RP checks for the registry.
#:
#: The module checkout is pinned and verified clean, so it is not patched.
#: Instead the build applies the network and identities first, grants the two
#: roles with `az`, then runs the full apply. Set this to False to drop the
#: extra steps once upstream assigns these roles.
D31_ROLE_WORKAROUND = True

#: The upstream root-module instances created before the cluster; verified in
#: terraform/main.tf at the pinned ref (module "network", module "identities").
_D31_STAGE1_TARGETS = ("module.network", "module.identities")

#: (identity name suffix, principal-ID context var, role, label). The names are
#: upstream's identity_names in modules/identities/locals.tf; they match the
#: az backend's suffixes, so the az plan's variable names are reused.
_D31_ASSIGNMENTS = (
    ("dp-file-csi-driver", "DP_FILE_CSI_DRIVER_MI_PID",
     roles.FILE_STORAGE_OPERATOR_ROLE, "dp file-csi-driver on VNet"),
    ("dp-image-registry", "DP_IMAGE_REGISTRY_MI_PID",
     roles.IMAGE_REGISTRY_OPERATOR_ROLE, "dp image-registry on VNet"),
)

#: Files Terraform loads from the module root without being asked. One left in
#: a checkout silently overrides the generated tfvars (D30).
_AUTO_VAR_FILES = ("terraform.tfvars", "terraform.tfvars.json")
_AUTO_VAR_GLOBS = ("*.auto.tfvars", "*.auto.tfvars.json")

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


def _checkout_dirname(ref: str) -> str:
    """One checkout per module ref (D29).

    Two clusters on different refs sharing a checkout means one run's
    `git checkout` swaps the module under the other's in-flight plan or apply.
    Clusters on the same ref still share one, which is safe: nothing moves it.
    The pinned default keeps the historical ``terraform-src`` name so existing
    work directories are reused rather than recloned.
    """
    if ref == TERRAFORM_REF:
        return "terraform-src"
    return "terraform-src-" + re.sub(r"[^A-Za-z0-9._-]", "_", ref)


def layout(config: ClusterConfig, directory: str | Path | None = None) -> Layout:
    root = Path(directory) if directory else Path.cwd() / ".aro-hcp"
    root = root.resolve()
    checkout = root / _checkout_dirname(config.terraform_ref)
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


#: HCL quoted-string escapes. hclsyntax accepts exactly \\n \\r \\t \\" \\\\
#: \\uNNNN and \\UNNNNNNNN; JSON's \\b, \\f and UTF-16 surrogate pairs are all
#: parse errors at `terraform plan` (N3).
_HCL_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _hcl_string(text: str) -> str:
    """Render a string as an HCL quoted literal that reads back verbatim."""
    out = []
    for ch in text:
        if ch in _HCL_ESCAPES:
            out.append(_HCL_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            # Everything else, including non-BMP characters, is written as
            # UTF-8; the file is written with that encoding.
            out.append(ch)
    # A quoted string is a template: ${ is an interpolation and %{ a
    # directive. Doubling the sigil is HCL's escape for both (D14, TF-14).
    body = "".join(out).replace("${", "$${").replace("%{", "%%{")
    return f'"{body}"'


def _hcl(value) -> str:
    """Render a Python value as an HCL literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TypeError(f"cannot render {value!r} as HCL")
        return repr(value)
    if isinstance(value, str):
        return _hcl_string(value)
    if isinstance(value, dict):
        if not value:
            return "{}"
        # Keys are quoted strings too, so they need the same escaping (N4).
        body = ", ".join(f"{_hcl_string(str(k))} = {_hcl(v)}" for k, v in value.items())
        return "{ " + body + " }"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_hcl(v) for v in value) + "]"
    raise TypeError(f"cannot render {type(value).__name__} as HCL")


def _node_pools(config: ClusterConfig, *, teardown: bool = False) -> dict:
    if teardown:
        # The module requires one pool of >= 2 replicas even to destroy, and
        # the teardown drops every pool from state first (OCPBUGS-86702), so
        # these values only have to pass its validation.
        name = config.nodepool_name if NODEPOOL_NAME_RE.match(config.nodepool_name) else "np-1"
        return {
            name: {
                "vm_size": config.nodepool_vm_size,
                "replicas": max(2, config.nodepool_replicas),
            }
        }
    if config.skip_nodepool:
        return {}
    return {
        config.nodepool_name: {
            "vm_size": config.nodepool_vm_size,
            "replicas": config.nodepool_replicas,
        }
    }


def _provenance(config: ClusterConfig) -> str:
    """Say which module the file was written for.

    With terraform_dir set, the pinned repo and ref are not what runs; claiming
    them would send whoever debugs this to the wrong source.
    """
    if config.terraform_dir:
        return f"# Module: custom checkout at {Path(config.terraform_dir).resolve()}"
    return f"# Module: {TERRAFORM_REPO} @ {config.terraform_ref}"


def render_tfvars(config: ClusterConfig, *, teardown: bool = False) -> str:
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
        ("node_pools", _node_pools(config, teardown=teardown)),
        # The module stores the file in Key Vault as redhat-pull-secret; the
        # pull-secret step puts it in the cluster. A teardown must not depend
        # on the file still being there (the module checks it exists).
        ("pull_secret_path", "" if teardown else config.pull_secret_path),
    ]

    lines = [
        "# Generated by aro-hcp from the cluster config. Do not edit:",
        "# `aro-hcp apply --backend terraform` overwrites this file.",
        _provenance(config),
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
    if teardown and (config.skip_nodepool or config.nodepool_replicas < 2):
        lines.insert(4, "# Written for a teardown: node_pools only satisfies the module.")
    elif config.skip_nodepool:
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


_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def _same_repo(a: str, b: str) -> bool:
    def norm(url: str) -> str:
        url = url.strip().rstrip("/")
        return (url[:-4] if url.endswith(".git") else url).lower()

    return norm(a) == norm(b)


def _rerun_on_changes(executor, reason: str) -> None:
    """Clear the recorded completion of every step that applies changes.

    Without this a finished apply is skipped forever, so a changed setting
    or drift reported by `plan` never reaches Azure (D16, TF-45).
    """
    reset = []
    for step in executor.plan:
        if RERUN_ON_CHANGES in step.tags and executor.state.is_complete(step.id):
            executor.state.reset(step.id)
            reset.append(step.id)
    if reset:
        executor.on_event(f"note  {reason}; will re-run: {', '.join(reset)}")


def _foreign_var_files(module: Path) -> list[str]:
    found = [name for name in _AUTO_VAR_FILES if (module / name).is_file()]
    for pattern in _AUTO_VAR_GLOBS:
        found += sorted(p.name for p in module.glob(pattern))
    return found


def _forget_az_vault_name(executor) -> None:
    """Drop the az backend's derived ``<cluster>-kv`` from the run context.

    ``config.base_context()`` seeds KEYVAULT_NAME for every run, but the module
    names its vault ``cust-kv-<random>``; until the outputs phase captures the
    real one, the seeded name points at a vault that does not exist.
    """
    context = executor.state.context
    if context.get("KEYVAULT_NAME") == executor.config.keyvault_name:
        context.pop("KEYVAULT_NAME", None)


def _resolve_ref(checkout: Path, ref: str) -> tuple[str | None, str]:
    """Resolve the configured ref to a commit SHA, or ``(None, error)``.

    A full SHA is taken as is. A branch resolves through ``origin/<ref>``: the
    local branch created at clone time never moves, so checking it out would
    pin the clone-time commit forever (N5). Tags and short SHAs fall through
    to a plain lookup.
    """
    if _FULL_SHA.match(ref):
        return ref, ""
    for candidate in (f"origin/{ref}", f"refs/tags/{ref}", ref):
        out = _git("rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}", cwd=checkout)
        sha = out.stdout.strip()
        if out.returncode == 0 and _FULL_SHA.match(sha):
            return sha, ""
    return None, f"cannot resolve terraform_ref {ref!r} to a commit in {checkout}"


#: The module's provider lock file. `terraform init` adds the current
#: platform's hashes to it (the committed file covers linux only), so it is the
#: one file allowed to differ; fetch-module resets it every run.
_LOCK_FILE = "terraform/.terraform.lock.hcl"


def _verify_existing_checkout(checkout: Path) -> str:
    """Return why a cached checkout cannot be trusted, or "" if it can.

    It must be a clone of the pinned repository and have no local changes:
    a modified or extra file is applied as if it were the upstream module.
    """
    origin = _git("remote", "get-url", "origin", cwd=checkout)
    url = origin.stdout.strip()
    if origin.returncode != 0:
        return f"{checkout} has no origin remote; delete it to reclone"
    if url and not _same_repo(url, TERRAFORM_REPO):
        return (f"{checkout} is a clone of {url}, not {TERRAFORM_REPO}; "
                "delete it to reclone")
    status = _git("status", "--porcelain", cwd=checkout)
    if status.returncode != 0:
        return f"git status failed in {checkout}: {status.stderr.strip()}"
    dirty = [line for line in status.stdout.splitlines() if line[3:] != _LOCK_FILE]
    if dirty:
        changed = ", ".join(line[3:] for line in dirty[:5])
        return (f"{checkout} has local changes ({changed}); the pinned module "
                "must be applied unmodified. Discard them or delete the checkout")
    return ""


def action_fetch_module(executor, step: Step) -> AzResult:
    """Clone the upstream Terraform module at the pinned ref.

    The target comes from the step's own arguments, not from recomputing the
    layout: the plan was rendered against one work directory and the action
    must not be able to pick a different one.
    """
    config = executor.config
    _forget_az_vault_name(executor)
    argv = step.render(executor.context)
    checkout = Path(argv[1])
    module = Path(config.terraform_dir) if config.terraform_dir else checkout / "terraform"

    if config.terraform_dir:
        if not (module / "variables.tf").is_file():
            return _fail(argv, f"terraform_dir {module} has no variables.tf")
        foreign = _foreign_var_files(module)
        if foreign:
            return _fail(argv, _foreign_message(module, foreign))
        return _ok(argv, f"using the configured checkout at {module}")

    if shutil.which("git") is None:
        return _fail(argv, "`git` is not on PATH; it is needed to fetch the module")

    ref = config.terraform_ref
    recorded = executor.state.get(MODULE_COMMIT)
    if "--teardown" in argv[2:] and recorded and recorded != ref:
        # Tear down with the module the cluster was built from, wherever
        # terraform_ref points today (a moved branch, a newer default pin).
        executor.on_event(f"note  {step.id}: using module commit {recorded[:12]}, "
                          "recorded when the cluster was built")
        ref = recorded
    previous = ""
    if (checkout / ".git").is_dir():
        problem = _verify_existing_checkout(checkout)
        if problem:
            return _fail(argv, problem)
        # Back to the committed lock file, so a checkout of another commit
        # cannot conflict with the hashes the last init added.
        reset = _git("checkout", "--", _LOCK_FILE, cwd=checkout)
        if reset.returncode != 0 and (checkout / _LOCK_FILE).exists():
            return _fail(argv, f"could not reset {_LOCK_FILE}: {reset.stderr.strip()}")
        head = _git("rev-parse", "HEAD", cwd=checkout)
        previous = head.stdout.strip() if head.returncode == 0 else ""
        # Exact, full-length comparison: a prefix match accepts any commit
        # sharing the first seven characters (TF-2).
        if _FULL_SHA.match(ref) and previous == ref:
            # Still checked: a gitignored *.auto.tfvars passes `git status`
            # and would override the generated variables (D30).
            foreign = _foreign_var_files(module)
            if foreign:
                return _fail(argv, _foreign_message(module, foreign))
            moved = _record_module_commit(executor, ref, ref)
            if moved:
                return _fail(argv, moved)
            return _ok(argv, f"{checkout} is already at {ref[:12]}")
        fetched = _git("fetch", "--quiet", "origin", cwd=checkout)
        if fetched.returncode != 0:
            return _fail(argv, f"git fetch failed: {fetched.stderr.strip()}")
        verify_head = True
    else:
        checkout.parent.mkdir(parents=True, exist_ok=True)
        # blob:none keeps the clone small; the pinned ref still has to be
        # reachable, so this is not a --depth 1 clone.
        cloned = _git(
            "clone", "--quiet", "--filter=blob:none", TERRAFORM_REPO, str(checkout),
        )
        if cloned.returncode != 0:
            return _fail(argv, f"git clone failed: {cloned.stderr.strip()}")
        # A fresh clone of a full SHA cannot land anywhere else; anything
        # resolved by name is checked after the checkout.
        verify_head = not _FULL_SHA.match(ref)

    sha, error = _resolve_ref(checkout, ref)
    if sha is None:
        return _fail(argv, error)
    out = _git("checkout", "--quiet", "--detach", sha, cwd=checkout)
    if out.returncode != 0:
        return _fail(argv, f"git checkout {ref} failed: {out.stderr.strip()}")
    if verify_head:
        head = _git("rev-parse", "HEAD", cwd=checkout)
        if head.returncode != 0 or head.stdout.strip() != sha:
            return _fail(
                argv,
                f"{checkout} is at {head.stdout.strip() or '?'} after checkout, "
                f"expected {sha}",
            )
    if not (module / "variables.tf").is_file():
        return _fail(
            argv,
            f"{module} has no variables.tf; the upstream layout may have "
            f"changed at {ref}",
        )
    foreign = _foreign_var_files(module)
    if foreign:
        return _fail(argv, _foreign_message(module, foreign))
    moved = _record_module_commit(executor, ref, sha)
    if moved:
        return _fail(argv, moved)
    # A different commit is a different module: what was applied before
    # no longer describes what this one would build. (A fresh clone has no
    # "before"; the plan step catches any difference that matters.)
    if previous and previous != sha:
        _rerun_on_changes(executor, f"module moved from {previous[:12]} to {sha[:12]}")
    resolved = "" if sha == ref else f" ({ref} resolves to {sha})"
    return _ok(argv, f"checked out {sha[:12]} in {checkout}{resolved}")


def _record_module_commit(executor, ref: str, sha: str) -> str:
    """Record the module commit in state; say why not if a name moved under it.

    A branch or tag is resolved afresh on every run, so the same config could
    build or update one cluster with different module code. A full SHA in
    terraform_ref is a deliberate choice and is simply recorded. (A teardown
    never gets here with a moved name: it checks out the recorded commit.)
    """
    recorded = executor.state.get(MODULE_COMMIT)
    if recorded and recorded != sha and not _FULL_SHA.match(ref):
        return (
            f"terraform_ref {ref!r} now resolves to {sha[:12]}, but this cluster's "
            f"state records module commit {recorded[:12]}: it moved upstream. Set "
            f"terraform_ref: {recorded} to keep the module the cluster was built "
            f"with, or terraform_ref: {sha} to move to the new one deliberately"
        )
    executor.state.set_context(MODULE_COMMIT, sha)
    return ""


def _foreign_message(module: Path, names: list[str]) -> str:
    return (
        f"{module} contains {', '.join(names)}, which Terraform loads "
        "automatically and which would override the generated tfvars. Remove "
        "or rename them; aro-hcp passes its own -var-file"
    )


def action_write_tfvars(executor, step: Step) -> AzResult:
    """Render the config into the module's tfvars file."""
    argv = step.render(executor.context)
    target = Path(argv[1])
    body = render_tfvars(executor.config, teardown="--teardown" in argv[2:])
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_text(encoding="utf-8") == body:
        return _ok(argv, f"{target} is already up to date")
    existed = target.exists()
    target.write_text(body, encoding="utf-8")
    if existed:
        _rerun_on_changes(executor, f"{target.name} changed")
    return _ok(argv, f"wrote {target} ({len(body.splitlines())} lines)")


def _planned_deletes(runner, plan_file: Path, timeout: int) -> tuple[list[str] | None, str]:
    """Addresses the saved plan deletes or replaces, or ``(None, error)``."""
    shown = runner.run(["show", "-json", str(plan_file)], check=False, force=True,
                       timeout=timeout)
    try:
        payload = json.loads(shown.stdout) if shown.ok else None
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        return None, (shown.stderr.strip() or "unreadable `terraform show -json` output")
    return [
        str(change.get("address"))
        for change in payload.get("resource_changes") or []
        if isinstance(change, dict)
        and "delete" in ((change.get("change") or {}).get("actions") or [])
    ], ""


def action_terraform_plan(executor, step: Step) -> AzResult:
    """Run `terraform plan -detailed-exitcode` and act on its answer.

    Exit 2 means "succeeded, with changes". The executor would read that as a
    failure, so this maps it to success and marks the apply steps pending:
    a completed apply must not hide a diff the plan just reported (D16).

    Apply re-plans with -auto-approve rather than applying a saved plan, so
    nobody reviews what it runs. A diff that deletes or replaces anything
    (drift, a moved module ref) is therefore refused unless the operator
    passed --allow-deletes. The saved plan is only inspected, then removed:
    it holds variable values, the pull secret among them.
    """
    runner = executor.runner_for(step)
    argv = step.render(executor.context)
    plan_file = Path(next(a for a in argv if a.startswith("-out=")).split("=", 1)[1])
    plan_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = runner.run(argv, check=False, force=True, timeout=step.timeout)
        if result.returncode != 2:
            if result.ok:
                executor.state.set_context("TF_PLAN_HAS_CHANGES", "no")
            return result
        deletes, error = _planned_deletes(runner, plan_file, step.timeout)
    finally:
        plan_file.unlink(missing_ok=True)
    executor.state.set_context("TF_PLAN_HAS_CHANGES", "yes")
    _rerun_on_changes(executor, "terraform plan reports changes")
    passed = AzResult(result.args, 0, result.stdout, result.stderr)
    if not deletes and deletes is not None:
        return passed
    what = (f"would delete or replace {len(deletes)} resource(s): {', '.join(deletes[:10])}"
            if deletes else f"could not be checked for deletions ({error})")
    if not executor.apply or executor.allow_deletes:
        executor.on_event(f"warn  {step.id}: the plan {what}")
        return passed
    return _fail(
        argv,
        f"terraform plan {what}. Apply re-plans without a review, so this is refused. "
        "Inspect it with `aro-hcp plan --backend terraform -v`, then re-run apply "
        "with --allow-deletes if it is intended.",
    )


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
        # Only Terraform's own words mean "no state". A silent non-zero exit
        # (killed process, backend error on stdout) skipping this step sends
        # destroy straight into OCPBUGS-86702 (N2, TF-51).
        if "No state file was found" in listed.stderr:
            return _ok(argv, "no terraform state; nothing to remove")
        detail = listed.stderr.strip() or listed.stdout.strip()
        return _fail(
            argv, detail or f"terraform state list exited {listed.returncode} with no output",
        )

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
    "terraform-plan": action_terraform_plan,
    "state-rm-node-pools": action_state_rm_node_pools,
}


# -- helpers for the CLI ------------------------------------------------------


def plan_json(
    config: ClusterConfig,
    runner: TerraformCli,
    directory: str | Path | None = None,
    *,
    timeout: int = LONG_TIMEOUT,
) -> dict:
    """Return ``terraform show -json`` of a fresh plan, for ``plan --json``.

    Needs the workspace and init phases to have run. Non-mutating: the saved
    plan lives in the per-cluster data directory and is only ever shown, never
    applied (apply re-plans; see build_terraform_plan). Raises AzError if
    either command fails.
    """
    paths = layout(config, directory)
    plan_file = paths.data_dir / "aro-hcp-review.tfplan"
    runner.run(
        ["plan", "-input=false", f"-out={plan_file}", f"-var-file={paths.tfvars}"],
        force=True, timeout=timeout,
    )
    shown = runner.run(["show", "-json", str(plan_file)], force=True, timeout=DEFAULT_TIMEOUT)
    return {"kind": "terraform-plan", "plan": json.loads(shown.stdout or "{}")}


def error_excerpt(text: str, limit: int = 4000) -> str:
    """The part of Terraform's output worth showing when a step fails.

    The diagnostic that matters (an RP error is several KB of JSON) comes
    after progress lines, so a head truncation shows everything but it.
    Start from the first ``Error:`` block, else keep the tail.
    """
    text = text.strip()
    match = re.search(r"^(?:[│|]\s*)?Error: ", text, re.M)
    if match:
        text = text[match.start():]
        return text if len(text) <= limit else text[:limit] + "\n[... truncated]"
    return text if len(text) <= limit else "[... truncated]\n" + text[-limit:]


# -- plans ------------------------------------------------------------------


def _workspace_steps(
    paths: Layout, *, always: bool = True, teardown: bool = False
) -> list[Step]:
    """Fetch the module and write the tfvars.

    Both are marked non-mutating: they touch only the local work directory, so
    they run during a dry run too. That is what lets `plan --backend terraform`
    show a real `terraform plan` diff instead of a rendered command.
    """
    tags = (ALWAYS, BOOKKEEPING) if always else (BOOKKEEPING,)
    return [
        Step(
            id="tf-fetch-module",
            phase="workspace",
            description="Fetch the upstream Terraform module at the pinned ref",
            args=["fetch-module", str(paths.checkout), *(["--teardown"] if teardown else [])],
            action="fetch-module",
            runner="terraform",
            mutating=False,
            timeout=900,
            tags=tags,
        ),
        Step(
            id="tf-write-tfvars",
            phase="workspace",
            description="Write the cluster config as Terraform variables",
            args=["write-tfvars", str(paths.tfvars), *(["--teardown"] if teardown else [])],
            action="write-tfvars",
            runner="terraform",
            mutating=False,
            tags=tags,
        ),
    ]


def _init_step(paths: Layout, *, always: bool = True) -> Step:
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
        tags=(ALWAYS, BOOKKEEPING) if always else (BOOKKEEPING,),
    )


def _d31_steps(var_file: str) -> list[Step]:
    """D31 WORKAROUND: grant the data-plane VNet roles the pinned module omits.

    Remove with D31_ROLE_WORKAROUND once upstream assigns them. Order matters:
    the identities and the VNet must exist before they can be granted, and the
    grants must exist before the cluster is created, so the apply is split
    around them. Lookups and grants reuse the az plan's machinery: the
    exists-probe makes a re-run a no-op.
    """
    tags = (D31_TAG, RERUN_ON_CHANGES)
    steps = [
        Step(
            id="tf-apply-network-identities",
            phase="apply",
            description=(
                "D31 workaround: create the network and identities first "
                "(terraform apply -target)"
            ),
            args=[
                "apply", "-input=false", "-auto-approve",
                *(f"-target={t}" for t in _D31_STAGE1_TARGETS),
                var_file,
            ],
            runner="terraform",
            timeout=LONG_TIMEOUT,
            tags=tags,
            # Only after this run's plan passed the deletion guard.
            after=("tf-plan",),
        ),
        Step(
            id="tf-d31-vnet-id",
            phase="apply",
            description="D31 workaround: read the VNet resource ID",
            args=["network", "vnet", "show", "--name", "${CUSTOMER_VNET_NAME}",
                  "--resource-group", "${CUSTOMER_RG_NAME}",
                  "--query", "id", "--output", "tsv"],
            capture="VNET_ID",
            mutating=False,
            tags=tags,
        ),
    ]
    for suffix, principal_var, _role, _label in _D31_ASSIGNMENTS:
        steps.append(
            Step(
                id=f"tf-d31-pid-{suffix}",
                phase="apply",
                description=f"D31 workaround: read the principal ID of {suffix}",
                args=["identity", "show", "--name", f"${{CLUSTER_NAME}}-{suffix}",
                      "--resource-group", "${CUSTOMER_RG_NAME}",
                      "--query", "principalId", "--output", "tsv"],
                capture=principal_var,
                mutating=False,
                tags=tags,
            )
        )
    for index, (suffix, principal_var, role, label) in enumerate(_D31_ASSIGNMENTS, start=1):
        grant = _role_assignment_step(index, principal_var, role, "VNET_ID", label, "apply")
        steps.append(
            dataclasses.replace(
                grant,
                id=f"tf-d31-role-{suffix}-vnet",
                description=f"D31 workaround: {grant.description}",
                tags=(*grant.tags, *tags),
            )
        )
    return steps


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
            # -detailed-exitcode: exit 2 means "changes pending", which the
            # action turns into "re-run the apply steps". -out is inspected
            # for deletions, never applied.
            args=["plan", "-input=false", "-detailed-exitcode",
                  f"-out={paths.data_dir / 'aro-hcp-check.tfplan'}", var_file],
            action="terraform-plan",
            runner="terraform",
            mutating=False,
            timeout=LONG_TIMEOUT,
            tags=(ALWAYS,),
        )
    )
    if D31_ROLE_WORKAROUND:
        steps += _d31_steps(var_file)
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
            tags=("billable", RERUN_ON_CHANGES),
            # Only after this run's plan passed the deletion guard, so neither
            # --keep-going nor --phase apply can skip it.
            after=("tf-plan",),
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
                tags=(ALWAYS,),
            )
        )
    if config.pull_secret_path:
        steps.append(pullsecret.build_step(config, after=("tf-apply",)))
    return steps


def build_terraform_destroy_plan(
    config: ClusterConfig, directory: str | Path | None = None
) -> list[Step]:
    """The Terraform equivalent of ``build_destroy_plan``.

    The module and tfvars are refetched first: `terraform destroy` needs both
    to resolve what it is destroying, and a teardown often runs in a fresh
    checkout. `init` is not repeated on a resumed teardown: the per-cluster
    data directory it populated is still there.

    The D31 role assignments are not removed separately: they are extension
    resources on the VNet, and ARM deletes them with it.
    """
    paths = layout(config, directory)

    steps = _workspace_steps(paths, teardown=True)
    steps.append(_init_step(paths, always=False))
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
            # Edits Terraform's state file only; ARM deletes the pools later.
            tags=("destructive", BOOKKEEPING),
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
