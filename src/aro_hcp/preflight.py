"""Environment checks that run before anything is created.

Each check returns a Finding. ``blocking=True`` means apply should not start.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import shutil
from dataclasses import dataclass, field

from .azure import AzCli
from .config import ClusterConfig
from . import roles

OK = "ok"
WARN = "warn"
FAIL = "fail"

#: `az account show --query user.name` under `az login --identity`. These are
#: literals, not principals, so nothing can be granted to them by that name.
MANAGED_IDENTITY_USER_NAMES = {"systemAssignedIdentity", "userAssignedIdentity"}

#: Built-in roles that carry Microsoft.Authorization/roleAssignments/write. The
#: plan creates ~30 role assignments, so the signed-in principal needs one of
#: these at the resource group (or a broader) scope. Matched by name and by
#: role definition GUID, since either can be what a listing shows.
ROLE_ASSIGNMENT_WRITER_ROLES = {
    "owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "user access administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "role based access control administrator": "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
}

#: Common built-ins known to lack roleAssignments/write, so a listing that has
#: only these is a definite "no" without fetching each role definition.
NON_WRITER_ROLES = {
    "contributor", "reader", "key vault administrator", "key vault crypto officer",
    "network contributor", "virtual machine contributor", "storage account contributor",
    "managed identity contributor", "managed identity operator", "monitoring reader",
}

ROLE_ASSIGNMENT_WRITE = "microsoft.authorization/roleassignments/write"

#: Error text that means "the thing does not exist", as opposed to "could not
#: look". Anything else from a lookup is an unknown, never an absence.
_NOT_FOUND_RE = re.compile(r"ResourceNotFound|ResourceGroupNotFound|could not be found")

#: Cluster provisioning states that mean "busy, try again later" rather than
#: "broken". Failed is handled separately; Succeeded resumes.
_CLUSTER_BUSY_STATES = {"accepted", "provisioning", "updating", "deleting", "creating"}

#: Worker VM shapes ARO does not support. Burstable B-series cannot sustain
#: node load and below MIN_WORKER_VCPUS the node is consumed by system pods.
UNSUPPORTED_VM_SERIES = {"B"}
MIN_WORKER_VCPUS = 4
SUPPORTED_SIZES_DOC = (
    "https://learn.microsoft.com/azure/openshift/support-policies-v4#supported-virtual-machine-sizes"
)
QUOTA_DOC = (
    "https://learn.microsoft.com/azure/azure-portal/supportability/per-vm-quota-requests"
)


@dataclass
class Finding:
    check: str
    status: str
    message: str
    remedy: str = ""

    @property
    def blocking(self) -> bool:
        return self.status == FAIL

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "status": self.status,
            "message": self.message,
            "remedy": self.remedy,
        }


@dataclass
class PreflightReport:
    findings: list[Finding] = field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    @property
    def blocked(self) -> bool:
        return any(f.blocking for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "blocked": self.blocked,
            "findings": [f.to_dict() for f in self.findings],
        }


def _parse_version(text: str) -> tuple[int, ...] | None:
    match = re.search(r"azure-cli\s+(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return None
    return tuple(int(g) for g in match.groups())


def check_az_cli(az: AzCli) -> Finding:
    if shutil.which("az") is None:
        return Finding(
            "az-cli", FAIL, "the `az` CLI is not on PATH",
            "install it: https://learn.microsoft.com/cli/azure/install-azure-cli",
        )
    result = az.run(["--version"], check=False, force=True)
    version = _parse_version(result.stdout)
    if version is None:
        return Finding("az-cli", WARN, "could not parse the `az --version` output")
    if version < roles.MIN_AZ_VERSION:
        want = ".".join(str(p) for p in roles.MIN_AZ_VERSION)
        have = ".".join(str(p) for p in version)
        return Finding(
            "az-cli", FAIL, f"azure-cli {have} is older than the required {want}",
            "az upgrade",
        )
    return Finding("az-cli", OK, f"azure-cli {'.'.join(str(p) for p in version)}")


def check_terraform(config: ClusterConfig) -> list[Finding]:
    """Tooling the terraform backend needs and the az one does not."""
    from .runner import MIN_TERRAFORM_VERSION
    from .runner import TerraformCli

    want = ".".join(str(p) for p in MIN_TERRAFORM_VERSION)
    if shutil.which("terraform") is None:
        return [
            Finding(
                "terraform", FAIL, "the `terraform` CLI is not on PATH",
                "install it: https://developer.hashicorp.com/terraform/install",
            )
        ]
    version = TerraformCli(".").version()
    if version is None:
        findings = [Finding("terraform", WARN, "could not read the terraform version")]
    elif version < MIN_TERRAFORM_VERSION:
        have = ".".join(str(p) for p in version)
        findings = [
            Finding(
                "terraform", FAIL,
                f"terraform {have} is older than the {want} the module requires",
                "upgrade terraform",
            )
        ]
    else:
        findings = [
            Finding("terraform", OK, f"terraform {'.'.join(str(p) for p in version)}")
        ]

    if config.terraform_dir:
        findings.append(
            Finding("terraform-module", OK, f"using the checkout at {config.terraform_dir}")
        )
    elif shutil.which("git") is None:
        findings.append(
            Finding(
                "terraform-module", FAIL,
                "`git` is not on PATH, and it is needed to fetch the module",
                "install git, or set terraform_dir to an existing checkout",
            )
        )
    else:
        findings.append(
            Finding(
                "terraform-module", OK,
                f"will fetch the module at {config.terraform_ref[:12]}",
            )
        )
    return findings


def check_aro_extension(az: AzCli) -> Finding:
    result = az.run(
        ["extension", "show", "--name", "aro", "--query", "version", "--output", "tsv"],
        check=False, force=True,
    )
    if not result.ok or not result.text:
        return Finding(
            "aro-extension", FAIL, "the `aro` CLI extension is not installed",
            "az extension add --name aro",
        )
    probe = az.run(["aro", "hcp", "--help"], check=False, force=True)
    if not probe.ok:
        return Finding(
            "aro-extension", FAIL,
            f"`aro` extension {result.text} is installed but has no `hcp` command group",
            "az extension update --name aro",
        )
    return Finding("aro-extension", OK, f"aro extension {result.text} with `hcp` support")


def check_login(az: AzCli, config: ClusterConfig) -> list[Finding]:
    subscription = az.current_subscription()
    if not subscription:
        return [Finding("login", FAIL, "not signed in to Azure", "az login")]
    findings = [Finding("login", OK, f"signed in, subscription {subscription}")]
    if config.subscription_id and config.subscription_id != subscription:
        findings.append(
            Finding(
                "subscription", WARN,
                f"config targets {config.subscription_id} but the active subscription "
                f"is {subscription}; every command will be scoped to the configured one",
            )
        )
    user = az.signed_in_user()
    if user in MANAGED_IDENTITY_USER_NAMES:
        findings.append(
            Finding(
                "identity", FAIL,
                f"signed in with a managed identity (user.name is the literal {user!r}); "
                "the Key Vault Crypto Officer grant would use that literal as its "
                "assignee and fail mid-apply",
                "sign in as a user (az login) or a service principal "
                "(az login --service-principal -u <appId> ...)",
            )
        )
    elif user:
        findings.append(Finding("identity", OK, f"signed in as {user}"))
    else:
        findings.append(
            Finding(
                "identity", WARN,
                "could not read `account show --query user.name`; the Key Vault Crypto "
                "Officer grant needs an explicit assignee",
            )
        )
    return findings


def check_providers(az: AzCli, config: ClusterConfig) -> list[Finding]:
    findings = []
    for provider in roles.REQUIRED_RESOURCE_PROVIDERS:
        result = az.run(
            ["provider", "show", "--namespace", provider,
             "--query", "registrationState", "--output", "tsv"],
            check=False, force=True,
        )
        state = result.text
        if state == "Registered":
            findings.append(Finding(f"provider:{provider}", OK, "registered"))
        else:
            findings.append(
                Finding(
                    f"provider:{provider}", WARN,
                    f"registration state is {state or 'unknown'}",
                    f"az provider register --namespace {provider} --wait "
                    "(the providers phase does this)",
                )
            )
    return findings


def _vm_vcpus(vm_size: str) -> int | None:
    """vCPUs from the size name: Standard_D8s_v6 -> 8, Standard_E8-4s_v5 -> 8.

    Quota is charged on the size's full vCPU count, so a constrained-core size
    (the ``-4`` above) still counts its leading number.
    """
    match = re.match(r"Standard_[A-Z]+(\d+)", vm_size, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _usage_entry(usages: list, name: str) -> dict | None:
    """Exact, case-insensitive quota-name match.

    Azure reports e.g. ``StandardDsv6Family`` where the docs say
    ``standardDSv6Family``; a substring match would let ``standardDSv6Family``
    hit ``standardDDSv6Family``-style neighbours, so compare whole names.
    """
    for usage in usages:
        names = usage.get("name")
        value = names.get("value", "") if isinstance(names, dict) else ""
        if isinstance(value, str) and value.lower() == name.lower():
            return usage
    return None


def check_quota(az: AzCli, config: ClusterConfig) -> Finding:
    """Compare free cores, in the VM family and region-wide, with what apply needs.

    Demand is replicas x vCPUs of the node pool size, floored at MIN_CORES.
    Both the family quota and the regional ``cores`` total must cover it; the
    tighter one wins.
    """
    family = _vm_family(config.nodepool_vm_size)
    vcpus = _vm_vcpus(config.nodepool_vm_size)
    demand = 0 if config.skip_nodepool or vcpus is None else config.nodepool_replicas * vcpus
    needed = max(roles.MIN_CORES, demand)
    why = (f"{config.nodepool_replicas} x {config.nodepool_vm_size} = {demand} cores"
           if demand > roles.MIN_CORES else f"ARO HCP needs at least {roles.MIN_CORES}")
    listing = f"az vm list-usage -l {config.location} -o table"

    result = az.run(
        ["vm", "list-usage", "--location", config.location, "--output", "json"],
        check=False, force=True,
    )
    if not result.ok or not result.text:
        return Finding(
            "quota", WARN, f"could not read VM quota for {config.location}", listing,
        )
    try:
        usages = result.json()
    except ValueError:
        return Finding("quota", WARN, "could not parse the VM quota response", listing)
    if not isinstance(usages, list) or not all(isinstance(u, dict) for u in usages):
        return Finding(
            "quota", WARN,
            "the VM quota response was not the expected list of usages", listing,
        )

    if not family:
        return Finding(
            "quota", WARN,
            f"cannot tell the quota family of VM size {config.nodepool_vm_size!r}",
            f"check it by hand: {listing}",
        )
    entries = [(family, _usage_entry(usages, family)), ("cores", _usage_entry(usages, "cores"))]
    if entries[0][1] is None:
        return Finding(
            "quota", WARN,
            f"no quota entry found for VM family {family!r} in {config.location}",
            f"check it by hand: {listing}",
        )

    summaries = []
    for label, entry in entries:
        if entry is None:
            # Regional total missing is odd but not a reason to block; the
            # family figure above is still checked.
            summaries.append(f"{label}: not reported")
            continue
        try:
            limit = int(entry.get("limit", 0))
            current = int(entry.get("currentValue", 0))
        except (TypeError, ValueError):
            return Finding(
                "quota", WARN, f"could not read the {label} quota figures", listing,
            )
        available = limit - current
        name = (entry.get("name") or {}).get("value", label)
        if available < needed:
            scope = "regional total" if label == "cores" else "family"
            return Finding(
                "quota", FAIL,
                f"{name} ({scope}): {available} of {limit} cores available in "
                f"{config.location}; {why}",
                f"request a quota increase for {name}: {QUOTA_DOC}, or lower "
                "nodepool_replicas / pick a smaller nodepool_vm_size",
            )
        summaries.append(f"{name}: {available} of {limit} cores available")
    return Finding("quota", OK, f"{'; '.join(summaries)} (need {needed})")


def check_vm_sku(az: AzCli, config: ClusterConfig) -> Finding:
    """Is the node pool size supported by ARO, and offered to this subscription here?"""
    size = config.nodepool_vm_size
    match = re.match(r"Standard_([A-Z]+)\d", size, re.IGNORECASE)
    vcpus = _vm_vcpus(size)
    if match and match.group(1).upper() in UNSUPPORTED_VM_SERIES:
        return Finding(
            "vm-size", FAIL,
            f"{size} is a burstable B-series size, which ARO does not support for workers",
            f"pick a supported nodepool_vm_size, e.g. Standard_D8s_v6: {SUPPORTED_SIZES_DOC}",
        )
    if vcpus is not None and vcpus < MIN_WORKER_VCPUS:
        return Finding(
            "vm-size", FAIL,
            f"{size} has {vcpus} vCPUs; ARO workers need at least {MIN_WORKER_VCPUS}",
            f"pick a supported nodepool_vm_size, e.g. Standard_D8s_v6: {SUPPORTED_SIZES_DOC}",
        )

    probe = (f"az vm list-skus -l {config.location} --size {size} --all "
             "--resource-type virtualMachines -o table")
    result = az.run(
        ["vm", "list-skus", "--location", config.location, "--size", size, "--all",
         "--resource-type", "virtualMachines", "--output", "json"],
        check=False, force=True,
    )
    try:
        skus = result.json() if result.ok else None
    except ValueError:
        skus = None
    if not isinstance(skus, list):
        return Finding(
            "vm-size", WARN,
            f"could not confirm {size} is offered in {config.location}", probe,
        )
    # --size is a prefix match (D8s_v6 also returns D8s_v6_something); keep the exact one.
    sku = next(
        (s for s in skus if isinstance(s, dict) and str(s.get("name", "")).lower() == size.lower()),
        None,
    )
    if sku is None:
        return Finding(
            "vm-size", FAIL, f"{size} is not offered in {config.location}",
            f"pick another nodepool_vm_size; list what is offered: "
            f"az vm list-skus -l {config.location} --resource-type virtualMachines -o table",
        )
    restrictions = [r for r in (sku.get("restrictions") or []) if isinstance(r, dict)]
    location_blocks = [r for r in restrictions if r.get("type") == "Location"]
    if location_blocks:
        reason = location_blocks[0].get("reasonCode") or "restricted"
        return Finding(
            "vm-size", FAIL,
            f"{size} is restricted for this subscription in {config.location} ({reason})",
            "pick another nodepool_vm_size, or ask Azure support to lift the restriction: "
            "https://learn.microsoft.com/troubleshoot/azure/general/region-access-request-process",
        )
    if restrictions:
        zones = sorted({
            z for r in restrictions
            for info in (r.get("restrictionInfo") or {},) if isinstance(info, dict)
            for z in (info.get("zones") or [])
        })
        return Finding(
            "vm-size", WARN,
            f"{size} is restricted in some zones of {config.location}"
            + (f" ({', '.join(zones)})" if zones else ""),
            probe,
        )
    return Finding("vm-size", OK, f"{size} is offered in {config.location}")


def _resolve_principal(az: AzCli) -> tuple[str, str]:
    """Return (assignee, kind) for the signed-in principal.

    The object id is preferred; when Graph cannot be read the login name (UPN
    or appId) still works as ``--assignee``. ``assignee`` is empty for a
    managed-identity login, whose name is not a principal.
    """
    name = az.signed_in_user() or ""
    if name in MANAGED_IDENTITY_USER_NAMES:
        return "", "managedIdentity"
    kind = az.query(["account", "show", "--query", "user.type", "--output", "tsv"])
    if kind == "servicePrincipal" and name:
        oid = az.query(["ad", "sp", "show", "--id", name, "--query", "id", "--output", "tsv"])
    else:
        oid = az.query(["ad", "signed-in-user", "show", "--query", "id", "--output", "tsv"])
    return (oid or name), (kind or "user")


def _scope_covers(scope: str, target: str) -> bool:
    """True if a role assignment at ``scope`` applies at ``target``."""
    if not scope:
        return False  # no scope reported: do not credit it
    scope = scope.rstrip("/").lower()
    target = target.rstrip("/").lower()
    if not scope or scope.startswith("/providers/microsoft.management/managementgroups/"):
        return True  # root or management group: inherited by every subscription
    return target == scope or target.startswith(scope + "/")


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action, pattern.lower())


def _definition_grants_write(az: AzCli, role: str, scope: str) -> bool | None:
    """Does a (custom) role carry roleAssignments/write? None when unreadable."""
    result = az.run(
        ["role", "definition", "list", "--name", role, "--scope", scope, "--output", "json"],
        check=False, force=True,
    )
    try:
        defs = result.json() if result.ok else None
    except ValueError:
        return None
    if not isinstance(defs, list) or not defs:
        return None
    for definition in defs:
        if not isinstance(definition, dict):
            return None
        for perm in definition.get("permissions") or []:
            if not isinstance(perm, dict):
                continue
            actions = [a.lower() for a in perm.get("actions") or []]
            excluded = [a.lower() for a in perm.get("notActions") or []]
            if (any(_action_matches(a, ROLE_ASSIGNMENT_WRITE) for a in actions)
                    and not any(_action_matches(a, ROLE_ASSIGNMENT_WRITE) for a in excluded)):
                return True
    return False


def check_role_assignment_permission(az: AzCli, config: ClusterConfig) -> Finding:
    """Can the signed-in principal create the plan's role assignments? (O2)

    Contributor can create every resource but not one role assignment, so
    without this check apply gets as far as the identities and then stops.
    """
    subscription = config.subscription_id or az.subscription or az.current_subscription()
    sub_scope = f"/subscriptions/{subscription}"
    rg_scope = f"{sub_scope}/resourceGroups/{config.resource_group}"
    remedy_scope = rg_scope
    assignee, kind = _resolve_principal(az)
    if not assignee:
        return Finding(
            "permissions", WARN,
            "cannot check role-assignment rights for a managed-identity login",
            "sign in as a user or service principal and re-run preflight",
        )
    remedy = (
        "have an Owner grant it: az role assignment create --assignee "
        f"{assignee} --role \"User Access Administrator\" --scope {remedy_scope} "
        "(or Owner / Role Based Access Control Administrator)"
    )

    roles_seen: dict[str, str] = {}  # lower name -> display name
    readable = False
    errors = []
    for scope in (sub_scope, rg_scope):
        result = az.run(
            ["role", "assignment", "list", "--assignee", assignee,
             "--include-inherited", "--include-groups", "--scope", scope, "--output", "json"],
            check=False, force=True,
        )
        try:
            payload = result.json() if result.ok else None
        except ValueError:
            payload = None
        if not isinstance(payload, list):
            detail = (result.stderr or result.stdout).strip().splitlines()
            errors.append(detail[0][:200] if detail else "no usable output")
            continue
        readable = True
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            if not _scope_covers(str(entry.get("scope", "")), rg_scope):
                continue
            name = str(entry.get("roleDefinitionName") or "")
            role_id = str(entry.get("roleDefinitionId") or "").rsplit("/", 1)[-1].lower()
            for writer, guid in ROLE_ASSIGNMENT_WRITER_ROLES.items():
                if name.lower() == writer or role_id == guid:
                    return Finding(
                        "permissions", OK,
                        f"{assignee} holds {name or writer} at {entry.get('scope')}",
                    )
            if name:
                roles_seen[name.lower()] = name
        if roles_seen.keys() - NON_WRITER_ROLES:
            break  # something to look up; the RG listing would not change that

    if not readable:
        return Finding(
            "permissions", WARN,
            f"could not read the role assignments of {assignee}, so it is unknown "
            f"whether it can create role assignments ({'; '.join(errors)})",
            f"az role assignment list --assignee {assignee} --all --include-inherited "
            "--include-groups -o table; it needs Owner, User Access Administrator or "
            "Role Based Access Control Administrator on the resource group",
        )

    unknown = []
    for lower, name in roles_seen.items():
        if lower in NON_WRITER_ROLES:
            continue
        grants = _definition_grants_write(az, name, sub_scope)
        if grants:
            return Finding(
                "permissions", OK,
                f"{assignee} holds {name}, which includes roleAssignments/write",
            )
        if grants is None:
            unknown.append(name)
    held = ", ".join(sorted(roles_seen.values())) or "no roles"
    if unknown:
        return Finding(
            "permissions", WARN,
            f"{assignee} holds {held}; could not read the definition of "
            f"{', '.join(unknown)} to tell whether it can create role assignments",
            remedy,
        )
    return Finding(
        "permissions", FAIL,
        f"{assignee} ({kind}) holds {held} at {rg_scope} or above, none of which can "
        "create role assignments; apply would stop at the first one",
        remedy,
    )


def _deleted_vault_location(text: str, name: str) -> tuple[bool, str]:
    """Parse `keyvault list-deleted` output. Returns (found, location)."""
    if not text:
        return False, ""
    try:
        payload = json.loads(text)
    except ValueError:
        # tsv of ids: any line is a hit, since the query already filtered by name.
        return True, ""
    if isinstance(payload, dict):
        payload = [payload]
    for entry in payload if isinstance(payload, list) else []:
        if isinstance(entry, dict) and str(entry.get("name", "")).lower() == name.lower():
            return True, str((entry.get("properties") or {}).get("location") or "")
    return False, ""


def check_keyvault_name(az: AzCli, config: ClusterConfig) -> Finding:
    """Key Vault names are global and survive deletion for the soft-delete period.

    Only the az-cli backend uses the derived name; the terraform module names
    its own vault. A vault already in the target resource group is a resume.
    """
    name = config.keyvault_name
    rename = ("choose a different cluster_name (the vault name is derived from it as "
              f"{config.cluster_name}-kv)")
    existing = az.run(
        ["keyvault", "show", "--name", name, "--resource-group", config.resource_group,
         "--query", "id", "--output", "tsv"],
        check=False, force=True,
    )
    if existing.ok and existing.text:
        return Finding(
            "keyvault-name", OK,
            f"Key Vault {name} already exists in {config.resource_group}; apply will reuse it",
        )

    deleted = az.run(
        ["keyvault", "list-deleted", "--resource-type", "vault",
         "--query", f"[?name=='{name}']", "--output", "json"],
        check=False, force=True,
    )
    if deleted.ok:
        found, location = _deleted_vault_location(deleted.text, name)
        if found:
            loc = location or config.location
            return Finding(
                "keyvault-name", FAIL,
                f"Key Vault name {name} is held by a soft-deleted vault"
                + (f" in {location}" if location else ""),
                f"purge it: az keyvault purge --name {name} --location {loc} "
                f"(irreversible), or {rename}",
            )

    subscription = config.subscription_id or az.subscription or ""
    check = az.run(
        ["rest", "--method", "post", "--url",
         f"https://management.azure.com/subscriptions/{subscription}/providers/"
         "Microsoft.KeyVault/checkNameAvailability?api-version=2022-07-01",
         "--body", json.dumps({"name": name, "type": "Microsoft.KeyVault/vaults"}),
         "--output", "json"],
        check=False, force=True,
    )
    try:
        answer = check.json() if check.ok else None
    except ValueError:
        answer = None
    if isinstance(answer, dict) and answer.get("nameAvailable") is False:
        detail = answer.get("message") or answer.get("reason") or "already in use"
        return Finding(
            "keyvault-name", FAIL,
            f"Key Vault name {name} is not available: {detail}",
            f"{rename}; if it is your own soft-deleted vault in another subscription, "
            "purge it there",
        )
    if isinstance(answer, dict) and answer.get("nameAvailable") is True:
        return Finding("keyvault-name", OK, f"Key Vault name {name} is available")
    if not deleted.ok:
        reason = "could not list soft-deleted vaults or check the name"
    else:
        reason = "could not check global name availability"
    return Finding(
        "keyvault-name", WARN,
        f"{reason} for Key Vault {name}",
        f"az keyvault list-deleted --query \"[?name=='{name}']\" -o table",
    )


def _lookup_failed(result) -> str | None:
    """None if ``result`` is a recognised not-found; otherwise the error text."""
    detail = (result.stderr or result.stdout or "").strip()
    if _NOT_FOUND_RE.search(detail):
        return None
    lines = detail.splitlines()
    return lines[0][:200] if lines else f"exit code {result.returncode}"


def check_name_collisions(az: AzCli, config: ClusterConfig) -> list[Finding]:
    """Look for leftovers that would break or redirect creation.

    A lookup that fails for any reason other than a recognised not-found is
    reported as unverified: an auth error or a timeout is not an absence (O3).
    """
    findings = []
    existing = az.run(
        ["aro", "hcp", "cluster", "show", "--name", config.cluster_name,
         "--resource-group", config.resource_group,
         "--query", "properties.provisioningState", "--output", "tsv"],
        check=False, force=True,
    )
    cluster_exists: bool | None = False
    if existing.ok:
        cluster_exists = True
        state = existing.text or "unknown"
        delete = (f"az aro hcp cluster delete --name {config.cluster_name} "
                  f"--resource-group {config.resource_group}")
        if state.lower() == "failed":
            findings.append(
                Finding(
                    "cluster-exists", FAIL,
                    f"cluster {config.cluster_name} already exists in "
                    f"{config.resource_group} in state {state}; it cannot be resumed",
                    f"delete it and re-run apply: {delete} (or `aro-hcp destroy`)",
                )
            )
        elif state.lower() == "succeeded":
            findings.append(
                Finding(
                    "cluster-exists", WARN,
                    f"cluster {config.cluster_name} already exists in "
                    f"{config.resource_group} (state: {state}); apply will skip "
                    "creation and resume",
                )
            )
        else:
            busy = state.lower() in _CLUSTER_BUSY_STATES
            findings.append(
                Finding(
                    "cluster-exists", WARN,
                    f"cluster {config.cluster_name} already exists in "
                    f"{config.resource_group} (state: {state})"
                    + ("; an operation is still in progress" if busy else ""),
                    "wait for the operation to finish, then re-run preflight: "
                    f"az aro hcp cluster show --name {config.cluster_name} "
                    f"--resource-group {config.resource_group}",
                )
            )
    else:
        error = _lookup_failed(existing)
        if error:
            cluster_exists = None
            findings.append(
                Finding(
                    "cluster-exists", WARN,
                    f"could not verify whether cluster {config.cluster_name} exists: {error}",
                    f"az aro hcp cluster show --name {config.cluster_name} "
                    f"--resource-group {config.resource_group}",
                )
            )

    managed = az.run(
        ["group", "show", "--name", config.managed_resource_group,
         "--query", "id", "--output", "tsv"],
        check=False, force=True,
    )
    if managed.ok and managed.text:
        if cluster_exists is False:
            findings.append(
                Finding(
                    "managed-rg", FAIL,
                    f"managed resource group {config.managed_resource_group} already exists "
                    "but no cluster owns it; cluster creation will fail",
                    "delete the group or choose a different managed_resource_group",
                )
            )
        elif cluster_exists is None:
            findings.append(
                Finding(
                    "managed-rg", WARN,
                    f"managed resource group {config.managed_resource_group} exists and "
                    "the cluster lookup failed, so it is unknown whether a cluster owns it",
                    "re-run preflight once `az aro hcp cluster show` works",
                )
            )
    elif not managed.ok:
        error = _lookup_failed(managed)
        if error:
            findings.append(
                Finding(
                    "managed-rg", WARN,
                    f"could not verify whether managed resource group "
                    f"{config.managed_resource_group} exists: {error}",
                    f"az group show --name {config.managed_resource_group}",
                )
            )
    return findings


def check_existing_vnet(az: AzCli, config: ClusterConfig) -> list[Finding]:
    """An existing VNet is reused as-is, so its address space must fit the subnets.

    The plan skips `vnet create` when the VNet exists and then creates the
    subnets inside it; a subnet outside the address space fails mid-apply.
    """
    result = az.run(
        ["network", "vnet", "show", "--name", config.vnet_name,
         "--resource-group", config.resource_group, "--output", "json"],
        check=False, force=True,
    )
    if not result.ok:
        error = _lookup_failed(result)
        if error:
            return [
                Finding(
                    "vnet", WARN,
                    f"could not verify whether VNet {config.vnet_name} exists: {error}",
                    f"az network vnet show --name {config.vnet_name} "
                    f"--resource-group {config.resource_group}",
                )
            ]
        return []
    try:
        vnet = result.json()
    except ValueError:
        vnet = None
    if vnet is None and not result.text:
        return []
    if not isinstance(vnet, dict):
        return [Finding("vnet", WARN, f"could not read VNet {config.vnet_name}")]

    try:
        spaces = [ipaddress.ip_network(p, strict=False) for p in
                  (vnet.get("addressSpace") or {}).get("addressPrefixes") or []]
    except ValueError:
        return [Finding("vnet", WARN, f"could not parse the address space of {config.vnet_name}")]
    problems = []
    wanted = {
        config.worker_subnet_name: config.worker_subnet_prefix,
        config.vnet_integration_subnet_name: config.vnet_integration_subnet_prefix,
    }
    for subnet_name, prefix in wanted.items():
        net = ipaddress.ip_network(prefix, strict=False)
        if not any(net.version == s.version and net.subnet_of(s) for s in spaces):
            problems.append(f"{subnet_name} {prefix} is outside its address space "
                            f"{', '.join(str(s) for s in spaces) or '(none)'}")
    for subnet in vnet.get("subnets") or []:
        if not isinstance(subnet, dict) or subnet.get("name") not in wanted:
            continue
        have = subnet.get("addressPrefix") or ", ".join(subnet.get("addressPrefixes") or [])
        if have and have != wanted[subnet["name"]]:
            problems.append(f"existing subnet {subnet['name']} is {have}, "
                            f"config wants {wanted[subnet['name']]}")
    if problems:
        return [
            Finding(
                "vnet", FAIL,
                f"VNet {config.vnet_name} already exists in {config.resource_group} and "
                f"does not fit the config: {'; '.join(problems)}",
                "set vnet_address_prefix / worker_subnet_prefix / "
                "vnet_integration_subnet_prefix to match it, or use a different cluster_name",
            )
        ]
    return [Finding("vnet", OK, f"VNet {config.vnet_name} already exists and fits; "
                                "apply will reuse it")]


def _get_versions(az: AzCli, location: str, flag: str):
    """Return (versions, error). ``versions`` maps version -> set of channel groups.

    One version can be offered in several channel groups (D27), so keeping
    only the last one seen would misreport a valid choice.
    """
    result = az.run(
        ["aro", "hcp", "get-versions", "--location", location, flag, "--output", "json"],
        check=False, force=True,
    )
    if not result.ok:
        return None, (result.stderr.strip() or result.stdout.strip())
    try:
        payload = result.json() or []
    except ValueError:
        return None, "the response was not valid JSON"
    if not isinstance(payload, list):
        return None, "the response was not a list of versions"
    versions: dict[str, set[str]] = {}
    for entry in payload:
        if isinstance(entry, dict) and entry.get("Name"):
            versions.setdefault(entry["Name"], set()).add(entry.get("ChannelGroup", ""))
    return versions, None


def _supported_locations(error: str) -> list[str]:
    """Pull the supported-region list out of a NoRegisteredProviderFound error."""
    match = re.search(r"supported locations are '([^']+)'", error)
    if not match:
        return []
    return [part.strip() for part in match.group(1).split(",") if part.strip()]


def _empty_versions(check: str, location: str, flag: str) -> Finding:
    """An empty list is what a principal without subscription-level read gets.

    Seen live with a resource-group-scoped service principal: the call
    succeeds and returns []. Calling that "version not offered" sends the user
    after the wrong fix.
    """
    return Finding(
        check, WARN,
        f"could not list versions in {location}: the list came back empty — the "
        "principal may lack subscription-level read",
        f"grant Reader on the subscription, or check by hand: "
        f"az aro hcp get-versions --location {location} {flag}",
    )


def check_versions(az: AzCli, config: ClusterConfig) -> list[Finding]:
    """Check region availability and both version numbers in one pass.

    `get-versions` fails with NoRegisteredProviderFound in a region where ARO
    HCP is not offered, and the error names the regions that are — so this
    doubles as the region check without a hardcoded list that would go stale.
    """
    control_plane, error = _get_versions(az, config.location, "--control-plane")
    if error:
        locations = _supported_locations(error)
        if locations:
            return [
                Finding(
                    "region", FAIL,
                    f"ARO HCP is not available in {config.location}",
                    f"use one of: {', '.join(locations)}",
                )
            ]
        return [
            Finding(
                "versions", WARN,
                f"could not list OpenShift versions in {config.location}, so region and "
                f"versions are unverified: "
                f"{error.splitlines()[0][:200] if error else 'no output'}",
                f"az aro hcp get-versions --location {config.location} --control-plane",
            )
        ]

    findings = [Finding("region", OK, f"ARO HCP is available in {config.location}")]
    channel = config.channel_group

    if not control_plane:
        findings.append(_empty_versions("cluster-version", config.location, "--control-plane"))
    elif config.cluster_version not in control_plane:
        findings.append(
            Finding(
                "cluster-version", FAIL,
                f"cluster version {config.cluster_version} is not offered in "
                f"{config.location}; available: {', '.join(sorted(control_plane))}",
                "set cluster_version to one of the available versions",
            )
        )
    elif channel not in control_plane[config.cluster_version]:
        offered = sorted(control_plane[config.cluster_version])
        findings.append(
            Finding(
                "cluster-version", FAIL,
                f"cluster version {config.cluster_version} is offered in channel group(s) "
                f"{', '.join(repr(g) for g in offered)}, not {channel!r}",
                f"set channel_group to {' or '.join(repr(g) for g in offered)}",
            )
        )
    else:
        findings.append(
            Finding("cluster-version", OK, f"{config.cluster_version} ({channel}) is offered")
        )

    if config.skip_nodepool:
        return findings

    node_pools, np_error = _get_versions(az, config.location, "--node-pools")
    if np_error or node_pools is None:
        findings.append(
            Finding(
                "nodepool-version", WARN,
                f"could not list node pool versions: {(np_error or 'no output')[:200]}",
                f"az aro hcp get-versions --location {config.location} --node-pools",
            )
        )
    elif not node_pools:
        findings.append(_empty_versions("nodepool-version", config.location, "--node-pools"))
    elif channel not in node_pools.get(config.nodepool_version, set()):
        in_stream = sorted(
            v for v, groups in node_pools.items()
            if v.startswith(f"{config.cluster_version}.") and channel in groups
        )
        if config.nodepool_version in node_pools:
            offered = sorted(node_pools[config.nodepool_version])
            message = (f"node pool version {config.nodepool_version} is offered in channel "
                       f"group(s) {', '.join(repr(g) for g in offered)}, not {channel!r}")
        else:
            message = (f"node pool version {config.nodepool_version} is not offered in "
                       f"{config.location}")
        findings.append(
            Finding(
                "nodepool-version", FAIL, message,
                f"available in the {config.cluster_version} stream ({channel}): "
                f"{', '.join(in_stream) if in_stream else '(none)'}",
            )
        )
    else:
        findings.append(
            Finding("nodepool-version", OK, f"{config.nodepool_version} ({channel}) is offered")
        )
    return findings


def _vm_family(vm_size: str) -> str:
    """Map e.g. Standard_D8s_v6 -> standardDSv6Family (quota entry name).

    Compare the result case-insensitively: Azure itself returns
    ``StandardDsv6Family``. B-series v1 is the exception to the pattern — every
    Bs/Bms size draws on ``standardBSFamily``.
    """
    match = re.match(
        r"Standard_([A-Z]+)(\d+)(?:-\d+)?([a-z]*)(?:_v(\d+))?$", vm_size, re.IGNORECASE
    )
    if not match:
        return ""
    series, _cores, suffix, version = match.groups()
    if series.upper() == "B" and not version:
        return "standardBSFamily"
    tail = f"v{version}" if version else ""
    return f"standard{series.upper()}{suffix.upper()}{tail}Family"


def run_preflight(az: AzCli, config: ClusterConfig, *, deep: bool = True) -> PreflightReport:
    """Run every environment check. ``deep=False`` skips the Azure round trips."""
    report = PreflightReport()

    for problem in config.validate():
        report.add(Finding("config", FAIL, problem))
    if not report.findings:
        report.add(Finding("config", OK, "cluster configuration is valid"))

    report.add(check_az_cli(az))
    if report.findings[-1].blocking:
        return report
    # The aro extension stays required either way: preflight, and the version
    # and region checks below, read the service through it.
    report.add(check_aro_extension(az))
    if config.backend == "terraform":
        report.add(*check_terraform(config))

    if not deep:
        return report

    report.add(*check_login(az, config))
    if any(f.check == "login" and f.blocking for f in report.findings):
        return report

    # Both backends create role assignments, so both need the right to.
    report.add(check_role_assignment_permission(az, config))
    report.add(*check_providers(az, config))
    if not config.skip_nodepool:
        report.add(check_vm_sku(az, config))
    report.add(check_quota(az, config))
    report.add(*check_versions(az, config))
    report.add(*check_name_collisions(az, config))
    if config.backend == "az-cli":
        # The terraform module names its own vault and VNet.
        report.add(check_keyvault_name(az, config))
        report.add(*check_existing_vnet(az, config))
    return report
