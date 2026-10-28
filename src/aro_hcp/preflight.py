"""Environment checks that run before anything is created.

Each check returns a Finding. ``blocking=True`` means apply should not start.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field

from .azure import AzCli
from .config import ClusterConfig
from . import roles

OK = "ok"
WARN = "warn"
FAIL = "fail"


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
    if user:
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


def check_quota(az: AzCli, config: ClusterConfig) -> Finding:
    """Compare available cores in the node pool's VM family against the minimum."""
    family = _vm_family(config.nodepool_vm_size)
    result = az.run(
        ["vm", "list-usage", "--location", config.location, "--output", "json"],
        check=False, force=True,
    )
    if not result.ok or not result.text:
        return Finding(
            "quota", WARN,
            f"could not read VM quota for {config.location}",
            f"az vm list-usage -l {config.location} -o table",
        )
    try:
        usages = result.json() or []
    except ValueError:
        return Finding("quota", WARN, "could not parse the VM quota response")

    match = None
    for usage in usages:
        name = (usage.get("name") or {}).get("value", "")
        if family and family.lower() in name.lower():
            match = usage
            break
    if match is None:
        return Finding(
            "quota", WARN,
            f"no quota entry found matching VM family {family!r} in {config.location}",
        )
    limit = int(match.get("limit", 0))
    current = int(match.get("currentValue", 0))
    available = limit - current
    needed = roles.MIN_CORES
    name = (match.get("name") or {}).get("value", family)
    if available < needed:
        return Finding(
            "quota", FAIL,
            f"{name}: {available} of {limit} cores available in {config.location}, "
            f"ARO HCP needs at least {needed}",
            "request a quota increase: "
            "https://learn.microsoft.com/azure/azure-portal/supportability/per-vm-quota-requests",
        )
    return Finding("quota", OK, f"{name}: {available} of {limit} cores available")


def check_name_collisions(az: AzCli, config: ClusterConfig) -> list[Finding]:
    findings = []
    existing = az.run(
        ["aro", "hcp", "cluster", "show", "--name", config.cluster_name,
         "--resource-group", config.resource_group,
         "--query", "properties.provisioningState", "--output", "tsv"],
        check=False, force=True,
    )
    if existing.ok and existing.text:
        findings.append(
            Finding(
                "cluster-exists", WARN,
                f"cluster {config.cluster_name} already exists in {config.resource_group} "
                f"(state: {existing.text}); apply will skip creation and resume",
            )
        )
    managed = az.run(
        ["group", "show", "--name", config.managed_resource_group,
         "--query", "id", "--output", "tsv"],
        check=False, force=True,
    )
    if managed.ok and managed.text and not (existing.ok and existing.text):
        findings.append(
            Finding(
                "managed-rg", FAIL,
                f"managed resource group {config.managed_resource_group} already exists "
                "but no cluster owns it; cluster creation will fail",
                "delete the group or choose a different managed_resource_group",
            )
        )
    return findings


def _get_versions(az: AzCli, location: str, flag: str):
    """Return (versions, error). ``versions`` maps version -> channel group."""
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
    versions = {}
    for entry in payload:
        if isinstance(entry, dict) and entry.get("Name"):
            versions[entry["Name"]] = entry.get("ChannelGroup", "")
    return versions, None


def _supported_locations(error: str) -> list[str]:
    """Pull the supported-region list out of a NoRegisteredProviderFound error."""
    match = re.search(r"supported locations are '([^']+)'", error)
    if not match:
        return []
    return [part.strip() for part in match.group(1).split(",") if part.strip()]


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
                f"could not list OpenShift versions in {config.location}: "
                f"{error.splitlines()[0][:200] if error else 'no output'}",
                f"az aro hcp get-versions --location {config.location} --control-plane",
            )
        ]

    findings = [Finding("region", OK, f"ARO HCP is available in {config.location}")]

    if not control_plane:
        findings.append(Finding("versions", WARN, "the control plane version list is empty"))
    elif config.cluster_version not in control_plane:
        findings.append(
            Finding(
                "cluster-version", FAIL,
                f"cluster version {config.cluster_version} is not offered in "
                f"{config.location}; available: {', '.join(sorted(control_plane))}",
                "set cluster_version to one of the available versions",
            )
        )
    elif control_plane[config.cluster_version] != config.channel_group:
        findings.append(
            Finding(
                "cluster-version", FAIL,
                f"cluster version {config.cluster_version} is offered in channel group "
                f"{control_plane[config.cluster_version]!r}, not {config.channel_group!r}",
                f"set channel_group to {control_plane[config.cluster_version]!r}",
            )
        )
    else:
        findings.append(
            Finding("cluster-version", OK,
                    f"{config.cluster_version} ({config.channel_group}) is offered")
        )

    if config.skip_nodepool:
        return findings

    node_pools, np_error = _get_versions(az, config.location, "--node-pools")
    if np_error or node_pools is None:
        findings.append(Finding("nodepool-version", WARN,
                                "could not list node pool versions"))
    elif config.nodepool_version not in node_pools:
        in_stream = sorted(
            v for v in node_pools if v.startswith(f"{config.cluster_version}.")
        )
        findings.append(
            Finding(
                "nodepool-version", FAIL,
                f"node pool version {config.nodepool_version} is not offered in "
                f"{config.location}",
                f"available in the {config.cluster_version} stream: "
                f"{', '.join(in_stream) if in_stream else '(none)'}",
            )
        )
    else:
        findings.append(
            Finding("nodepool-version", OK, f"{config.nodepool_version} is offered")
        )
    return findings


def _vm_family(vm_size: str) -> str:
    """Map e.g. Standard_D8s_v6 -> standardDSv6Family (quota entry name)."""
    match = re.match(r"Standard_([A-Z]+)(\d+)([a-z]*)(?:_v(\d+))?", vm_size, re.IGNORECASE)
    if not match:
        return ""
    series, _cores, suffix, version = match.groups()
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

    report.add(*check_providers(az, config))
    report.add(check_quota(az, config))
    report.add(*check_versions(az, config))
    report.add(*check_name_collisions(az, config))
    return report
