"""Cluster configuration: load, validate, derive."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

VISIBILITY = ("Public", "Private")

#: Provisioning backends. Both read this same config; they are not
#: interchangeable for one cluster, because they name resources differently.
BACKENDS = ("az-cli", "terraform")

#: The upstream Terraform module. No LICENSE file, so it is cloned at a pinned
#: ref rather than vendored into this repository.
TERRAFORM_REPO = "https://github.com/rh-mobb/validated-pattern-aro-hcp.git"
TERRAFORM_REF = "4c1d95ddf114cb90e9751a2a56e9ec7fb6251572"

#: Keys that used to be settable in cluster.yaml and no longer are, because the
#: Terraform backend cannot honour them. Rejecting them by name beats ignoring
#: them: a silently dropped key leaves the file describing a cluster you did
#: not get.
REMOVED_KEYS = {
    "keyvault_name": (
        "the vault name is derived from cluster_name; the terraform backend "
        "names it cust-kv-<random> and cannot be told otherwise"
    ),
    "kms_key_name": "the etcd key is always 'etcd-kms-key'",
    "keyvault_private_endpoint": (
        "pass --keyvault-private-endpoint instead; it is an az-cli backend "
        "feature with no terraform equivalent"
    ),
}

_CLUSTER_NAME_RE = re.compile(r"^[a-z]([-a-z0-9]{0,52}[a-z0-9])?$")
_RG_NAME_RE = re.compile(r"^[-\w._()]{1,90}$")
_KEYVAULT_NAME_RE = re.compile(r"^[a-zA-Z](?!.*--)[a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$")
_CLUSTER_VERSION_RE = re.compile(r"^\d+\.\d+$")
_NODEPOOL_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


class ConfigError(ValueError):
    """Raised when the cluster configuration is unusable."""


@dataclass
class ClusterConfig:
    # Required
    cluster_name: str
    location: str
    resource_group: str
    cluster_version: str
    nodepool_version: str

    # Subscription (resolved from `az account show` when omitted)
    subscription_id: str | None = None

    # Networking
    nsg_name: str = ""
    vnet_name: str = ""
    worker_subnet_name: str = ""
    vnet_integration_subnet_name: str = ""
    vnet_address_prefix: str = "10.0.0.0/16"
    worker_subnet_prefix: str = "10.0.0.0/24"
    vnet_integration_subnet_prefix: str = "10.0.1.0/24"

    # Cluster
    managed_resource_group: str = ""
    channel_group: str = "stable"
    api_visibility: str = "Public"
    ingress_visibility: str = "Public"

    # etcd encryption (mandatory for ARO HCP). keyvault_name, kms_key_name and
    # keyvault_private_endpoint are no longer readable from a config file — see
    # REMOVED_KEYS. They remain attributes so the az plan can template them.
    keyvault_name: str = ""
    kms_key_name: str = "etcd-kms-key"
    vault_visibility: str = "Public"
    keyvault_private_endpoint: bool = False

    # Node pool
    nodepool_name: str = "np-1"
    nodepool_replicas: int = 2
    nodepool_vm_size: str = "Standard_D8s_v6"

    # Behaviour
    skip_nodepool: bool = False
    tags: dict[str, str] = field(default_factory=dict)

    # Backend selection
    backend: str = "az-cli"
    #: An existing checkout of the upstream Terraform module. Empty means
    #: clone TERRAFORM_REPO at terraform_ref into the work directory.
    terraform_dir: str = ""
    terraform_ref: str = TERRAFORM_REF

    def __post_init__(self) -> None:
        # Derive names that default off the cluster name.
        self.nsg_name = self.nsg_name or f"{self.cluster_name}-nsg"
        self.vnet_name = self.vnet_name or f"{self.cluster_name}-vnet"
        self.worker_subnet_name = self.worker_subnet_name or "worker-subnet"
        self.vnet_integration_subnet_name = (
            self.vnet_integration_subnet_name or "vnet-integration-subnet"
        )
        self.managed_resource_group = (
            self.managed_resource_group or f"{self.cluster_name}-managed-rg"
        )
        # Key Vault names are globally unique and capped at 24 chars.
        self.keyvault_name = self.keyvault_name or f"{self.cluster_name}-kv"[:24].rstrip("-")
        if self.keyvault_private_endpoint:
            self.vault_visibility = "Private"

    # -- validation ---------------------------------------------------------

    def validate(self) -> list[str]:
        """Return a list of problems; empty means the config is usable."""
        problems: list[str] = []

        if not _CLUSTER_NAME_RE.match(self.cluster_name):
            problems.append(
                f"cluster_name {self.cluster_name!r}: must be 1-54 chars, lowercase "
                "alphanumeric or '-', starting with a letter and not ending in '-'"
            )
        for label, value in (
            ("resource_group", self.resource_group),
            ("managed_resource_group", self.managed_resource_group),
        ):
            if not _RG_NAME_RE.match(value):
                problems.append(f"{label} {value!r}: invalid Azure resource group name")
        if self.resource_group == self.managed_resource_group:
            problems.append(
                "managed_resource_group must differ from resource_group; the service "
                "creates and owns the managed group"
            )
        if not _KEYVAULT_NAME_RE.match(self.keyvault_name):
            problems.append(
                f"keyvault_name {self.keyvault_name!r}: must be 3-24 chars, alphanumeric "
                "or single hyphens, starting with a letter (and globally unique)"
            )
        if not self.location or not self.location.islower() or " " in self.location:
            problems.append(f"location {self.location!r}: use a short region name, e.g. 'eastus'")
        if not _CLUSTER_VERSION_RE.match(self.cluster_version):
            problems.append(
                f"cluster_version {self.cluster_version!r}: must be major.minor, e.g. '4.22'"
            )
        if not _NODEPOOL_VERSION_RE.match(self.nodepool_version):
            problems.append(
                f"nodepool_version {self.nodepool_version!r}: must be major.minor.patch, "
                "e.g. '4.22.1'"
            )
        elif not self.nodepool_version.startswith(f"{self.cluster_version}."):
            problems.append(
                f"nodepool_version {self.nodepool_version!r} is not in the "
                f"{self.cluster_version} stream; a node pool may not lead its cluster's "
                "minor version"
            )
        for label in ("api_visibility", "ingress_visibility", "vault_visibility"):
            value = getattr(self, label)
            if value not in VISIBILITY:
                problems.append(f"{label} {value!r}: must be one of {VISIBILITY}")
        if self.keyvault_private_endpoint and self.vault_visibility != "Private":
            problems.append(
                "keyvault_private_endpoint requires vault_visibility 'Private'; the Key "
                "Vault network config and the cluster setting must match"
            )
        if self.nodepool_replicas < 1:
            problems.append(f"nodepool_replicas {self.nodepool_replicas}: must be >= 1")

        problems.extend(self._validate_backend())
        problems.extend(self._validate_network())
        return problems

    def _validate_backend(self) -> list[str]:
        problems: list[str] = []
        if self.backend not in BACKENDS:
            problems.append(f"backend {self.backend!r}: must be one of {BACKENDS}")
            return problems
        if self.backend != "terraform":
            return problems
        if self.keyvault_private_endpoint:
            problems.append(
                "--keyvault-private-endpoint is not supported by the terraform "
                "backend; the upstream module has no private-endpoint variable"
            )
        if self.terraform_dir:
            root = Path(self.terraform_dir)
            if not root.is_dir():
                problems.append(f"terraform_dir {self.terraform_dir!r}: not a directory")
            elif not (root / "variables.tf").is_file():
                problems.append(
                    f"terraform_dir {self.terraform_dir!r}: no variables.tf — point this "
                    "at the module root (the `terraform/` directory of the upstream repo)"
                )
        return problems

    def _validate_network(self) -> list[str]:
        problems: list[str] = []
        try:
            vnet = ipaddress.ip_network(self.vnet_address_prefix)
            worker = ipaddress.ip_network(self.worker_subnet_prefix)
            integration = ipaddress.ip_network(self.vnet_integration_subnet_prefix)
        except ValueError as exc:
            return [f"network prefixes: {exc}"]

        for label, subnet in (
            ("worker_subnet_prefix", worker),
            ("vnet_integration_subnet_prefix", integration),
        ):
            if not subnet.subnet_of(vnet):  # type: ignore[arg-type]
                problems.append(
                    f"{label} {subnet} is not inside vnet_address_prefix {vnet}"
                )
        if worker.overlaps(integration):
            problems.append(
                f"worker_subnet_prefix {worker} overlaps "
                f"vnet_integration_subnet_prefix {integration}"
            )
        if worker.prefixlen > 24:
            problems.append(
                f"worker_subnet_prefix {worker} is smaller than /24; worker nodes need "
                "room to scale"
            )
        return problems

    def require_valid(self) -> None:
        problems = self.validate()
        if problems:
            raise ConfigError(
                "invalid cluster configuration:\n"
                + "\n".join(f"  - {p}" for p in problems)
            )

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ClusterConfig":
        removed = sorted(set(data) & set(REMOVED_KEYS))
        if removed:
            raise ConfigError(
                "these config keys are no longer accepted, so that one config "
                "file works with both backends:\n"
                + "\n".join(f"  - {key}: {REMOVED_KEYS[key]}" for key in removed)
            )
        known = {f.name for f in fields(cls)} - set(REMOVED_KEYS)
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")
        missing = [
            name
            for name in ("cluster_name", "location", "resource_group", "cluster_version", "nodepool_version")
            if not data.get(name)
        ]
        if missing:
            raise ConfigError(f"missing required config keys: {', '.join(missing)}")
        return cls(**data)

    @classmethod
    def load(cls, path: str | Path) -> "ClusterConfig":
        path = Path(path)
        text = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore[import-untyped]
            except ModuleNotFoundError as exc:  # pragma: no cover - optional dep
                raise ConfigError(
                    "PyYAML is required to read YAML config; install it or use JSON"
                ) from exc
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: expected a mapping at the top level")
        return cls.from_dict(data)

    @classmethod
    def from_env(cls, prefix: str = "ARO_") -> "ClusterConfig":
        """Build a config from ARO_* environment variables."""
        data: dict = {}
        for f in fields(cls):
            if f.name in REMOVED_KEYS:
                continue
            raw = os.environ.get(prefix + f.name.upper())
            if raw is None:
                continue
            if f.type == "bool" or isinstance(getattr(cls, f.name, None), bool):
                data[f.name] = raw.strip().lower() in ("1", "true", "yes", "on")
            elif f.name == "nodepool_replicas":
                data[f.name] = int(raw)
            elif f.name == "tags":
                data[f.name] = json.loads(raw)
            else:
                data[f.name] = raw
        return cls.from_dict(data)

    # -- derived values -----------------------------------------------------

    def identity_name(self, suffix: str) -> str:
        return f"{self.cluster_name}-{suffix}"

    def base_context(self) -> dict[str, str]:
        """Template variables available to every plan step."""
        return {
            "CLUSTER_NAME": self.cluster_name,
            "LOCATION": self.location,
            "CUSTOMER_RG_NAME": self.resource_group,
            "MANAGED_RESOURCE_GROUP": self.managed_resource_group,
            "SUBSCRIPTION_ID": self.subscription_id or "",
            "CUSTOMER_NSG": self.nsg_name,
            "CUSTOMER_VNET_NAME": self.vnet_name,
            "CUSTOMER_VNET_SUBNET1": self.worker_subnet_name,
            "CUSTOMER_VNET_INTEGRATION_SUBNET_NAME": self.vnet_integration_subnet_name,
            "KEYVAULT_NAME": self.keyvault_name,
            "KMS_KEY_NAME": self.kms_key_name,
            "NP_NAME": self.nodepool_name,
            "CLUSTER_VERSION": self.cluster_version,
            "NP_VERSION": self.nodepool_version,
        }
