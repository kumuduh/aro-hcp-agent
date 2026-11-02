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
_SUBSCRIPTION_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_CHANNEL_GROUP_RE = re.compile(r"^[a-z][a-z0-9-]*$")

#: Azure naming rules (Microsoft.Network). ASCII only: \w would otherwise
#: admit non-ASCII letters that the resource provider refuses.
_VNET_NAME_RE = re.compile(r"^[A-Za-z0-9][-\w.]{0,62}\w$", re.ASCII)  # 2-64
_NSG_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[-\w.]{0,78}\w)?$", re.ASCII)  # 1-80
_SUBNET_NAME_RE = _NSG_NAME_RE  # 1-80, same character rules
#: Node pool names become OpenShift machine pool IDs: a short lowercase DNS
#: label (3-15 chars). Stricter than some Azure names, but a pool the service
#: refuses after the cluster is up is a slower way to learn the same rule.
NODEPOOL_NAME_RE = re.compile(r"^[a-z][-a-z0-9]{1,13}[a-z0-9]$")

#: Channel groups the service is known to offer. Not enforced: a new group
#: should not need a release of this tool, and preflight checks the real list.
KNOWN_CHANNEL_GROUPS = ("stable", "candidate", "fast", "nightly")

#: Names derived from cluster_name in __post_init__ when not set explicitly.
#: with_overrides() re-derives exactly these, and only the ones not given.
DERIVED_NAMES = ("nsg_name", "vnet_name", "managed_resource_group", "keyvault_name")

#: Key Vault names are capped at 24 chars. A cluster name longer than this
#: has its derived vault name truncated (see ClusterConfig.warnings()).
_KEYVAULT_PREFIX_MAX = 24 - len("-kv")

#: Cluster-network defaults ARO HCP applies when the create call does not set
#: them (it does not, here). The machine network (the VNet) must not overlap
#: either; the pinned Terraform module documents the same defaults and rule.
POD_CIDR = "10.128.0.0/14"
SERVICE_CIDR = "172.30.0.0/16"

#: Field types, checked before any value check. YAML is generous with types
#: (`4.20` is a float, `"false"` is a string), and a wrong type either crashes a
#: later comparison or, worse, is truthy where the user meant false.
_STR_FIELDS = (
    "cluster_name", "location", "resource_group", "cluster_version", "nodepool_version",
    "nsg_name", "vnet_name", "worker_subnet_name", "vnet_integration_subnet_name",
    "vnet_address_prefix", "worker_subnet_prefix", "vnet_integration_subnet_prefix",
    "managed_resource_group", "channel_group", "api_visibility", "ingress_visibility",
    "keyvault_name", "kms_key_name", "vault_visibility", "nodepool_name",
    "nodepool_vm_size", "backend", "terraform_dir", "terraform_ref", "pull_secret_path",
)
_BOOL_FIELDS = ("keyvault_private_endpoint", "skip_nodepool")
_VERSION_FIELDS = ("cluster_version", "nodepool_version")

#: Environment strings accepted for boolean fields. Anything else is an error:
#: a typo such as `ture` must not quietly mean false.
_ENV_TRUE = ("1", "true", "yes", "on")
_ENV_FALSE = ("0", "false", "no", "off")

#: A cluster config is a few hundred bytes. Refuse anything far larger before
#: parsing it, rather than hand a parser an arbitrarily large file.
MAX_CONFIG_BYTES = 1024 * 1024


class ConfigError(ValueError):
    """Raised when the cluster configuration is unusable."""


def _type_problems(values: dict) -> list[str]:
    """Type-check config values (only the keys present in ``values``).

    Shared by from_dict(), which refuses a mistyped file outright, and
    validate(), which also covers configs built in code or edited by CLI
    overrides. Value checks assume these pass, so they run first.
    """
    problems: list[str] = []
    for name in _STR_FIELDS:
        if name not in values:
            continue
        value = values[name]
        if isinstance(value, str):
            continue
        if name in _VERSION_FIELDS and isinstance(value, (int, float)) \
                and not isinstance(value, bool):
            problems.append(
                f"{name} {value!r}: must be a string; quote it, e.g. {name}: \"4.22\". "
                "Unquoted, YAML reads 4.20 as the number 4.2"
            )
        else:
            problems.append(f"{name} {value!r}: must be a string, not {type(value).__name__}")
    if "subscription_id" in values:
        value = values["subscription_id"]
        if value is not None and not isinstance(value, str):
            problems.append(
                f"subscription_id {value!r}: must be a string, not {type(value).__name__}"
            )
    for name in _BOOL_FIELDS:
        if name in values and not isinstance(values[name], bool):
            problems.append(
                f"{name} {values[name]!r}: must be true or false (unquoted), not "
                f"{type(values[name]).__name__}; a quoted \"false\" would read as true"
            )
    if "nodepool_replicas" in values:
        value = values["nodepool_replicas"]
        # bool is a subclass of int; `replicas: true` is not a count.
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(
                f"nodepool_replicas {value!r}: must be a whole number, not "
                f"{type(value).__name__}"
            )
    if "tags" in values:
        tags = values["tags"]
        if not isinstance(tags, dict):
            problems.append(
                f"tags {tags!r}: must be a mapping of string keys to string values "
                "(omit the key for no tags)"
            )
        else:
            bad = [k for k, v in tags.items() if not isinstance(k, str) or not isinstance(v, str)]
            if bad:
                problems.append(
                    f"tags: keys and values must be strings (quote numbers and booleans; "
                    f"no nested mappings); offending keys: {', '.join(map(repr, bad))}"
                )
    return problems


def _parse_json(path: Path, text: str) -> object:
    def no_duplicates(pairs: list) -> dict:
        seen: dict = {}
        for key, value in pairs:
            if key in seen:
                raise ConfigError(f"{path}: duplicate key {key!r}")
            seen[key] = value
        return seen

    try:
        return json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: not valid JSON: {exc}") from exc


def _parse_yaml(path: Path, text: str) -> object:
    try:
        import yaml  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:  # pragma: no cover - pyyaml is a dependency
        raise ConfigError(
            f"{path}: PyYAML is required to read YAML config; install it or use JSON"
        ) from exc

    class StrictLoader(yaml.SafeLoader):
        """SafeLoader that refuses duplicate keys.

        PyYAML keeps the last of two identical keys, so a second
        `cluster_name:` further down a file would silently win.
        """

    def construct_mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue  # `<<:` merge keys may legitimately be overridden
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError:
                continue  # unhashable; SafeLoader raises its own error below
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        # SafeLoader subclass: python/object tags are refused, never run.
        return yaml.load(text, Loader=StrictLoader)  # noqa: S506
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: not valid YAML: {exc}") from exc


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
    #: A Red Hat pull secret (dockerconfigjson) to add to the cluster as
    #: kube-system/additional-pull-secret. Empty: the cluster gets none.
    pull_secret_path: str = ""

    # Backend selection
    backend: str = "az-cli"
    #: An existing checkout of the upstream Terraform module. Empty means
    #: clone TERRAFORM_REPO at terraform_ref into the work directory.
    terraform_dir: str = ""
    terraform_ref: str = TERRAFORM_REF

    def __post_init__(self) -> None:
        #: Derived names the caller set explicitly. A plain attribute, not a
        #: dataclass field, so it never reaches to_dict() or the config schema.
        self._explicit_names = frozenset(n for n in DERIVED_NAMES if getattr(self, n))
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
        if isinstance(self.pull_secret_path, str) and self.pull_secret_path:
            self.pull_secret_path = os.path.expanduser(self.pull_secret_path)

    def with_overrides(self, **overrides) -> "ClusterConfig":
        """Return a copy with ``overrides`` applied and derived names re-derived.

        Assigning ``config.cluster_name = "beta"`` after construction leaves
        ``alpha-kv``, ``alpha-vnet`` and friends behind, so the plan would build
        a mix of two clusters' names. This rebuilds the config instead: every
        name in DERIVED_NAMES that was derived (not set in the file, env or
        overrides) is derived again from the new values; names that were set
        explicitly are kept. ``None`` values are skipped, so argparse results
        can be passed straight through.
        """
        known = {f.name for f in fields(self)}
        unknown = set(overrides) - known
        if unknown:
            raise ConfigError(f"unknown config overrides: {', '.join(sorted(unknown))}")
        data = {f.name: getattr(self, f.name) for f in fields(self)}
        for name in DERIVED_NAMES:
            if name not in self._explicit_names:
                data[name] = ""
        data.update({k: v for k, v in overrides.items() if v is not None})
        return type(self)(**data)

    def warnings(self) -> list[str]:
        """Return non-fatal concerns; validate() stays the gate for usability.

        Kept apart from validate() because these do not make the config wrong,
        only risky: preflight (which can ask Azure) decides whether they bite.
        """
        out: list[str] = []
        if (
            "keyvault_name" not in self._explicit_names
            and isinstance(self.cluster_name, str)
            and len(self.cluster_name) > _KEYVAULT_PREFIX_MAX
        ):
            out.append(
                f"keyvault_name {self.keyvault_name!r} is cluster_name truncated to 24 "
                f"chars; any other cluster whose name starts with the same "
                f"{_KEYVAULT_PREFIX_MAX} characters derives the same (globally unique) "
                "vault name. Use a shorter cluster_name to avoid the collision"
            )
        return out

    # -- validation ---------------------------------------------------------

    def validate(self, *, teardown: bool = False) -> list[str]:
        """Return a list of problems; empty means the config is usable.

        ``teardown=True`` keeps only the checks that locate what to delete
        (names, subscription, region, backend). The rest guard a build, and a
        cluster built before one of them was added must still be deletable
        without editing its config.
        """
        problems = _type_problems({f.name: getattr(self, f.name) for f in fields(self)})
        if problems:
            # Every check below assumes the types are right.
            return problems

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
        # Azure resource group names are case-insensitive.
        if self.resource_group.lower() == self.managed_resource_group.lower():
            problems.append(
                "managed_resource_group must differ from resource_group (case-insensitively); "
                "the service creates and owns the managed group"
            )
        if not _KEYVAULT_NAME_RE.match(self.keyvault_name):
            problems.append(
                f"keyvault_name {self.keyvault_name!r}: must be 3-24 chars, alphanumeric "
                "or single hyphens, starting with a letter (and globally unique)"
            )
        if self.subscription_id is not None and not _SUBSCRIPTION_RE.match(self.subscription_id):
            problems.append(
                f"subscription_id {self.subscription_id!r}: must be a subscription GUID, "
                "e.g. '00000000-0000-0000-0000-000000000000'"
            )
        if not self.location or not self.location.islower() or " " in self.location:
            problems.append(f"location {self.location!r}: use a short region name, e.g. 'eastus'")
        problems.extend(self._validate_names(teardown=teardown))
        problems.extend(self._validate_backend(teardown=teardown))
        if teardown:
            return problems

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
        if not _CHANNEL_GROUP_RE.match(self.channel_group):
            problems.append(
                f"channel_group {self.channel_group!r}: must be a lowercase name, e.g. "
                f"one of {KNOWN_CHANNEL_GROUPS}"
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
        if self.pull_secret_path:
            from .pullsecret import PullSecretError, read  # local: pullsecret imports plan

            try:
                read(self.pull_secret_path)
            except PullSecretError as exc:
                problems.append(str(exc))
        problems.extend(self._validate_network())
        return problems

    def _validate_names(self, *, teardown: bool = False) -> list[str]:
        """Azure naming rules for the names the plan passes to `az` verbatim."""
        problems: list[str] = []
        for label, regex, rule in (
            ("vnet_name", _VNET_NAME_RE, "2-64"),
            ("nsg_name", _NSG_NAME_RE, "1-80"),
            ("worker_subnet_name", _SUBNET_NAME_RE, "1-80"),
            ("vnet_integration_subnet_name", _SUBNET_NAME_RE, "1-80"),
        ):
            value = getattr(self, label)
            if not regex.match(value):
                problems.append(
                    f"{label} {value!r}: must be {rule} chars of letters, digits, '_', "
                    "'.' or '-', starting with a letter or digit and ending with a "
                    "letter, digit or '_'"
                )
        if self.worker_subnet_name.lower() == self.vnet_integration_subnet_name.lower():
            problems.append(
                f"worker_subnet_name and vnet_integration_subnet_name are both "
                f"{self.worker_subnet_name!r}; they are two subnets and need two names"
            )
        # No teardown step names the node pool: deleting the cluster cascades it.
        if not teardown and not NODEPOOL_NAME_RE.match(self.nodepool_name):
            problems.append(
                f"nodepool_name {self.nodepool_name!r}: must be 3-15 chars, lowercase "
                "letters, digits or '-', starting with a letter and not ending in '-'"
            )
        return problems

    def _validate_backend(self, *, teardown: bool = False) -> list[str]:
        problems: list[str] = []
        if self.backend not in BACKENDS:
            problems.append(f"backend {self.backend!r}: must be one of {BACKENDS}")
            return problems
        if teardown:
            return self._validate_terraform_dir()
        if self.backend != "terraform":
            if self.vault_visibility == "Private" and not self.keyvault_private_endpoint:
                problems.append(
                    "vault_visibility 'Private' needs --keyvault-private-endpoint on the "
                    "az-cli backend; without it the Key Vault keeps public network access "
                    "and only the cluster setting says Private"
                )
            return problems
        if self.keyvault_private_endpoint:
            problems.append(
                "--keyvault-private-endpoint is not supported by the terraform "
                "backend; the upstream module has no private-endpoint variable"
            )
        elif self.vault_visibility == "Private":
            problems.append(
                "vault_visibility 'Private' is not supported by the terraform backend; "
                "the pinned module creates the Key Vault with public network access "
                "enabled regardless"
            )
        # The pinned module validates node_pools: at least one pool, and each
        # pool replicas >= 2. Live testing showed a violating config does not
        # always fail at plan time; the pool can be silently dropped instead.
        if self.skip_nodepool:
            problems.append(
                "skip_nodepool is not supported by the terraform backend; the pinned "
                "module requires at least one node pool"
            )
        elif self.nodepool_replicas < 2:
            problems.append(
                f"nodepool_replicas {self.nodepool_replicas}: the terraform backend "
                "requires >= 2 (the pinned module rejects fewer)"
            )
        problems.extend(self._validate_terraform_dir())
        return problems

    def _validate_terraform_dir(self) -> list[str]:
        problems: list[str] = []
        if self.backend == "terraform" and self.terraform_dir:
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
        nets = {}
        for label in ("vnet_address_prefix", "worker_subnet_prefix",
                      "vnet_integration_subnet_prefix"):
            value = getattr(self, label)
            try:
                nets[label] = ipaddress.ip_network(value)
            except ValueError as exc:
                return [f"network prefixes: {label} {value!r}: {exc}"]
        ipv6 = [label for label, net in nets.items() if net.version != 4]
        if ipv6:
            # ARO HCP networking is IPv4-only; this also keeps the mixed-family
            # comparisons below (which raise TypeError) from ever running.
            return [
                f"network prefixes: {', '.join(ipv6)} {'is' if len(ipv6) == 1 else 'are'} "
                "IPv6; ARO HCP supports IPv4 prefixes only"
            ]
        vnet = nets["vnet_address_prefix"]
        worker = nets["worker_subnet_prefix"]
        integration = nets["vnet_integration_subnet_prefix"]

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
                f"worker_subnet_prefix {worker} is smaller than /24; this is an aro-hcp "
                "tool constraint (room for worker nodes to scale), not an Azure limit"
            )
        # Microsoft's ARO HCP networking prerequisites (learn.microsoft.com, "Azure
        # Red Hat OpenShift with hosted control planes" virtual network
        # requirements) require the VNet integration subnet to be /28 or larger.
        if integration.prefixlen > 28:
            problems.append(
                f"vnet_integration_subnet_prefix {integration} is smaller than /28, the "
                "minimum Microsoft requires for the VNet integration subnet"
            )
        for label, cidr in (("pod CIDR", POD_CIDR), ("service CIDR", SERVICE_CIDR)):
            if vnet.overlaps(ipaddress.ip_network(cidr)):
                problems.append(
                    f"vnet_address_prefix {vnet} overlaps the default cluster {label} "
                    f"{cidr}; ARO HCP uses it for in-cluster addresses, so pick a VNet "
                    "range outside it"
                )
        return problems

    def require_valid(self, *, teardown: bool = False) -> None:
        problems = self.validate(teardown=teardown)
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
        removed = sorted(set(data) & set(REMOVED_KEYS), key=str)
        if removed:
            raise ConfigError(
                "these config keys are no longer accepted, so that one config "
                "file works with both backends:\n"
                + "\n".join(f"  - {key}: {REMOVED_KEYS[key]}" for key in removed)
            )
        known = {f.name for f in fields(cls)} - set(REMOVED_KEYS)
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"unknown config keys: {', '.join(sorted(map(str, unknown)))}")
        missing = [
            name
            for name in ("cluster_name", "location", "resource_group", "cluster_version", "nodepool_version")
            if data.get(name) is None or data.get(name) == ""
        ]
        if missing:
            raise ConfigError(f"missing required config keys: {', '.join(missing)}")
        # Refuse mistyped values here rather than let them reach validate()
        # (which would crash on a float version) or the plan (where a quoted
        # "false" is truthy and drops the node pool).
        problems = _type_problems(data)
        if problems:
            raise ConfigError(
                "invalid config value types:\n" + "\n".join(f"  - {p}" for p in problems)
            )
        return cls(**data)

    @classmethod
    def load(cls, path: str | Path) -> "ClusterConfig":
        """Load a YAML or JSON config file.

        ``.json`` (any case) is parsed as JSON; everything else, including a
        file with no extension, as YAML. Every read or parse failure becomes a
        ConfigError naming the file, so the CLI exits 2 with a message rather
        than a traceback.
        """
        path = Path(path)
        try:
            size = path.stat().st_size
            if size > MAX_CONFIG_BYTES:
                raise ConfigError(
                    f"{path}: {size} bytes is too large for a cluster config "
                    f"(limit {MAX_CONFIG_BYTES})"
                )
            text = path.read_text()
        except OSError as exc:
            raise ConfigError(f"{path}: cannot read config file: {exc.strerror or exc}") from exc
        except UnicodeDecodeError as exc:
            raise ConfigError(f"{path}: not a text file: {exc}") from exc
        if not text.strip():
            data: object = {}
        elif path.suffix.lower() == ".json":
            data = _parse_json(path, text)
        else:
            data = _parse_yaml(path, text)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: expected a mapping at the top level")
        secret = data.get("pull_secret_path")
        if isinstance(secret, str) and secret and not Path(secret).expanduser().is_absolute():
            # Relative to the config file, so the file works from any directory.
            data["pull_secret_path"] = str((path.parent / secret).resolve())
        try:
            return cls.from_dict(data)
        except ConfigError as exc:
            raise ConfigError(f"{path}: {exc}") from exc

    @classmethod
    def from_env(cls, prefix: str = "ARO_") -> "ClusterConfig":
        """Build a config from ARO_* environment variables."""
        data: dict = {}
        for f in fields(cls):
            if f.name in REMOVED_KEYS:
                continue
            var = prefix + f.name.upper()
            raw = os.environ.get(var)
            if raw is None:
                continue
            if f.type == "bool" or isinstance(getattr(cls, f.name, None), bool):
                word = raw.strip().lower()
                if word in _ENV_TRUE:
                    data[f.name] = True
                elif word in _ENV_FALSE:
                    data[f.name] = False
                else:
                    raise ConfigError(
                        f"{var}={raw!r}: not a boolean; use one of "
                        f"{', '.join(_ENV_TRUE)} or {', '.join(_ENV_FALSE)}"
                    )
            elif f.name == "nodepool_replicas":
                try:
                    data[f.name] = int(raw)
                except ValueError as exc:
                    raise ConfigError(f"{var}={raw!r}: not a whole number") from exc
            elif f.name == "tags":
                try:
                    data[f.name] = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ConfigError(
                        f"{var}: not valid JSON ({exc}); expected e.g. '{{\"team\": \"qa\"}}'"
                    ) from exc
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
