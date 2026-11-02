"""The provisioning plan: an ordered, resumable list of `az` steps.

Steps are templates. ``${NAME}`` placeholders are substituted from the run
context at execution time, so a plan can be rendered and reviewed before any
resource IDs exist. ``${...}`` syntax (not ``{...}``) is deliberate: the
``--kms-active-key`` argument contains literal braces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from string import Template

from .azure import DEFAULT_TIMEOUT, LONG_TIMEOUT
from .config import ClusterConfig
from . import roles

PHASES = (
    "providers",
    "resource-group",
    "network",
    "identities",
    "role-assignments",
    "etcd-encryption",
    "cluster",
    "nodepool",
    "pull-secret",
)


@dataclass
class Step:
    id: str
    phase: str
    description: str
    args: list[str]
    #: Read-only command proving the resource exists. For a create, non-empty
    #: stdout means "already done". For a delete the sense is inverted: empty
    #: stdout means the resource is already gone. See ``deletes``.
    exists: list[str] | None = None
    #: True for teardown steps, which inverts the ``exists`` probe.
    deletes: bool = False
    #: Variable name to populate from this step's stdout (used with --query/tsv).
    capture: str | None = None
    #: Post-processing for the captured value. "basename" keeps the last path
    #: segment. Needed because `az` returns the Key Vault key version only as
    #: part of a full key identifier URL, and JMESPath has no split().
    capture_transform: str | None = None
    #: Variables this step must be able to resolve before it can run.
    requires: tuple[str, ...] = ()
    timeout: int = DEFAULT_TIMEOUT
    #: False for pure lookups — they never change anything and never prompt.
    mutating: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)
    #: Which runner executes this step: "az" or "terraform".
    runner: str = "az"
    #: Name of an in-process action instead of a subprocess — see
    #: ``terraform.ACTIONS``. Set this and ``args`` is only for display.
    action: str | None = None
    #: For a create whose probe returns a provisioning state: only these
    #: values mean "done". Anything else non-empty is either in progress
    #: (waited for) or terminal (a failure). Without this, a cluster in
    #: ``Failed`` or ``Provisioning`` counted as already created.
    ready_states: tuple[str, ...] = ()
    #: Step ids whose resources must be in place (for a create) or gone (for
    #: a delete) before this step may run. Checked against state, then against
    #: Azure, so a phase-scoped run cannot skip ahead — e.g. purge the KMS
    #: vault while the cluster that uses it still exists.
    after: tuple[str, ...] = ()
    #: Re-run on every invocation even when recorded complete. For cheap,
    #: non-mutating steps whose output must be current (reads, terraform plan).
    always: bool = False
    #: Expected probe output for an existing resource. A resource that exists
    #: with different settings (another prefix, no delegation) is a conflict,
    #: not something to skip past.
    expect: str | None = None

    def render(self, context: dict[str, str]) -> list[str]:
        return [Template(a).safe_substitute(context) for a in self.args]

    def render_exists(self, context: dict[str, str]) -> list[str] | None:
        if self.exists is None:
            return None
        return [Template(a).safe_substitute(context) for a in self.exists]

    def unresolved(self, context: dict[str, str]) -> list[str]:
        return [name for name in self.requires if not context.get(name)]


def _rg() -> list[str]:
    return ["--resource-group", "${CUSTOMER_RG_NAME}"]


#: Provisioning states that mean a long-running create has not finished yet.
IN_PROGRESS_STATES = ("Accepted", "Provisioning", "Updating", "Creating")


def _tags(config: ClusterConfig) -> list[str]:
    """``--tags`` for every create that supports it.

    The terraform backend always rendered config tags; this backend silently
    dropped them, so a cleanup policy keyed on tags could not find its
    resources.
    """
    if not config.tags:
        return []
    return ["--tags", *(f"{key}={value}" for key, value in config.tags.items())]


def _identity_steps(prefix: str, suffix: str, phase: str, tags: list[str] = ()) -> list[Step]:
    """Create one managed identity and capture the IDs the plan needs."""
    steps = [
        Step(
            id=f"identity-create-{suffix}",
            phase=phase,
            description=f"Create managed identity {suffix}",
            args=["identity", "create", "--name", f"${{CLUSTER_NAME}}-{suffix}", *_rg(),
                  "--location", "${LOCATION}", *tags],
            exists=["identity", "show", "--name", f"${{CLUSTER_NAME}}-{suffix}", *_rg(),
                    "--query", "id", "--output", "tsv"],
        ),
        Step(
            id=f"identity-id-{suffix}",
            phase=phase,
            description=f"Read resource ID of {suffix}",
            args=["identity", "show", "--name", f"${{CLUSTER_NAME}}-{suffix}", *_rg(),
                  "--query", "id", "--output", "tsv"],
            capture=f"{prefix}_MI_ID",
            mutating=False,
            always=True,
        ),
    ]
    if prefix in roles.PRINCIPAL_ID_NEEDED:
        steps.append(
            Step(
                id=f"identity-pid-{suffix}",
                phase=phase,
                description=f"Read principal ID of {suffix}",
                args=["identity", "show", "--name", f"${{CLUSTER_NAME}}-{suffix}", *_rg(),
                      "--query", "principalId", "--output", "tsv"],
                capture=f"{prefix}_MI_PID",
                mutating=False,
                always=True,
            )
        )
    return steps


def _role_assignment_step(
    index: int, principal_var: str, role: str, scope_var: str, label: str, phase: str
) -> Step:
    return Step(
        id=f"role-{phase}-{index:02d}",
        phase=phase,
        description=f"Assign {roles.ROLE_NAMES[role]}: {label}",
        args=[
            "role", "assignment", "create",
            "--assignee-object-id", f"${{{principal_var}}}",
            "--assignee-principal-type", "ServicePrincipal",
            "--role", role,
            "--scope", f"${{{scope_var}}}",
        ],
        exists=[
            "role", "assignment", "list",
            "--assignee-object-id", f"${{{principal_var}}}",
            "--role", role,
            "--scope", f"${{{scope_var}}}",
            "--query", "[0].id", "--output", "tsv",
        ],
        requires=(principal_var, scope_var),
        tags=("role-assignment",),
    )


def build_plan(config: ClusterConfig) -> list[Step]:
    """Return the full ordered provisioning plan for ``config``."""
    steps: list[Step] = []
    tags = _tags(config)

    # -- resource providers -------------------------------------------------
    for provider in roles.REQUIRED_RESOURCE_PROVIDERS:
        steps.append(
            Step(
                id=f"provider-{provider.split('.')[-1].lower()}",
                phase="providers",
                description=f"Register resource provider {provider}",
                args=["provider", "register", "--namespace", provider, "--wait"],
                exists=[
                    "provider", "show", "--namespace", provider,
                    "--query", "registrationState == 'Registered' && 'Registered' || ''",
                    "--output", "tsv",
                ],
                timeout=900,
            )
        )

    # -- resource group -----------------------------------------------------
    steps.append(
        Step(
            id="resource-group",
            phase="resource-group",
            description="Create the customer resource group",
            args=["group", "create", "--name", "${CUSTOMER_RG_NAME}",
                  "--location", "${LOCATION}", *tags],
            exists=["group", "show", "--name", "${CUSTOMER_RG_NAME}",
                    "--query", "id", "--output", "tsv"],
        )
    )

    # -- network ------------------------------------------------------------
    steps += [
        Step(
            id="nsg-create",
            phase="network",
            description="Create the network security group",
            args=["network", "nsg", "create", "--name", "${CUSTOMER_NSG}", *_rg(),
                  "--location", "${LOCATION}", *tags],
            exists=["network", "nsg", "show", "--name", "${CUSTOMER_NSG}", *_rg(),
                    "--query", "id", "--output", "tsv"],
        ),
        Step(
            id="vnet-create",
            phase="network",
            description="Create the VNet and worker subnet",
            args=["network", "vnet", "create", "--name", "${CUSTOMER_VNET_NAME}", *_rg(),
                  "--location", "${LOCATION}",
                  "--address-prefixes", config.vnet_address_prefix,
                  "--subnet-name", "${CUSTOMER_VNET_SUBNET1}",
                  "--subnet-prefixes", config.worker_subnet_prefix,
                  "--nsg", "${CUSTOMER_NSG}", *tags],
            exists=["network", "vnet", "show", "--name", "${CUSTOMER_VNET_NAME}", *_rg(),
                    "--query", "addressSpace.addressPrefixes[0]", "--output", "tsv"],
            expect=config.vnet_address_prefix,
        ),
        Step(
            id="vnet-integration-subnet",
            phase="network",
            description="Create the delegated VNet integration subnet",
            args=["network", "vnet", "subnet", "create",
                  "--name", "${CUSTOMER_VNET_INTEGRATION_SUBNET_NAME}",
                  "--vnet-name", "${CUSTOMER_VNET_NAME}", *_rg(),
                  "--address-prefixes", config.vnet_integration_subnet_prefix,
                  "--delegations", roles.VNET_INTEGRATION_DELEGATION],
            exists=["network", "vnet", "subnet", "show",
                    "--name", "${CUSTOMER_VNET_INTEGRATION_SUBNET_NAME}",
                    "--vnet-name", "${CUSTOMER_VNET_NAME}", *_rg(),
                    "--query", "join(' ', [addressPrefix || addressPrefixes[0], delegations[0].serviceName || 'none'])",
                    "--output", "tsv"],
            expect=f"{config.vnet_integration_subnet_prefix} {roles.VNET_INTEGRATION_DELEGATION}",
        ),
        Step(
            id="nsg-id",
            phase="network",
            description="Read the NSG resource ID",
            args=["network", "nsg", "show", "--name", "${CUSTOMER_NSG}", *_rg(),
                  "--query", "id", "--output", "tsv"],
            capture="NSG_ID",
            mutating=False,
            always=True,
        ),
        Step(
            id="vnet-id",
            phase="network",
            description="Read the VNet resource ID",
            args=["network", "vnet", "show", "--name", "${CUSTOMER_VNET_NAME}", *_rg(),
                  "--query", "id", "--output", "tsv"],
            capture="VNET_ID",
            mutating=False,
            always=True,
        ),
        Step(
            id="worker-subnet-id",
            phase="network",
            description="Read the worker subnet resource ID",
            args=["network", "vnet", "subnet", "show", "--name", "${CUSTOMER_VNET_SUBNET1}",
                  "--vnet-name", "${CUSTOMER_VNET_NAME}", *_rg(),
                  "--query", "id", "--output", "tsv"],
            capture="SUBNET_ID",
            mutating=False,
            always=True,
        ),
        Step(
            id="integration-subnet-id",
            phase="network",
            description="Read the VNet integration subnet resource ID",
            args=["network", "vnet", "subnet", "show",
                  "--name", "${CUSTOMER_VNET_INTEGRATION_SUBNET_NAME}",
                  "--vnet-name", "${CUSTOMER_VNET_NAME}", *_rg(),
                  "--query", "id", "--output", "tsv"],
            capture="VNET_INTEGRATION_SUBNET_ID",
            mutating=False,
            always=True,
        ),
    ]

    # -- managed identities -------------------------------------------------
    for _key, suffix, prefix in roles.CONTROL_PLANE_IDENTITIES:
        steps += _identity_steps(prefix, suffix, "identities", tags)
    for _key, suffix, prefix in roles.DATA_PLANE_IDENTITIES:
        steps += _identity_steps(prefix, suffix, "identities", tags)
    service_suffix, service_prefix = roles.SERVICE_IDENTITY
    steps += _identity_steps(service_prefix, service_suffix, "identities", tags)
    kms_suffix, kms_prefix = roles.KMS_IDENTITY
    steps += _identity_steps(kms_prefix, kms_suffix, "identities", tags)

    # -- role assignments ---------------------------------------------------
    assignments = (
        roles.CONTROL_PLANE_ROLE_ASSIGNMENTS
        + roles.SERVICE_ROLE_ASSIGNMENTS
        + roles.DATA_PLANE_ROLE_ASSIGNMENTS
        + [("SERVICE_MI_PID", roles.READER_ROLE, "KMS_MI_ID", "service MI reader on KMS identity")]
    )
    for index, (principal, role, scope, label) in enumerate(assignments, start=1):
        steps.append(
            _role_assignment_step(index, principal, role, scope, label, "role-assignments")
        )

    # -- etcd encryption ----------------------------------------------------
    steps += [
        Step(
            id="keyvault-create",
            phase="etcd-encryption",
            description="Create the Key Vault (RBAC authorization)",
            args=["keyvault", "create", "--name", "${KEYVAULT_NAME}", *_rg(),
                  "--location", "${LOCATION}", "--enable-rbac-authorization", "true", *tags],
            exists=["keyvault", "show", "--name", "${KEYVAULT_NAME}", *_rg(),
                    "--query", "id", "--output", "tsv"],
            timeout=600,
            # Billed per operation; listed so the confirmation summary names it.
            tags=("billable",),
        ),
        Step(
            id="keyvault-id",
            phase="etcd-encryption",
            description="Read the Key Vault resource ID",
            args=["keyvault", "show", "--name", "${KEYVAULT_NAME}", *_rg(),
                  "--query", "id", "--output", "tsv"],
            capture="KEYVAULT_ID",
            mutating=False,
            always=True,
        ),
        Step(
            id="keyvault-crypto-officer",
            phase="etcd-encryption",
            description="Grant the signed-in principal Key Vault Crypto Officer",
            # By object id and type, which needs no Graph lookup: a managed
            # identity login usually has no Graph read permission.
            args=["role", "assignment", "create", "--role", "Key Vault Crypto Officer",
                  "--assignee-object-id", "${SIGNED_IN_USER}",
                  "--assignee-principal-type", "${SIGNED_IN_PRINCIPAL_TYPE}",
                  "--scope", "${KEYVAULT_ID}"],
            exists=["role", "assignment", "list", "--assignee-object-id", "${SIGNED_IN_USER}",
                    "--role", "Key Vault Crypto Officer", "--scope", "${KEYVAULT_ID}",
                    "--query", "[0].id", "--output", "tsv"],
            requires=("SIGNED_IN_USER", "SIGNED_IN_PRINCIPAL_TYPE", "KEYVAULT_ID"),
            tags=("role-assignment",),
        ),
        Step(
            id="kms-key-create",
            phase="etcd-encryption",
            description="Create the RSA 2048 etcd encryption key",
            args=["keyvault", "key", "create", "--vault-name", "${KEYVAULT_NAME}",
                  "--name", "${KMS_KEY_NAME}", "--kty", "RSA", "--size", "2048"],
            exists=["keyvault", "key", "show", "--vault-name", "${KEYVAULT_NAME}",
                    "--name", "${KMS_KEY_NAME}", "--query", "key.kid", "--output", "tsv"],
        ),
        Step(
            id="kms-key-version",
            phase="etcd-encryption",
            description="Read the active KMS key version",
            args=["keyvault", "key", "show", "--vault-name", "${KEYVAULT_NAME}",
                  "--name", "${KMS_KEY_NAME}", "--query", "key.kid", "--output", "tsv"],
            capture="KMS_KEY_VERSION",
            capture_transform="basename",
            mutating=False,
            always=True,
        ),
        _role_assignment_step(
            99, "KMS_MI_PID", roles.KEY_VAULT_CRYPTO_USER_ROLE, "KEYVAULT_ID",
            "KMS identity on Key Vault", "etcd-encryption",
        ),
    ]

    if config.keyvault_private_endpoint:
        steps += [
            Step(
                id="keyvault-disable-public",
                phase="etcd-encryption",
                description="Disable public network access on the Key Vault",
                args=["keyvault", "update", "--name", "${KEYVAULT_NAME}", *_rg(),
                      "--public-network-access", "Disabled"],
            ),
            Step(
                id="keyvault-private-endpoint",
                phase="etcd-encryption",
                description="Create the Key Vault private endpoint",
                args=["network", "private-endpoint", "create", "--name", "kv-private-endpoint",
                      *_rg(), "--location", "${LOCATION}",
                      "--vnet-name", "${CUSTOMER_VNET_NAME}",
                      "--subnet", "${CUSTOMER_VNET_SUBNET1}",
                      "--private-connection-resource-id", "${KEYVAULT_ID}",
                      "--group-ids", "vault", "--connection-name", "kv-private-endpoint", *tags],
                exists=["network", "private-endpoint", "show", "--name", "kv-private-endpoint",
                        *_rg(), "--query", "id", "--output", "tsv"],
                requires=("KEYVAULT_ID",),
                tags=("billable",),
            ),
            Step(
                id="keyvault-dns-zone",
                phase="etcd-encryption",
                description="Create the Key Vault private DNS zone",
                args=["network", "private-dns", "zone", "create",
                      "--name", roles.KEYVAULT_PRIVATE_DNS_ZONE, *_rg(), *tags],
                exists=["network", "private-dns", "zone", "show",
                        "--name", roles.KEYVAULT_PRIVATE_DNS_ZONE, *_rg(),
                        "--query", "id", "--output", "tsv"],
                tags=("billable",),
            ),
            Step(
                id="keyvault-dns-link",
                phase="etcd-encryption",
                description="Link the private DNS zone to the VNet",
                args=["network", "private-dns", "link", "vnet", "create",
                      "--name", "kv-private-dns-zone-link", *_rg(),
                      "--zone-name", roles.KEYVAULT_PRIVATE_DNS_ZONE,
                      "--virtual-network", "${CUSTOMER_VNET_NAME}",
                      "--registration-enabled", "false"],
                exists=["network", "private-dns", "link", "vnet", "show",
                        "--name", "kv-private-dns-zone-link", *_rg(),
                        "--zone-name", roles.KEYVAULT_PRIVATE_DNS_ZONE,
                        "--query", "id", "--output", "tsv"],
            ),
            Step(
                id="keyvault-dns-zone-group",
                phase="etcd-encryption",
                description="Attach the DNS zone group to the private endpoint",
                args=["network", "private-endpoint", "dns-zone-group", "create",
                      "--name", "kv-private-ep-dns-group", *_rg(),
                      "--endpoint-name", "kv-private-endpoint",
                      "--private-dns-zone", roles.KEYVAULT_PRIVATE_DNS_ZONE,
                      "--zone-name", "config1"],
                exists=["network", "private-endpoint", "dns-zone-group", "show",
                        "--name", "kv-private-ep-dns-group", *_rg(),
                        "--endpoint-name", "kv-private-endpoint",
                        "--query", "id", "--output", "tsv"],
            ),
        ]

    # -- cluster ------------------------------------------------------------
    cluster_args = [
        "aro", "hcp", "cluster", "create",
        "--name", "${CLUSTER_NAME}", *_rg(),
        "--location", "${LOCATION}",
        "--version", "${CLUSTER_VERSION}",
        "--channel-group", config.channel_group,
        "--subnet-id", "${SUBNET_ID}",
        "--vnet-integration-subnet-id", "${VNET_INTEGRATION_SUBNET_ID}",
        "--nsg", "${NSG_ID}",
        "--managed-resource-group-name", "${MANAGED_RESOURCE_GROUP}",
        "--kms-vault-name", "${KEYVAULT_NAME}",
        "--vault-visibility", config.vault_visibility,
        "--kms-active-key", "{name:${KMS_KEY_NAME},version:${KMS_KEY_VERSION}}",
        "--api-visibility", config.api_visibility,
        "--ingress-visibility", config.ingress_visibility,
        "--assign-service-managed-identity", "${SERVICE_MI_ID}",
        *tags,
    ]
    cluster_requires = [
        "SUBNET_ID", "VNET_INTEGRATION_SUBNET_ID", "NSG_ID",
        "KMS_KEY_VERSION", "SERVICE_MI_ID",
    ]
    for key, _suffix, prefix in roles.CONTROL_PLANE_IDENTITIES:
        cluster_args += ["--assign-control-plane-operator-identity", key, f"${{{prefix}_MI_ID}}"]
        cluster_requires.append(f"{prefix}_MI_ID")
    cluster_args += ["--assign-control-plane-operator-identity", "kms", "${KMS_MI_ID}"]
    cluster_requires.append("KMS_MI_ID")
    for key, _suffix, prefix in roles.DATA_PLANE_IDENTITIES:
        cluster_args += ["--assign-data-plane-operator-identity", key, f"${{{prefix}_MI_ID}}"]
        cluster_requires.append(f"{prefix}_MI_ID")

    steps.append(
        Step(
            id="cluster-create",
            phase="cluster",
            description="Create the ARO HCP cluster (15-20 minutes)",
            args=cluster_args,
            exists=["aro", "hcp", "cluster", "show", "--name", "${CLUSTER_NAME}", *_rg(),
                    "--query", "properties.provisioningState", "--output", "tsv"],
            requires=tuple(cluster_requires),
            timeout=LONG_TIMEOUT,
            tags=("billable", "long-running"),
            ready_states=("Succeeded",),
        )
    )
    steps.append(
        Step(
            id="cluster-state",
            phase="cluster",
            description="Read the cluster provisioning state",
            args=["aro", "hcp", "cluster", "show", "--name", "${CLUSTER_NAME}", *_rg(),
                  "--query", "properties.provisioningState", "--output", "tsv"],
            capture="CLUSTER_PROVISIONING_STATE",
            mutating=False,
        )
    )

    # -- node pool ----------------------------------------------------------
    if not config.skip_nodepool:
        steps += [
            Step(
                id="nodepool-create",
                phase="nodepool",
                description=(
                    f"Create node pool {config.nodepool_name} "
                    f"({config.nodepool_replicas} x {config.nodepool_vm_size})"
                ),
                args=["aro", "hcp", "cluster", "nodepool", "create",
                      "--cluster-name", "${CLUSTER_NAME}", "--name", "${NP_NAME}", *_rg(),
                      # Explicit, because `az configure --defaults location=`
                      # otherwise wins over the resource group's location and
                      # sends the node pool to a region the RP does not serve.
                      "--location", "${LOCATION}",
                      "--replicas", str(config.nodepool_replicas),
                      "--vm-size", config.nodepool_vm_size,
                      "--version", "${NP_VERSION}",
                      "--channel-group", config.channel_group, *tags],
                exists=["aro", "hcp", "cluster", "nodepool", "show",
                        "--cluster-name", "${CLUSTER_NAME}", "--name", "${NP_NAME}", *_rg(),
                        "--query", "properties.provisioningState", "--output", "tsv"],
                timeout=LONG_TIMEOUT,
                tags=("billable", "long-running"),
                ready_states=("Succeeded",),
                # The RP rejects a node pool while its cluster is still
                # provisioning (Conflict), and the create step itself carries
                # no resource-ID dependency on the cluster to stop it.
                after=("cluster-create",),
            ),
            Step(
                id="nodepool-state",
                phase="nodepool",
                description="Read the node pool provisioning state",
                args=["aro", "hcp", "cluster", "nodepool", "show",
                      "--cluster-name", "${CLUSTER_NAME}", "--name", "${NP_NAME}", *_rg(),
                      "--query", "properties.provisioningState", "--output", "tsv"],
                capture="NODEPOOL_PROVISIONING_STATE",
                mutating=False,
            ),
        ]

    # -- pull secret ----------------------------------------------------------
    if config.pull_secret_path:
        from .pullsecret import build_step  # local: pullsecret imports Step

        after = ("cluster-create",) if config.skip_nodepool else ("cluster-create",
                                                                 "nodepool-create")
        steps.append(build_step(config, after=after))

    return steps
