"""The teardown plan: everything ``build_plan`` creates, removed in reverse.

Ordering is not cosmetic. The cluster must go before the Key Vault holding its
etcd encryption key, or the control plane loses the key it is still using; the
VNet must go before the NSG attached to its subnet; and the resource group
goes last.

The Key Vault private endpoint and its DNS zone are deleted explicitly before
the VNet, because they block the VNet delete and teardown would otherwise stop
there with everything after it still billing.

Node pools are the exception to "reverse the build": they are not deleted at
all. OCPBUGS-86702 — the resource provider rejects DELETE of a cluster's last
node pool, and this tool only ever creates one, so the request could never
succeed. Deleting the cluster cascades its node pools, which is what the
terraform backend relies on too.

Resource providers are never unregistered — they are subscription-wide and
other workloads depend on them.
"""

from __future__ import annotations

from .azure import LONG_TIMEOUT
from .config import ClusterConfig
from .plan import Step
from . import roles

DESTROY_PHASES = (
    "cluster",
    "etcd-encryption",
    "identities",
    "network",
    "resource-group",
)


def _rg() -> list[str]:
    return ["--resource-group", "${CUSTOMER_RG_NAME}"]


def _delete(
    step_id: str,
    phase: str,
    description: str,
    args: list[str],
    exists: list[str],
    *,
    timeout: int | None = None,
    tags: tuple[str, ...] = (),
    after: tuple[str, ...] = (),
) -> Step:
    return Step(
        id=step_id,
        phase=phase,
        description=description,
        args=args,
        exists=exists,
        deletes=True,
        timeout=timeout or 600,
        tags=("destructive", *tags),
        after=after,
    )


#: Everything after the cluster depends on the cluster being gone: the control
#: plane still uses the KMS key, the identities and the network until then.
#: Enforced per step, so ``--phase`` and ``--keep-going`` cannot skip ahead.
_CLUSTER_GONE = ("cluster-delete",)


def build_destroy_plan(config: ClusterConfig) -> list[Step]:
    """Teardown steps for one cluster, in dependency order."""
    steps: list[Step] = []

    # No node pool step on purpose — see the module docstring (OCPBUGS-86702).
    steps.append(_delete(
        "cluster-delete", "cluster",
        "Delete the ARO HCP cluster and its node pools (15-30 minutes)",
        ["aro", "hcp", "cluster", "delete", "--name", "${CLUSTER_NAME}", *_rg(), "--yes"],
        ["aro", "hcp", "cluster", "show", "--name", "${CLUSTER_NAME}", *_rg(),
         "--query", "id", "--output", "tsv"],
        timeout=LONG_TIMEOUT,
    ))

    # Azure owns the managed resource group and removes it with the cluster.
    # If it is left behind it blocks the next create, so sweep it if present.
    steps.append(_delete(
        "managed-rg-delete", "cluster",
        "Delete the managed resource group if Azure left it behind",
        ["group", "delete", "--name", "${MANAGED_RESOURCE_GROUP}", "--yes"],
        ["group", "show", "--name", "${MANAGED_RESOURCE_GROUP}", "--query", "id", "--output", "tsv"],
        timeout=LONG_TIMEOUT,
        after=_CLUSTER_GONE,
    ))

    steps.append(_delete(
        "keyvault-delete", "etcd-encryption",
        "Delete the Key Vault (soft-deleted, still recoverable)",
        ["keyvault", "delete", "--name", "${KEYVAULT_NAME}", *_rg()],
        ["keyvault", "show", "--name", "${KEYVAULT_NAME}", *_rg(),
         "--query", "id", "--output", "tsv"],
        after=_CLUSTER_GONE,
    ))
    # Soft delete outlives the resource group, so the name stays reserved —
    # and a later create of the same cluster fails on it. Purging is what
    # actually frees it, which is also what makes it irreversible.
    steps.append(_delete(
        "keyvault-purge", "etcd-encryption",
        "Purge the soft-deleted Key Vault (irreversible)",
        ["keyvault", "purge", "--name", "${KEYVAULT_NAME}", "--location", "${LOCATION}"],
        ["keyvault", "list-deleted", "--query",
         "[?name=='${KEYVAULT_NAME}'].id | [0]", "--output", "tsv"],
        tags=("purge",),
        after=(*_CLUSTER_GONE, "keyvault-delete"),
    ))

    identities = [
        *(suffix for _k, suffix, _p in roles.CONTROL_PLANE_IDENTITIES),
        *(suffix for _k, suffix, _p in roles.DATA_PLANE_IDENTITIES),
        roles.SERVICE_IDENTITY[0],
        roles.KMS_IDENTITY[0],
    ]
    for suffix in identities:
        steps.append(_delete(
            f"identity-delete-{suffix}", "identities",
            f"Delete managed identity {suffix}",
            ["identity", "delete", "--name", f"${{CLUSTER_NAME}}-{suffix}", *_rg()],
            ["identity", "show", "--name", f"${{CLUSTER_NAME}}-{suffix}", *_rg(),
             "--query", "id", "--output", "tsv"],
            after=_CLUSTER_GONE,
        ))

    # The Key Vault private endpoint's NIC sits in the worker subnet, and the
    # DNS zone is linked to the VNet; either one blocks the VNet delete
    # (InUseSubnetCannotBeDeleted). Always planned: the probes skip them when
    # the cluster was built without --keyvault-private-endpoint, so teardown
    # does not depend on the operator remembering the flag.
    pe = "kv-private-endpoint"
    zone = roles.KEYVAULT_PRIVATE_DNS_ZONE
    steps.append(_delete(
        "keyvault-private-endpoint-delete", "network",
        "Delete the Key Vault private endpoint (and its DNS zone group)",
        ["network", "private-endpoint", "delete", "--name", pe, *_rg()],
        ["network", "private-endpoint", "show", "--name", pe, *_rg(),
         "--query", "id", "--output", "tsv"],
        after=_CLUSTER_GONE,
    ))
    steps.append(_delete(
        "keyvault-dns-link-delete", "network",
        "Delete the private DNS zone link to the VNet",
        ["network", "private-dns", "link", "vnet", "delete", "--name", "kv-private-dns-zone-link",
         "--zone-name", zone, *_rg(), "--yes"],
        ["network", "private-dns", "link", "vnet", "show", "--name", "kv-private-dns-zone-link",
         "--zone-name", zone, *_rg(), "--query", "id", "--output", "tsv"],
        after=_CLUSTER_GONE,
    ))
    steps.append(_delete(
        "keyvault-dns-zone-delete", "network",
        "Delete the Key Vault private DNS zone",
        ["network", "private-dns", "zone", "delete", "--name", zone, *_rg(), "--yes"],
        ["network", "private-dns", "zone", "show", "--name", zone, *_rg(),
         "--query", "id", "--output", "tsv"],
        after=("keyvault-dns-link-delete",),
    ))

    # The VNet first: the NSG is attached to the worker subnet and cannot be
    # deleted while that association exists.
    steps.append(_delete(
        "vnet-delete", "network",
        "Delete the VNet and its subnets",
        ["network", "vnet", "delete", "--name", "${CUSTOMER_VNET_NAME}", *_rg()],
        ["network", "vnet", "show", "--name", "${CUSTOMER_VNET_NAME}", *_rg(),
         "--query", "id", "--output", "tsv"],
        after=(*_CLUSTER_GONE, "keyvault-private-endpoint-delete", "keyvault-dns-link-delete"),
    ))
    steps.append(_delete(
        "nsg-delete", "network",
        "Delete the network security group",
        ["network", "nsg", "delete", "--name", "${CUSTOMER_NSG}", *_rg()],
        ["network", "nsg", "show", "--name", "${CUSTOMER_NSG}", *_rg(),
         "--query", "id", "--output", "tsv"],
        after=("vnet-delete",),
    ))

    steps.append(_delete(
        "resource-group-delete", "resource-group",
        "Delete the customer resource group and anything still in it",
        ["group", "delete", "--name", "${CUSTOMER_RG_NAME}", "--yes"],
        ["group", "show", "--name", "${CUSTOMER_RG_NAME}",
         "--query", "id", "--output", "tsv"],
        timeout=LONG_TIMEOUT,
        after=(*_CLUSTER_GONE, "keyvault-purge"),
    ))

    return steps
