"""Static facts from the ARO HCP provisioning procedure.

Source: https://learn.microsoft.com/en-us/azure/openshift/howto-create-custom-hosted-cluster?pivots=aro-az-cli
"""

from __future__ import annotations

# --- Azure role definition GUIDs -------------------------------------------

READER_ROLE = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
HCP_CLUSTER_API_PROVIDER_ROLE = "88366f10-ed47-4cc0-9fab-c8a06148393e"
HCP_CONTROL_PLANE_OPERATOR_ROLE = "fc0c873f-45e9-4d0d-a7d1-585aab30c6ed"
CLOUD_CONTROLLER_MANAGER_ROLE = "a1f96423-95ce-4224-ab27-4e3dc72facd4"
INGRESS_OPERATOR_ROLE = "0336e1d3-7a87-462b-b6db-342b63f7802c"
FILE_STORAGE_OPERATOR_ROLE = "0d7aedc0-15fd-4a67-a412-efad370c947e"
NETWORK_OPERATOR_ROLE = "be7a6435-15ae-4171-8f30-4a343eff9e8f"
FEDERATED_CREDENTIAL_ROLE = "ef318e2a-8334-4a05-9e4a-295a196c6a6e"
HCP_SERVICE_MI_ROLE = "c0ff367d-66d8-445e-917c-583feb0ef0d4"
IMAGE_REGISTRY_OPERATOR_ROLE = "8b32b316-c2f5-4ddf-b05b-83dacd2d08b5"
KEY_VAULT_CRYPTO_USER_ROLE = "12338af0-0e69-4776-bea7-57ae8d297424"

ROLE_NAMES = {
    READER_ROLE: "Reader",
    HCP_CLUSTER_API_PROVIDER_ROLE: "ARO HCP Cluster API Provider",
    HCP_CONTROL_PLANE_OPERATOR_ROLE: "ARO HCP Control Plane Operator",
    CLOUD_CONTROLLER_MANAGER_ROLE: "ARO Cloud Controller Manager",
    INGRESS_OPERATOR_ROLE: "ARO Cluster Ingress Operator",
    FILE_STORAGE_OPERATOR_ROLE: "ARO File Storage Operator",
    NETWORK_OPERATOR_ROLE: "ARO Network Operator",
    FEDERATED_CREDENTIAL_ROLE: "ARO Federated Credential",
    HCP_SERVICE_MI_ROLE: "ARO HCP Service Managed Identity",
    IMAGE_REGISTRY_OPERATOR_ROLE: "ARO Image Registry Operator",
    KEY_VAULT_CRYPTO_USER_ROLE: "Key Vault Crypto User",
}

# --- Managed identities -----------------------------------------------------
#
# Each entry is (operator_key, name_suffix, context_prefix). ``operator_key`` is
# the value passed to --assign-{control,data}-plane-operator-identity; the
# context prefix names the ${PREFIX_MI_ID} / ${PREFIX_MI_PID} variables the plan
# resolves at execution time.

CONTROL_PLANE_IDENTITIES = [
    ("cluster-api-azure", "cp-cluster-api-azure", "CLUSTER_API_AZURE"),
    ("control-plane", "cp-control-plane", "CONTROL_PLANE"),
    ("cloud-controller-manager", "cp-cloud-controller-manager", "CLOUD_CONTROLLER_MANAGER"),
    ("ingress", "cp-ingress", "INGRESS"),
    ("disk-csi-driver", "cp-disk-csi-driver", "DISK_CSI_DRIVER"),
    ("file-csi-driver", "cp-file-csi-driver", "FILE_CSI_DRIVER"),
    ("image-registry", "cp-image-registry", "IMAGE_REGISTRY"),
    ("cloud-network-config", "cp-cloud-network-config", "CLOUD_NETWORK_CONFIG"),
]

DATA_PLANE_IDENTITIES = [
    ("disk-csi-driver", "dp-disk-csi-driver", "DP_DISK_CSI_DRIVER"),
    ("file-csi-driver", "dp-file-csi-driver", "DP_FILE_CSI_DRIVER"),
    ("image-registry", "dp-image-registry", "DP_IMAGE_REGISTRY"),
]

SERVICE_IDENTITY = ("service-managed-identity", "SERVICE")
KMS_IDENTITY = ("cp-kms", "KMS")

# --- Role assignments -------------------------------------------------------
#
# (assignee_principal_var, role_guid, scope_var, human label)

CONTROL_PLANE_ROLE_ASSIGNMENTS = [
    ("CLUSTER_API_AZURE_MI_PID", HCP_CLUSTER_API_PROVIDER_ROLE, "VNET_ID", "cluster-api-azure on VNet"),
    ("CONTROL_PLANE_MI_PID", HCP_CONTROL_PLANE_OPERATOR_ROLE, "VNET_ID", "control-plane on VNet"),
    ("CONTROL_PLANE_MI_PID", HCP_CONTROL_PLANE_OPERATOR_ROLE, "NSG_ID", "control-plane on NSG"),
    ("CLOUD_CONTROLLER_MANAGER_MI_PID", CLOUD_CONTROLLER_MANAGER_ROLE, "NSG_ID", "cloud-controller-manager on NSG"),
    ("CLOUD_CONTROLLER_MANAGER_MI_PID", CLOUD_CONTROLLER_MANAGER_ROLE, "VNET_ID", "cloud-controller-manager on VNet"),
    ("INGRESS_MI_PID", INGRESS_OPERATOR_ROLE, "VNET_ID", "ingress on VNet"),
    ("FILE_CSI_DRIVER_MI_PID", FILE_STORAGE_OPERATOR_ROLE, "NSG_ID", "file-csi-driver on NSG"),
    ("FILE_CSI_DRIVER_MI_PID", FILE_STORAGE_OPERATOR_ROLE, "VNET_ID", "file-csi-driver on VNet"),
    ("CLOUD_NETWORK_CONFIG_MI_PID", NETWORK_OPERATOR_ROLE, "VNET_ID", "cloud-network-config on VNet"),
    ("IMAGE_REGISTRY_MI_PID", IMAGE_REGISTRY_OPERATOR_ROLE, "VNET_ID", "image-registry on VNet"),
]

SERVICE_ROLE_ASSIGNMENTS = [
    ("SERVICE_MI_PID", HCP_SERVICE_MI_ROLE, "VNET_ID", "service MI on VNet"),
    ("SERVICE_MI_PID", HCP_SERVICE_MI_ROLE, "NSG_ID", "service MI on NSG"),
] + [
    ("SERVICE_MI_PID", READER_ROLE, f"{prefix}_MI_ID", f"service MI reader on {suffix}")
    for _key, suffix, prefix in CONTROL_PLANE_IDENTITIES
]

DATA_PLANE_ROLE_ASSIGNMENTS = [
    ("SERVICE_MI_PID", FEDERATED_CREDENTIAL_ROLE, f"{prefix}_MI_ID", f"service MI federated credential on {suffix}")
    for _key, suffix, prefix in DATA_PLANE_IDENTITIES
] + [
    ("DP_FILE_CSI_DRIVER_MI_PID", FILE_STORAGE_OPERATOR_ROLE, "NSG_ID", "dp file-csi-driver on NSG"),
    ("DP_FILE_CSI_DRIVER_MI_PID", FILE_STORAGE_OPERATOR_ROLE, "VNET_ID", "dp file-csi-driver on VNet"),
    ("DP_IMAGE_REGISTRY_MI_PID", IMAGE_REGISTRY_OPERATOR_ROLE, "VNET_ID", "dp image-registry on VNet"),
]

# Identities whose principalId the plan needs. Everything else only needs the
# resource ID, so we skip the extra `az identity show` round trip.
PRINCIPAL_ID_NEEDED = {
    "CLUSTER_API_AZURE",
    "CONTROL_PLANE",
    "CLOUD_CONTROLLER_MANAGER",
    "INGRESS",
    "FILE_CSI_DRIVER",
    "IMAGE_REGISTRY",
    "CLOUD_NETWORK_CONFIG",
    "DP_FILE_CSI_DRIVER",
    "DP_IMAGE_REGISTRY",
    "SERVICE",
    "KMS",
}

REQUIRED_RESOURCE_PROVIDERS = [
    "Microsoft.RedHatOpenShift",
    "Microsoft.Compute",
    "Microsoft.Storage",
    "Microsoft.Authorization",
]

MIN_AZ_VERSION = (2, 67, 0)
MIN_CORES = 20
VNET_INTEGRATION_DELEGATION = "Microsoft.RedHatOpenShift/hcpOpenShiftClusters"
KEYVAULT_PRIVATE_DNS_ZONE = "privatelink.vaultcore.azure.net"
