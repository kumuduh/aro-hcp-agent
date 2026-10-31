"""Regression tests for the preflight fixes (O2, O3, D19, D27, N1-N5, PRE-24..34)."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess

import pytest

from aro_hcp import preflight
from aro_hcp.azure import AzCli, AzResult, token_object_id
from aro_hcp.config import ClusterConfig
from aro_hcp.executor import resolve_signed_in_user
from aro_hcp.preflight import FAIL, OK, WARN, run_preflight
from aro_hcp.state import RunState

SUB = "00000000-0000-0000-0000-000000000001"
NOT_FOUND = (3, "", "ERROR: (ResourceNotFound) The Resource was not found.")


class ScriptedAz(AzCli):
    """Answers each call from the first rule whose needle is in the argv."""

    def __init__(self, rules):
        super().__init__(SUB)
        self.rules = rules
        self.calls: list[list[str]] = []

    def run(self, args, *, check=True, timeout=0, force=False):
        argv = list(args)
        self.calls.append(argv)
        joined = " ".join(argv)
        for needle, resp in self.rules:
            if needle in joined:
                return AzResult(argv, *resp)
        return AzResult(argv, 0, "", "")


def usage(name, limit, current=0):
    return {"name": {"value": name}, "limit": limit, "currentValue": current}


def versions(*pairs):
    return (0, json.dumps([{"Name": n, "ChannelGroup": g} for n, g in pairs]), "")


HEALTHY = [
    ("--version", (0, "azure-cli  2.70.0\n", "")),
    ("extension show", (0, "1.0.13\n", "")),
    ("aro hcp --help", (0, "Group", "")),
    ("account show --query id", (0, SUB + "\n", "")),
    ("account show --query user.name", (0, "qa@example.com\n", "")),
    ("account show --query user.type", (0, "user\n", "")),
    ("ad signed-in-user show", (0, "oid-1\n", "")),
    ("role assignment list", (0, json.dumps([
        {"roleDefinitionName": "Owner", "scope": f"/subscriptions/{SUB}"}]), "")),
    ("provider show", (0, "Registered\n", "")),
    ("list-skus", (0, json.dumps([{"name": "Standard_D8s_v6", "restrictions": []}]), "")),
    ("vm list-usage", (0, json.dumps([usage("cores", 350), usage("StandardDsv6Family", 350)]), "")),
    ("--control-plane", versions(("4.22", "stable"))),
    ("--node-pools", versions(("4.22.20", "stable"))),
    ("cluster show", NOT_FOUND),
    ("group show", (3, "", "(ResourceGroupNotFound) Resource group 'x' could not be found.")),
    ("keyvault show", NOT_FOUND),
    ("list-deleted", (0, "[]", "")),
    ("checkNameAvailability", (0, json.dumps({"nameAvailable": True}), "")),
    ("vnet show", NOT_FOUND),
]


def az_with(**overrides):
    """HEALTHY with some needles answered differently (overrides go first)."""
    return ScriptedAz(list(overrides.items()) + HEALTHY)


def config(**overrides):
    data = dict(cluster_name="qa", location="eastus2", resource_group="qa-rg",
                cluster_version="4.22", nodepool_version="4.22.20", subscription_id=SUB)
    data.update(overrides)
    return ClusterConfig(**data)


def by_check(findings, check):
    return [f for f in findings if f.check == check]


@pytest.fixture(autouse=True)
def _az_on_path(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: f"/usr/bin/{name}")


def test_healthy_environment_passes_with_every_check_ok():
    report = run_preflight(az_with(), config())
    assert not report.blocked
    bad = [f.to_dict() for f in report.findings if f.status != OK]
    assert not bad


# -- N1 managed identity -----------------------------------------------------


MI_OID = "11111111-2222-3333-4444-555555555555"


def jwt(claims):
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature"


@pytest.mark.parametrize("literal", ["systemAssignedIdentity", "userAssignedIdentity"])
def test_managed_identity_login_passes_with_its_object_id(literal):
    az = az_with(**{
        "account show --query user.name": (0, literal + "\n", ""),
        "account show --query user.type": (0, "servicePrincipal\n", ""),
        "get-access-token": (0, jwt({"oid": MI_OID, "idtyp": "app"}) + "\n", ""),
    })
    report = run_preflight(az, config())
    ident = by_check(report.findings, "identity")[0]
    assert ident.status == OK and MI_OID in ident.message
    assert by_check(report.findings, "permissions")[0].status == OK
    listing = [c for c in az.calls if c[:3] == ["role", "assignment", "list"]][0]
    assert listing[listing.index("--assignee-object-id") + 1] == MI_OID
    # No Graph lookup: a managed identity usually cannot read Graph.
    assert not [c for c in az.calls if c[:1] == ["ad"]]


@pytest.mark.parametrize("literal", ["systemAssignedIdentity", "userAssignedIdentity"])
def test_managed_identity_without_object_id_blocks(literal):
    az = az_with(**{"account show --query user.name": (0, literal + "\n", ""),
                    "get-access-token": (1, "", "ERROR: no token")})
    report = run_preflight(az, config())
    ident = by_check(report.findings, "identity")[0]
    assert ident.status == FAIL and ident.remedy
    assert by_check(report.findings, "permissions")[0].status == WARN


def test_managed_identity_login_passes_on_terraform_backend():
    az = az_with(**{
        "account show --query user.name": (0, "systemAssignedIdentity\n", ""),
        "get-access-token": (0, jwt({"oid": MI_OID}) + "\n", ""),
    })
    findings = preflight.check_login(az, config(backend="terraform"))
    assert by_check(findings, "identity")[0].status == OK


@pytest.mark.parametrize("token", [
    "not-a-jwt", "a.!!!.c", jwt({"sub": "x"}), jwt({"oid": "not-a-guid"}), jwt(["oid"]),
])
def test_token_object_id_rejects_unusable_tokens(token):
    assert token_object_id(token) is None


def test_token_object_id_reads_oid():
    assert token_object_id(jwt({"oid": MI_OID}) + "\n") == MI_OID


def test_access_token_is_kept_out_of_the_command_log(monkeypatch):
    token = jwt({"oid": MI_OID})
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 0, token + "\n", ""))
    az = AzCli(SUB)
    assert az.principal_object_id() == MI_OID
    assert all(token not in r.stdout for r in az.log)


@pytest.mark.parametrize("user_type, expected", [
    ("user", "User"), ("servicePrincipal", "ServicePrincipal"),
])
def test_signed_in_principal_type_is_recorded(tmp_path, user_type, expected):
    az = az_with(**{"account show --query user.type": (0, user_type + "\n", ""),
                    "get-access-token": (0, jwt({"oid": MI_OID}) + "\n", "")})
    state = RunState(path=tmp_path / "s.json")
    assert resolve_signed_in_user(az, state) == MI_OID
    assert state.get("SIGNED_IN_PRINCIPAL_TYPE") == expected


def test_managed_identity_is_recorded_as_service_principal(tmp_path):
    az = az_with(**{"account show --query user.name": (0, "userAssignedIdentity\n", ""),
                    "get-access-token": (0, jwt({"oid": MI_OID}) + "\n", "")})
    state = RunState(path=tmp_path / "s.json")
    assert resolve_signed_in_user(az, state) == MI_OID
    assert state.get("SIGNED_IN_PRINCIPAL_TYPE") == "ServicePrincipal"


def test_login_name_from_older_state_is_re_resolved(tmp_path):
    state = RunState(path=tmp_path / "s.json")
    state.set_context("SIGNED_IN_USER", "qa@example.com")
    az = az_with(**{"get-access-token": (0, jwt({"oid": MI_OID}) + "\n", "")})
    assert resolve_signed_in_user(az, state) == MI_OID
    assert state.get("SIGNED_IN_PRINCIPAL_TYPE") == "User"


# -- O2 role-assignment rights ----------------------------------------------


def assignments(*entries):
    return (0, json.dumps([{"roleDefinitionName": n, "scope": s} for n, s in entries]), "")


@pytest.mark.parametrize("role", ["Owner", "User Access Administrator",
                                  "Role Based Access Control Administrator"])
def test_permission_ok_for_writer_roles(role):
    az = az_with(**{"role assignment list": assignments((role, f"/subscriptions/{SUB}"))})
    f = preflight.check_role_assignment_permission(az, config())
    assert f.status == OK


def test_permission_uses_object_id_for_users():
    az = az_with()
    preflight.check_role_assignment_permission(az, config())
    listing = [c for c in az.calls if c[:3] == ["role", "assignment", "list"]][0]
    assert listing[listing.index("--assignee-object-id") + 1] == "oid-1"
    assert "--include-groups" in listing and "--include-inherited" in listing


def test_permission_resolves_service_principal_object_id():
    az = az_with(**{
        "account show --query user.type": (0, "servicePrincipal\n", ""),
        "account show --query user.name": (0, "app-id\n", ""),
        "ad sp show --id app-id": (0, "sp-oid\n", ""),
    })
    preflight.check_role_assignment_permission(az, config())
    listing = [c for c in az.calls if c[:3] == ["role", "assignment", "list"]][0]
    assert listing[listing.index("--assignee-object-id") + 1] == "sp-oid"


def test_permission_contributor_only_fails_with_grant_command():
    az = az_with(**{"role assignment list": assignments(("Contributor", f"/subscriptions/{SUB}"))})
    f = preflight.check_role_assignment_permission(az, config())
    assert f.status == FAIL
    assert "az role assignment create" in f.remedy and "qa-rg" in f.remedy


def test_permission_owner_on_unrelated_rg_does_not_count():
    other = f"/subscriptions/{SUB}/resourceGroups/other-rg"
    az = az_with(**{"role assignment list": assignments(("Owner", other), ("Reader", f"/subscriptions/{SUB}"))})
    assert preflight.check_role_assignment_permission(az, config()).status == FAIL


def test_permission_rg_scoped_owner_found_when_sub_listing_denied():
    rg = f"/subscriptions/{SUB}/resourceGroups/qa-rg"
    az = az_with(**{
        f"--scope {rg}": assignments(("Owner", rg)),
        "role assignment list": (1, "", "(AuthorizationFailed) no read at subscription"),
    })
    assert preflight.check_role_assignment_permission(az, config()).status == OK


def test_permission_unreadable_is_warn_not_ok():
    az = az_with(**{"role assignment list": (1, "", "(AuthorizationFailed) denied")})
    f = preflight.check_role_assignment_permission(az, config())
    assert f.status == WARN and "AuthorizationFailed" in f.message


def test_permission_custom_role_with_write_is_ok():
    custom = json.dumps([{"roleType": "CustomRole", "permissions": [
        {"actions": ["Microsoft.Authorization/roleAssignments/*"], "notActions": []}]}])
    az = az_with(**{
        "role assignment list": assignments(("Deployer", f"/subscriptions/{SUB}")),
        "role definition list": (0, custom, ""),
    })
    assert preflight.check_role_assignment_permission(az, config()).status == OK


def test_permission_custom_role_with_write_excluded_fails():
    custom = json.dumps([{"permissions": [
        {"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Write"]}]}])
    az = az_with(**{
        "role assignment list": assignments(("Deployer", f"/subscriptions/{SUB}")),
        "role definition list": (0, custom, ""),
    })
    assert preflight.check_role_assignment_permission(az, config()).status == FAIL


def test_permission_custom_role_unreadable_is_warn():
    az = az_with(**{
        "role assignment list": assignments(("Deployer", f"/subscriptions/{SUB}")),
        "role definition list": (1, "", "denied"),
    })
    f = preflight.check_role_assignment_permission(az, config())
    assert f.status == WARN and "Deployer" in f.message


# -- PRE-31 Key Vault name ---------------------------------------------------


def test_keyvault_soft_deleted_fails_with_purge_command():
    deleted = json.dumps([{"name": "qa-kv", "properties": {"location": "eastus2"}}])
    f = preflight.check_keyvault_name(az_with(**{"list-deleted": (0, deleted, "")}), config())
    assert f.status == FAIL
    assert "az keyvault purge --name qa-kv --location eastus2" in f.remedy


def test_keyvault_name_taken_globally_fails():
    taken = json.dumps({"nameAvailable": False, "reason": "AlreadyExists",
                        "message": "The vault name 'qa-kv' is already in use."})
    f = preflight.check_keyvault_name(az_with(**{"checkNameAvailability": (0, taken, "")}), config())
    assert f.status == FAIL and "cluster_name" in f.remedy


def test_keyvault_existing_in_target_rg_is_resume():
    az = az_with(**{"keyvault show": (0, "/subscriptions/x/vaults/qa-kv\n", "")})
    f = preflight.check_keyvault_name(az, config())
    assert f.status == OK
    assert not [c for c in az.calls if "list-deleted" in c or "rest" in c]


def test_keyvault_unknown_is_warn():
    az = az_with(**{"list-deleted": (1, "", "denied"), "checkNameAvailability": (1, "", "denied")})
    assert preflight.check_keyvault_name(az, config()).status == WARN


def test_keyvault_and_vnet_checks_skipped_on_terraform(monkeypatch):
    from aro_hcp.runner import TerraformCli

    monkeypatch.setattr(TerraformCli, "version", lambda self: (1, 9, 5))
    az = az_with()
    report = run_preflight(az, config(backend="terraform"))
    assert not by_check(report.findings, "keyvault-name")
    assert not by_check(report.findings, "vnet")
    assert not [c for c in az.calls if "list-deleted" in c]


# -- D19 / N2 / PRE-21..25 quota and SKU -------------------------------------


def test_b_series_family_name():
    assert preflight._vm_family("Standard_B2ms") == "standardBSFamily"
    assert preflight._vm_family("Standard_E8-4s_v5").lower() == "standardesv5family"


def test_quota_family_match_is_exact_not_substring():
    # standardDSv6Family must not be satisfied by a standardDDSv6Family entry.
    az = az_with(**{"vm list-usage": (0, json.dumps(
        [usage("cores", 500), usage("standardDDSv6Family", 500)]), "")})
    assert preflight.check_quota(az, config()).status == WARN


def test_quota_demand_is_replicas_times_vcpus():
    az = az_with(**{"vm list-usage": (0, json.dumps(
        [usage("cores", 500), usage("StandardDsv6Family", 79)]), "")})
    f = preflight.check_quota(az, config(nodepool_replicas=10))
    assert f.status == FAIL and "80" in f.message
    az = az_with(**{"vm list-usage": (0, json.dumps(
        [usage("cores", 500), usage("StandardDsv6Family", 80)]), "")})
    assert preflight.check_quota(az, config(nodepool_replicas=10)).status == OK


def test_quota_regional_total_checked():
    az = az_with(**{"vm list-usage": (0, json.dumps(
        [usage("cores", 100, 90), usage("StandardDsv6Family", 350)]), "")})
    f = preflight.check_quota(az, config())
    assert f.status == FAIL and "regional" in f.message


@pytest.mark.parametrize("payload", [
    {"value": []}, ["a", "b"], [{"name": "x", "limit": 5}],
    [{"name": {"value": "StandardDsv6Family"}, "limit": "lots", "currentValue": 0}],
])
def test_quota_wrong_shape_is_warn(payload):
    az = az_with(**{"vm list-usage": (0, json.dumps(payload), "")})
    assert preflight.check_quota(az, config()).status == WARN


def test_sku_restricted_fails():
    sku = json.dumps([{"name": "Standard_D8s_v6", "restrictions": [
        {"type": "Location", "reasonCode": "NotAvailableForSubscription", "values": ["eastus2"]}]}])
    f = preflight.check_vm_sku(az_with(**{"list-skus": (0, sku, "")}), config())
    assert f.status == FAIL and "NotAvailableForSubscription" in f.message


def test_sku_not_offered_fails_and_prefix_matches_ignored():
    sku = json.dumps([{"name": "Standard_D8s_v6_Promo", "restrictions": []}])
    assert preflight.check_vm_sku(az_with(**{"list-skus": (0, sku, "")}), config()).status == FAIL


def test_sku_zone_restriction_is_warn():
    sku = json.dumps([{"name": "Standard_D8s_v6", "restrictions": [
        {"type": "Zone", "restrictionInfo": {"zones": ["3"]}}]}])
    f = preflight.check_vm_sku(az_with(**{"list-skus": (0, sku, "")}), config())
    assert f.status == WARN and "3" in f.message


def test_sku_unknown_is_warn():
    f = preflight.check_vm_sku(az_with(**{"list-skus": (1, "", "boom")}), config())
    assert f.status == WARN


@pytest.mark.parametrize("size", ["Standard_B2ms", "Standard_D2s_v5"])
def test_unsupported_worker_size_fails(size):
    f = preflight.check_vm_sku(az_with(), config(nodepool_vm_size=size))
    assert f.status == FAIL and "Standard_D8s_v6" in f.remedy


# -- D27 / D19 / PRE-26a versions -------------------------------------------


def test_version_in_two_channels_is_ok():
    az = az_with(**{"--control-plane": versions(("4.22", "candidate"), ("4.22", "stable"))})
    f = by_check(preflight.check_versions(az, config()), "cluster-version")[0]
    assert f.status == OK


def test_nodepool_wrong_channel_fails():
    az = az_with(**{"--node-pools": versions(("4.22.20", "candidate"), ("4.22.19", "stable"))})
    f = by_check(preflight.check_versions(az, config()), "nodepool-version")[0]
    assert f.status == FAIL and "candidate" in f.message and "4.22.19" in f.remedy


def test_empty_version_lists_are_permission_hint_not_fail():
    az = az_with(**{"--control-plane": (0, "[]", ""), "--node-pools": (0, "[]", "")})
    findings = preflight.check_versions(az, config())
    assert not [f for f in findings if f.status == FAIL]
    for check in ("cluster-version", "nodepool-version"):
        f = by_check(findings, check)[0]
        assert f.status == WARN and "subscription-level read" in f.message


@pytest.mark.parametrize("resp", [(0, "{oops", ""), (0, json.dumps({"x": 1}), ""),
                                  (1, "", "(InternalServerError) 500")])
def test_unusable_version_response_is_warn(resp):
    findings = preflight.check_versions(az_with(**{"--control-plane": resp}), config())
    assert [f.status for f in findings] == [WARN]


# -- O3 / PRE-33 / PRE-34 collisions -----------------------------------------


def test_failed_cluster_blocks_with_delete_remedy():
    az = az_with(**{"cluster show": (0, "Failed\n", "")})
    f = by_check(preflight.check_name_collisions(az, config()), "cluster-exists")[0]
    assert f.status == FAIL and "az aro hcp cluster delete" in f.remedy


@pytest.mark.parametrize("state", ["Provisioning", "Deleting", "Updating"])
def test_busy_cluster_warns(state):
    az = az_with(**{"cluster show": (0, state + "\n", "")})
    f = by_check(preflight.check_name_collisions(az, config()), "cluster-exists")[0]
    assert f.status == WARN and state in f.message and f.remedy


@pytest.mark.parametrize("needle", ["cluster show", "group show"])
def test_lookup_errors_are_unverified(needle):
    az = az_with(**{needle: (1, "", "(AuthorizationFailed) denied")})
    findings = preflight.check_name_collisions(az, config())
    assert any(f.status == WARN and "could not verify" in f.message for f in findings)


def test_managed_rg_with_unverifiable_cluster_is_warn_not_fail():
    az = az_with(**{"cluster show": (124, "", "timed out after 300s"),
                    "group show": (0, "/subscriptions/x/resourceGroups/qa-managed-rg\n", "")})
    findings = preflight.check_name_collisions(az, config())
    assert by_check(findings, "managed-rg")[0].status == WARN


# -- N5 existing VNet ---------------------------------------------------------


def test_existing_vnet_outside_address_space_fails():
    vnet = json.dumps({"addressSpace": {"addressPrefixes": ["192.168.0.0/16"]}, "subnets": []})
    f = preflight.check_existing_vnet(az_with(**{"vnet show": (0, vnet, "")}), config())[0]
    assert f.status == FAIL and "10.0.0.0/24" in f.message


def test_existing_vnet_with_conflicting_subnet_fails():
    vnet = json.dumps({"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                       "subnets": [{"name": "worker-subnet", "addressPrefix": "10.0.5.0/24"}]})
    f = preflight.check_existing_vnet(az_with(**{"vnet show": (0, vnet, "")}), config())[0]
    assert f.status == FAIL and "10.0.5.0/24" in f.message


def test_existing_compatible_vnet_is_ok():
    vnet = json.dumps({"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                       "subnets": [{"name": "worker-subnet", "addressPrefix": "10.0.0.0/24"}]})
    f = preflight.check_existing_vnet(az_with(**{"vnet show": (0, vnet, "")}), config())[0]
    assert f.status == OK


def test_access_token_is_for_the_configured_subscription_and_fetched_once():
    az = az_with(**{"get-access-token": (0, jwt({"oid": MI_OID}) + "\n", "")})
    assert az.principal_object_id() == az.principal_object_id() == MI_OID
    calls = [c for c in az.calls if "get-access-token" in c]
    assert len(calls) == 1 and calls[0][calls[0].index("--subscription") + 1] == SUB
