"""Regression tests for config loading, typing and validation fixes.

Covers D4, D5, D6, D17, D18 and the CFG-6..CFG-42 findings: every bad input
must surface as a ConfigError or a validate() problem, never a traceback.
"""

from __future__ import annotations

import json

import pytest

from aro_hcp import config as config_mod
from aro_hcp.config import ClusterConfig, ConfigError

MINIMAL = """\
cluster_name: demo
location: eastus
resource_group: demo-rg
cluster_version: "4.22"
nodepool_version: "4.22.1"
subscription_id: 00000000-0000-0000-0000-000000000000
"""


def make_config(**overrides) -> ClusterConfig:
    base = dict(
        cluster_name="demo",
        location="eastus",
        resource_group="demo-rg",
        cluster_version="4.22",
        nodepool_version="4.22.1",
        subscription_id="00000000-0000-0000-0000-000000000000",
    )
    base.update(overrides)
    return ClusterConfig(**base)


def write(tmp_path, text, name="c.yaml"):
    path = tmp_path / name
    path.write_text(text)
    return path


def with_line(key, raw):
    lines = [l for l in MINIMAL.splitlines() if not l.startswith(key + ":")]
    return "\n".join(lines + [f"{key}: {raw}"]) + "\n"


def test_minimal_config_is_valid():
    assert make_config().validate() == []
    assert make_config(backend="terraform").validate() == []


# -- load(): read and parse errors (CFG-6..9) ---------------------------------

@pytest.mark.parametrize("text,name,needle", [
    ("", "c.json", "missing required"),
    ("   \n", "c.yaml", "missing required"),
    ("{bad json", "c.json", "not valid JSON"),
    ("cluster_name: [unclosed\n", "c.yaml", "not valid YAML"),
    ("cluster_name: !!python/object/apply:os.getcwd []\n", "c.yaml", "not valid YAML"),
    (MINIMAL + "cluster_name: other\n", "c.yaml", "duplicate key"),
    ('{"cluster_name": "a", "cluster_name": "b"}', "c.json", "duplicate key"),
    ("- a\n", "c.yaml", "expected a mapping"),
])
def test_load_errors_are_config_errors_naming_the_file(tmp_path, text, name, needle):
    path = write(tmp_path, text, name)
    with pytest.raises(ConfigError, match=needle) as ei:
        ClusterConfig.load(path)
    assert str(path) in str(ei.value)


def test_load_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="missing.yaml"):
        ClusterConfig.load(tmp_path / "missing.yaml")


def test_load_refuses_oversized_file_before_parsing(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "MAX_CONFIG_BYTES", 100)
    path = write(tmp_path, MINIMAL + "#" * 200 + "\n")
    with pytest.raises(ConfigError, match="too large"):
        ClusterConfig.load(path)


@pytest.mark.parametrize("name", ["c.yml", "c.YAML", "c.Yml", "cluster"])
def test_load_yaml_extensions_case_insensitive_and_extensionless(tmp_path, name):
    assert ClusterConfig.load(write(tmp_path, MINIMAL, name)).validate() == []


def test_load_json_uppercase_extension(tmp_path):
    import yaml

    text = json.dumps(yaml.safe_load(MINIMAL))
    assert ClusterConfig.load(write(tmp_path, text, "c.JSON")).cluster_name == "demo"


def test_yaml_merge_key_override_is_not_a_duplicate(tmp_path):
    text = MINIMAL + "tags:\n  <<: {team: a}\n  team: b\n"
    assert ClusterConfig.load(write(tmp_path, text)).tags == {"team": "b"}


# -- types (D5, D6, CFG-12..15) ------------------------------------------------

@pytest.mark.parametrize("raw", ["4.20", "4", "4.3"])
def test_unquoted_version_rejected_with_quote_hint(tmp_path, raw):
    with pytest.raises(ConfigError, match="quote it") as ei:
        ClusterConfig.load(write(tmp_path, with_line("cluster_version", raw)))
    assert "4.2" in str(ei.value)


def test_float_version_built_in_code_is_a_problem_not_a_crash():
    problems = make_config(cluster_version=4.2).validate()
    assert any("quote it" in p for p in problems)


@pytest.mark.parametrize("raw", ['"false"', '"no"', "0", '"0"', "1"])
def test_skip_nodepool_must_be_a_real_bool(tmp_path, raw):
    with pytest.raises(ConfigError, match="skip_nodepool"):
        ClusterConfig.load(write(tmp_path, with_line("skip_nodepool", raw)))


@pytest.mark.parametrize("raw", ['"2"', "2.5", "true"])
def test_nodepool_replicas_must_be_int(tmp_path, raw):
    with pytest.raises(ConfigError, match="nodepool_replicas"):
        ClusterConfig.load(write(tmp_path, with_line("nodepool_replicas", raw)))


@pytest.mark.parametrize("replicas,ok", [(0, False), (-1, False), (1, True)])
def test_nodepool_replicas_minimum_az_cli(replicas, ok):
    assert (make_config(nodepool_replicas=replicas).validate() == []) is ok


@pytest.mark.parametrize("raw", ["null", "[]", "{a: 1}", "{a: {b: c}}", "{1: a}"])
def test_tags_must_be_flat_string_mapping(tmp_path, raw):
    with pytest.raises(ConfigError, match="tags"):
        ClusterConfig.load(write(tmp_path, with_line("tags", raw)))


def test_tags_string_mapping_accepted(tmp_path):
    cfg = ClusterConfig.load(write(tmp_path, with_line("tags", '{team: qa, cost: "42"}')))
    assert cfg.tags == {"team": "qa", "cost": "42"} and cfg.validate() == []


# -- from_env (CFG-41/42) ------------------------------------------------------

@pytest.fixture
def env(monkeypatch):
    for f in ClusterConfig.__dataclass_fields__:
        monkeypatch.delenv("ARO_" + f.upper(), raising=False)
    for k, v in dict(cluster_name="demo", location="eastus", resource_group="demo-rg",
                     cluster_version="4.22", nodepool_version="4.22.1").items():
        monkeypatch.setenv("ARO_" + k.upper(), v)
    return monkeypatch


@pytest.mark.parametrize("raw,expected", [("YES", True), ("off", False), (" 1 ", True)])
def test_env_bool_known_words(env, raw, expected):
    env.setenv("ARO_SKIP_NODEPOOL", raw)
    assert ClusterConfig.from_env().skip_nodepool is expected


@pytest.mark.parametrize("var,val,needle", [
    ("ARO_SKIP_NODEPOOL", "ture", "not a boolean"),
    ("ARO_SKIP_NODEPOOL", "", "not a boolean"),
    ("ARO_NODEPOOL_REPLICAS", "two", "not a whole number"),
    ("ARO_TAGS", "not json", "not valid JSON"),
    ("ARO_TAGS", '{"a": {"b": "c"}}', "tags"),
    ("ARO_TAGS", "null", "tags"),
])
def test_env_bad_values_are_config_errors(env, var, val, needle):
    env.setenv(var, val)
    with pytest.raises(ConfigError, match=needle):
        ClusterConfig.from_env()


# -- names, subscription, channel (CFG-16, CFG-17, CFG-31, CFG-34) ------------

@pytest.mark.parametrize("overrides,needle", [
    (dict(subscription_id="my-sub; rm -rf /"), "subscription_id"),
    (dict(worker_subnet_name="same", vnet_integration_subnet_name="SAME"), "two names"),
    (dict(nodepool_name="NP_1 !"), "nodepool_name"),
    (dict(nodepool_name="np"), "nodepool_name"),
    (dict(nodepool_name="a" * 16), "nodepool_name"),
    (dict(vnet_name="bad name;"), "vnet_name"),
    (dict(vnet_name="v"), "vnet_name"),
    (dict(nsg_name="-x"), "nsg_name"),
    (dict(nsg_name="x."), "nsg_name"),
    (dict(worker_subnet_name="sübnet"), "worker_subnet_name"),
    (dict(managed_resource_group="DEMO-RG"), "case-insensitively"),
    (dict(channel_group=""), "channel_group"),
    (dict(channel_group="Stable"), "channel_group"),
])
def test_invalid_values_rejected(overrides, needle):
    problems = make_config(**overrides).validate()
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize("overrides", [
    dict(subscription_id=None),
    dict(nodepool_name="workers-2"),
    dict(vnet_name="My_VNet.1", nsg_name="n", worker_subnet_name="w_"),
    dict(channel_group="candidate"),
    dict(channel_group="some-new-group"),
])
def test_valid_values_accepted(overrides):
    assert make_config(**overrides).validate() == []


# -- network (CFG-22..25) ------------------------------------------------------

@pytest.mark.parametrize("overrides", [
    dict(worker_subnet_prefix="fd00::/64"),
    dict(vnet_address_prefix="fd00::/48", worker_subnet_prefix="fd00:0:0:1::/64",
         vnet_integration_subnet_prefix="fd00:0:0:2::/64"),
])
def test_ipv6_rejected_cleanly(overrides):
    problems = make_config(**overrides).validate()
    assert any("IPv4" in p for p in problems), problems


@pytest.mark.parametrize("prefix,ok", [("10.0.1.0/28", True), ("10.0.1.0/29", False)])
def test_integration_subnet_minimum_28(prefix, ok):
    problems = make_config(vnet_integration_subnet_prefix=prefix).validate()
    assert (problems == []) is ok
    if not ok:
        assert any("/28" in p and "Microsoft" in p for p in problems)


def test_worker_minimum_is_labelled_a_tool_constraint():
    problems = make_config(worker_subnet_prefix="10.0.4.0/25").validate()
    assert any("tool constraint" in p for p in problems)


@pytest.mark.parametrize("vnet,w,i", [
    ("10.128.0.0/16", "10.128.0.0/24", "10.128.1.0/24"),
    ("172.30.0.0/16", "172.30.0.0/24", "172.30.1.0/24"),
])
def test_vnet_overlapping_cluster_networks_rejected(vnet, w, i):
    problems = make_config(vnet_address_prefix=vnet, worker_subnet_prefix=w,
                           vnet_integration_subnet_prefix=i).validate()
    assert any("cluster" in p and "CIDR" in p for p in problems), problems


# -- D18: private vault without a private endpoint -----------------------------

def test_d18_az_cli_private_vault_needs_private_endpoint():
    problems = make_config(vault_visibility="Private").validate()
    assert any("--keyvault-private-endpoint" in p for p in problems)
    assert make_config(keyvault_private_endpoint=True).validate() == []


def test_d18_terraform_private_vault_rejected():
    problems = make_config(vault_visibility="Private", backend="terraform").validate()
    assert any("public network access" in p for p in problems)


# -- D17: terraform node pool constraints --------------------------------------

def test_d17_terraform_rejects_skip_nodepool():
    problems = make_config(backend="terraform", skip_nodepool=True).validate()
    assert any("skip_nodepool" in p for p in problems)
    assert make_config(skip_nodepool=True).validate() == []  # az-cli is fine


def test_d17_terraform_requires_two_replicas():
    assert make_config(backend="terraform", nodepool_replicas=2).validate() == []
    problems = make_config(backend="terraform", nodepool_replicas=1).validate()
    assert any(">= 2" in p for p in problems)


# -- D4: overrides re-derive names ---------------------------------------------

def test_d4_with_overrides_rederives_derived_names():
    cfg = make_config(cluster_name="alpha").with_overrides(cluster_name="beta")
    assert (cfg.keyvault_name, cfg.vnet_name, cfg.nsg_name, cfg.managed_resource_group) == (
        "beta-kv", "beta-vnet", "beta-nsg", "beta-managed-rg")
    assert "alpha" not in json.dumps(cfg.to_dict())


def test_d4_with_overrides_keeps_explicit_names(tmp_path):
    cfg = ClusterConfig.load(write(tmp_path, MINIMAL + "vnet_name: custom-vnet\n"))
    out = cfg.with_overrides(cluster_name="beta", resource_group="beta-rg", location=None)
    assert out.vnet_name == "custom-vnet" and out.nsg_name == "beta-nsg"
    assert out.resource_group == "beta-rg" and out.location == "eastus"
    # Explicitness survives a second round of overrides.
    assert out.with_overrides(cluster_name="gamma").vnet_name == "custom-vnet"


def test_d4_with_overrides_private_endpoint_forces_private_vault():
    cfg = make_config().with_overrides(keyvault_private_endpoint=True)
    assert cfg.vault_visibility == "Private" and cfg.validate() == []


def test_d4_with_overrides_unknown_key():
    with pytest.raises(ConfigError, match="unknown config overrides"):
        make_config().with_overrides(clustr_name="x")


def test_explicit_names_not_serialised():
    assert "_explicit_names" not in make_config(vnet_name="v-net").to_dict()


# -- CFG-11a: truncated vault name collision warning ---------------------------

def test_long_cluster_name_warns_about_shared_vault_name():
    a = make_config(cluster_name="abcdefghijklmnopqrstuvwxyz-one")
    b = make_config(cluster_name="abcdefghijklmnopqrstuvwxyz-two")
    assert a.keyvault_name == b.keyvault_name  # derivation unchanged (teardown relies on it)
    assert any("same" in w for w in a.warnings())
    assert make_config().warnings() == []
