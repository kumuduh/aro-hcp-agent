# aro-hcp

An agent that provisions **Azure Red Hat OpenShift with hosted control planes**
(ARO HCP) clusters, following the Microsoft Learn procedure
[Create a cluster — ARO with hosted control planes](https://learn.microsoft.com/azure/openshift/howto-create-custom-hosted-cluster?pivots=aro-az-cli).

That procedure is ~86 `az` commands: four resource providers, a delegated VNet,
13 managed identities, 29 role assignments against hardcoded role definition
GUIDs, a Key Vault with a customer-managed etcd encryption key, then the cluster
and a node pool. Getting one role assignment wrong fails the cluster create
20 minutes in. This encodes it as an ordered, idempotent, resumable plan.

It can also build the same cluster with Red Hat's
[Terraform module](https://cloud.redhat.com/experts/aro/terraform-hcp/) from the
same config file — see [Backends](#backends).

## Install

As a tool, which puts `aro-hcp` on your PATH:

```bash
uv tool install git+https://github.com/kumuduh/aro-hcp-agent
```

Or from a clone, for development:

```bash
uv sync      # then prefix the commands below with `uv run`
```

Add `[agent]` to the install for [agent mode](#agent-mode) — it is the only
thing that needs the Anthropic SDK, so it is an optional extra.

Requires Python 3.11+ and the Azure CLI 2.67+ with the `aro` extension:

```bash
az extension add --name aro
az login
```

## Use

```bash
aro-hcp init -o cluster.yaml     # starter config
aro-hcp validate -c cluster.yaml # offline checks
aro-hcp preflight -c cluster.yaml
aro-hcp plan -c cluster.yaml -v  # render every command, create nothing
aro-hcp apply -c cluster.yaml    # create, confirming once
aro-hcp status -c cluster.yaml
aro-hcp destroy -c cluster.yaml  # show the teardown plan, delete nothing
```

`cluster.example.yaml` is a commented sample. `init` writes `cluster.yaml`,
which is gitignored — it names real resources in a real subscription.

`apply` is **plan-then-apply with confirmation**: it asks once, after preflight
and before anything is written, listing what it will build and what it will
bill for. One prompt rather than one per phase, because a prompt you answer
eight times is a prompt you stop reading. Pass `-y` for unattended runs, or
`--confirm-each-phase` to gate every phase.

### Resuming

Every step records its outcome in `.aro-hcp/<cluster>.state.json` as it
finishes, and every step checks whether its resource already exists before
creating it. After a failure, fix the cause and re-run the same `apply`.
Completed steps are re-checked against Azure rather than trusted: one whose
resource has disappeared is redone, and a cluster or node pool only counts
once its provisioning state is `Succeeded`. One still `Provisioning` stops the
run with "re-run apply when the operation finishes" (exit 5) instead of being
reported as provisioned. An existence check that fails for any reason other
than "not found" (403, throttling, timeout) stops the step; it is never read as
"absent".

The state file is bound to its cluster, subscription and the settings it was
built with. Pointing `--state` at another cluster's file, or changing the
region, network prefixes, versions or node pool after a partial build, is
refused rather than resumed. Two runs against the same state file cannot
overlap: the second fails immediately.

## Backends

Two ways to build the same cluster from the same `cluster.yaml`. Pick one with
`backend:` in the config or `--backend` on any command.

| | `az-cli` (default) | `terraform` |
|---|---|---|
| What runs | ~86 `az` commands from the Microsoft Learn doc | Red Hat's [rh-mobb module](https://github.com/rh-mobb/validated-pattern-aro-hcp) |
| Extra tooling | none | `terraform` ≥ 1.9 and `git` |
| Resume | per step, from `.aro-hcp/<cluster>.state.json` | per step, plus Terraform's own state |
| Preview | the exact commands it would run | a real `terraform plan` diff |
| Drift detection | no — re-apply re-checks each resource exists | yes — every `plan`/`apply` runs a fresh `terraform plan` |

```bash
aro-hcp plan    -c cluster.yaml --backend terraform  # real diff, creates nothing
aro-hcp apply   -c cluster.yaml --backend terraform
aro-hcp destroy -c cluster.yaml --backend terraform --apply
```

**The two are not interchangeable for one cluster.** They name things
differently — the Key Vault is `<cluster>-kv` under `az-cli` and
`cust-kv-<random>` under Terraform, and the identities differ too
(`<cluster>-cp-cluster-api-azure` versus `<cluster>-cluster-api-azure`). Terraform
cannot adopt what the az path built; it would create a second, overlapping set.
Either backend refuses to build or tear down a cluster whose state file under
the *other* backend shows completed steps — and an unreadable state file counts
as "may have built something".

The footprints also differ beyond names, at the pinned module ref:

| | `az-cli` | `terraform` |
|---|---|---|
| Managed identities | 13 | 13, plus an `eso` identity with Key Vault Secrets User |
| Deployer's vault role | Key Vault Crypto Officer | Key Vault Administrator |
| etcd key name | `etcd-kms-key` | `etcd-data-kms-encryption-key` |
| Private Key Vault | `--keyvault-private-endpoint` | not supported (the module forces public network access) |
| Node pools | `skip_nodepool`, replicas ≥ 1 | at least one pool, replicas ≥ 2 |

The module is **cloned at a pinned ref** into `.aro-hcp/terraform-src/` rather
than vendored here, because the upstream repository ships no LICENSE file. Set
`terraform_dir:` to use your own checkout instead. Each cluster gets its own
`TF_DATA_DIR` and state file, so one checkout can back several.

Three upstream defaults are pinned in the generated tfvars to keep the two
backends comparable: `enable_external_auth = false` (upstream defaults *true*
and registers an Entra application, which the az path never does),
`enable_jumpbox = false`, and `pull_secret_path = ""`. The generated file says
so inline.

**Missing role assignments in the pinned module (D31).** At the pinned ref the
module grants `dp-file-csi-driver` its File Storage Operator role on the worker
subnet only, and grants `dp-image-registry` nothing; the ARO HCP resource
provider now validates both on the VNet and rejects the cluster
(`MissingRequiredPermissions`). Until upstream fixes it, `apply` runs Terraform
in two stages: `-target=module.network -target=module.identities` first, then
two `az role assignment create` steps for the missing VNet grants, then the full
apply. The steps are tagged `d31-workaround`; set
`aro_hcp.terraform.D31_ROLE_WORKAROUND = False` once the module is fixed.

Terraform runs with a filtered environment: `TF_CLI_ARGS*` and `TF_VAR_*` are
not passed through, and a module directory containing `*.auto.tfvars` or
`terraform.tfvars` is refused, so nothing outside `cluster.yaml` can change what
is applied. The checkout must be exactly the pinned commit and clean.

Teardown removes the node pools from Terraform state before destroying.
OCPBUGS-86702: the resource provider rejects `DELETE` of a cluster's last node
pool, which is the first thing `terraform destroy` tries, so a bare destroy
fails. ARM cascades the pools when the cluster goes.

## Phases

With the `terraform` backend: `workspace` → `init` → `plan` → `apply` →
`outputs`, and for teardown `workspace` → `init` → `nodepool-state` →
`destroy`. With the default `az-cli` backend:

| Phase | What it creates |
|---|---|
| `providers` | Registers `Microsoft.RedHatOpenShift`, `.Compute`, `.Storage`, `.Authorization` |
| `resource-group` | The customer resource group |
| `network` | NSG, VNet, worker subnet, VNet integration subnet with the `hcpOpenShiftClusters` delegation |
| `identities` | 8 control-plane + 3 data-plane + service + KMS managed identities |
| `role-assignments` | 27 assignments across the VNet, NSG, and the identities |
| `etcd-encryption` | Key Vault (RBAC), RSA-2048 KMS key, Crypto Officer/User grants (the other 2 of the 29), optional private endpoint |
| `cluster` | `az aro hcp cluster create` — 15–20 minutes, billable |
| `nodepool` | `az aro hcp cluster nodepool create` |

Run one phase at a time with `--phase network`.

## Teardown

```bash
aro-hcp destroy -c cluster.yaml          # plan only
aro-hcp destroy -c cluster.yaml --apply  # delete
```

`destroy` reverses the build plan in dependency order: cluster → managed
resource group → Key Vault (delete, then **purge**) → 13 identities → Key Vault
private endpoint and private DNS link/zone (if present) → VNet → NSG → resource
group. Resource providers are never unregistered.

The order is enforced per step, not just by phase order: nothing after the
cluster — the KMS vault, the identities, the network — runs until the cluster
is confirmed gone, so neither `--phase etcd-encryption` nor `--keep-going` past a
failed cluster delete can destroy the encryption key under a running control
plane. Every delete is confirmed against Azure before it counts.

Node pools are the one thing it does not delete. OCPBUGS-86702: the resource
provider rejects `DELETE` of a cluster's last node pool, and this tool only
ever creates one, so the request could never succeed. Deleting the cluster
cascades them — the same reason the Terraform teardown drops them from state
first.

Three gates, because this is irreversible:

1. Without `--apply` nothing is deleted — it prints the plan and exits.
2. With `--apply` you must **type the cluster name**, once, before anything is
   deleted. A `y/N` is too easy to answer on autopilot; `-y` skips this for
   automation.
3. Non-interactive runs without `-y` decline rather than guess.

It keeps its own state file (`<cluster>.destroy.state.json`, or
`<name>.destroy.state.json` next to a custom `--state`) so it never reads or
clobbers the build run's, and each step probes first — a resource that is
already gone is skipped, so a failed teardown resumes cleanly. On success both
files are removed: the build state so a later `apply` starts fresh, and the
teardown state so a later teardown of a rebuilt cluster does real work.

Before asking for the cluster name, the confirmation lists anything in the
resource group that aro-hcp did not create — the final step deletes the whole
group, and those resources with it.

The Key Vault purge matters: soft delete outlives the resource group and keeps
the vault name reserved, so skipping it makes recreating the same cluster fail.

## Preflight

Catches the failures that otherwise surface late:

- az CLI version and the `aro` extension's `hcp` command group
- Azure sign-in and the signed-in principal (needed for the Crypto Officer
  grant); a managed-identity login is rejected because it cannot be an assignee
- **rights to create role assignments** (Owner, User Access Administrator, or
  Role Based Access Control Administrator) — otherwise apply would create the
  network and 13 identities and then fail
- resource provider registration
- VM core quota: `replicas × vCPUs` (at least 20) against both the VM family
  and the regional total, and the VM size's availability in the region
- Key Vault name availability, including a soft-deleted vault holding the name
- **region availability** — ARO HCP is preview and regional; the check reads the
  live region list out of the service's own error rather than a hardcoded list
- cluster and node pool version availability, each in its channel group; an
  empty version list is reported as a probable permissions gap, not as
  "version not offered"
- name collisions, including a stale managed resource group, a cluster left in
  `Failed`, and an existing VNet whose address space does not fit the config.
  A lookup that cannot be completed is a warning, never a silent pass
- with `--backend terraform`, the `terraform` version against the module's
  `required_version`, and `git` when a checkout has to be fetched

## Configuration

Only five keys are required; the rest derive from `cluster_name`.

```yaml
cluster_name: my-hcp-cluster
location: eastus2
resource_group: my-hcp-rg
cluster_version: "4.22"
nodepool_version: "4.22.1"
```

Notable optional keys:

| Key | Default | Notes |
|---|---|---|
| `backend` | `az-cli` | `az-cli` or `terraform` |
| `terraform_dir` | *(clone)* | Your own checkout of the module's `terraform/` directory |
| `api_visibility` / `ingress_visibility` | `Public` | `Public` or `Private` |
| `nodepool_replicas` / `nodepool_vm_size` | `2` / `Standard_D8s_v6` | |
| `skip_nodepool` | `false` | Cluster only |

The Key Vault name, the KMS key name, and the private endpoint are **not**
config keys. The first two are derived, and Terraform names the vault itself;
for the third, pass `--keyvault-private-endpoint` (az-cli backend only — it
adds the private endpoint and DNS steps and forces `vault_visibility: Private`).
Setting any of them in the file is an error that names the replacement, rather
than a silently ignored line.

Validation is strict and offline:

- Values must have the right type. **Quote versions** — YAML reads an unquoted
  `4.20` as the number `4.2`. Booleans must be `true`/`false`, not `"false"`;
  `nodepool_replicas` must be an integer; `tags` a flat string map.
- IPv4 only. Subnet prefixes must sit inside the VNet and not overlap; the VNet
  must not overlap the cluster's default pod (`10.128.0.0/14`) or service
  (`172.30.0.0/16`) ranges. The integration subnet must be **/28 or larger**
  (Microsoft's requirement); the worker subnet /24 or larger (a constraint of
  this tool, leaving room to scale).
- The node pool version must be in the cluster's minor stream, the managed
  resource group must differ from the customer one (case-insensitively), and
  every resource name must satisfy Azure's naming rules.
- `vault_visibility: Private` requires `--keyvault-private-endpoint`; a Private
  setting on a public vault made the cluster create hang.
- On the terraform backend, `skip_nodepool` and `nodepool_replicas < 2` are
  rejected: the pinned module would otherwise plan a cluster with no workers.

A malformed or unreadable config file is a clean error naming the file. `.json`
files are read as JSON, everything else as YAML.

Config can also come from `ARO_*` environment variables (`ARO_CLUSTER_NAME`, …).
Boolean variables accept `1/true/yes/on` and `0/false/no/off`; anything else is
an error.

`--cluster-name` (and the other overrides) re-derive every name that was not set
explicitly — the vault, VNet, NSG and managed resource group follow the new
cluster name.

### What the cluster does not include

A cluster built by either backend has **no Red Hat pull secret** (images from
`registry.redhat.io`, including the sample image streams, cannot be pulled) and
**no identity provider** (the web console reports
`OAuthClientSecretGetDegraded`). Use `az aro hcp cluster request-credential
--admin` for break-glass access, and configure a pull secret and external
authentication separately.

## Agent mode

```bash
export ANTHROPIC_API_KEY=...
aro-hcp agent "provision this cluster" --apply -c cluster.yaml
```

Claude drives the same plan through tools (`preflight`, `show_plan`,
`execute_phase`, `execute_step`, `inspect_azure`) rather than writing `az`
commands. It diagnoses failures against real Azure state, distinguishes a
transient AD propagation lag from a permissions problem, and resumes.
Without `--apply` it reviews the plan and reports risks without writing.

The model is not the safety gate. Before an `--apply` run starts, the CLI runs
the same checks as the equivalent command: preflight and the one-time
confirmation for a build, the typed cluster name for `--destroy --apply`
(`-y` skips the prompt; a non-interactive run without `-y` declines). The
executor's dependency checks apply to the agent's tools too — it cannot purge
the vault while the cluster exists. `inspect_azure` runs only an allowlist of
read commands, refuses anything that can return secrets (Key Vault secrets,
storage keys, credentials, tokens), `@file` arguments, `--debug`, and other
subscriptions, and redacts secret-looking values in what it returns. The exit
code reflects the plan, not the model's last message: failed or pending steps,
a refusal, or hitting `--max-turns` exit non-zero.

The model defaults to `claude-opus-5`; set `--model` or `ARO_HCP_MODEL`. The
SDK is pinned below 2.0: SDK 2.x's tool runner sends a field that
Anthropic-compatible gateways (for example Vertex behind `ANTHROPIC_BASE_URL`)
reject.

`--destroy` points the same agent at the teardown plan, under a system prompt
that holds the dependency order and refuses to reorder it:

```bash
aro-hcp agent --destroy -c cluster.yaml            # review teardown
aro-hcp agent --destroy --apply -c cluster.yaml    # tear down
```

Inside Claude Code, use the bundled skill (`.claude/skills/provision-aro-hcp/`)
instead — Claude is already the agent there, so it drives the deterministic
subcommands directly and no API key is needed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done (for `--phase`, the selected phases are done) |
| 1 | A step failed |
| 2 | Config, state or argument problem; nothing ran |
| 3 | Declined by the operator, or no TTY without `-y` |
| 4 | Preflight blocked the run |
| 5 | Nothing failed, but requested work is still pending (e.g. a cluster still provisioning) |
| 130 | Interrupted; re-run the same command to resume |

## Development

```bash
uv run pytest
```
