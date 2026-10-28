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

Every step records its outcome in `.aro-hcp/<cluster>.state.json`, and every
step checks whether its resource already exists before creating it. After a
failure, fix the cause and re-run the same `apply` — completed steps are
skipped. The same property makes it safe to point at a partially built cluster.

## Backends

Two ways to build the same cluster from the same `cluster.yaml`. Pick one with
`backend:` in the config or `--backend` on any command.

| | `az-cli` (default) | `terraform` |
|---|---|---|
| What runs | ~86 `az` commands from the Microsoft Learn doc | Red Hat's [rh-mobb module](https://github.com/rh-mobb/validated-pattern-aro-hcp) |
| Extra tooling | none | `terraform` ≥ 1.9 and `git` |
| Resume | per step, from `.aro-hcp/<cluster>.state.json` | per step, plus Terraform's own state |
| Preview | the exact commands it would run | a real `terraform plan` diff |
| Drift detection | no | yes |

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
`apply --backend terraform` refuses outright when the az state file shows
completed steps for that cluster.

The module is **cloned at a pinned ref** into `.aro-hcp/terraform-src/` rather
than vendored here, because the upstream repository ships no LICENSE file. Set
`terraform_dir:` to use your own checkout instead. Each cluster gets its own
`TF_DATA_DIR` and state file, so one checkout can back several.

Three upstream defaults are pinned in the generated tfvars to keep the two
backends comparable: `enable_external_auth = false` (upstream defaults *true*
and registers an Entra application, which the az path never does),
`enable_jumpbox = false`, and `pull_secret_path = ""`. The generated file says
so inline.

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
| `role-assignments` | 29 assignments across the VNet, NSG, and the identities |
| `etcd-encryption` | Key Vault (RBAC), RSA-2048 KMS key, Crypto Officer/User grants, optional private endpoint |
| `cluster` | `az aro hcp cluster create` — 15–20 minutes, billable |
| `nodepool` | `az aro hcp cluster nodepool create` |

Run one phase at a time with `--phase network`.

## Teardown

```bash
aro-hcp destroy -c cluster.yaml          # plan only
aro-hcp destroy -c cluster.yaml --apply  # delete
```

`destroy` reverses the build plan in dependency order: cluster → managed
resource group → Key Vault (delete, then **purge**) → 13 identities → VNet →
NSG → resource group. Resource providers are never unregistered.

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

It keeps its own state file (`<cluster>.destroy.state.json`) so it never reads
or clobbers the build run's, and each step probes first — a resource that is
already gone is skipped, so a failed teardown resumes cleanly. On success the
stale build state is removed so a later `apply` starts fresh.

The Key Vault purge matters: soft delete outlives the resource group and keeps
the vault name reserved, so skipping it makes recreating the same cluster fail.

## Preflight

Catches the failures that otherwise surface late:

- az CLI version and the `aro` extension's `hcp` command group
- Azure sign-in and the signed-in principal (needed for the Crypto Officer grant)
- resource provider registration
- VM core quota in the node pool's family (ARO HCP needs 20+)
- **region availability** — ARO HCP is preview and regional; the check reads the
  live region list out of the service's own error rather than a hardcoded list
- cluster and node pool version availability, including channel group
- name collisions, including a stale managed resource group
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

Validation is strict and offline: subnet prefixes must sit inside the VNet and
not overlap, the node pool version must be in the cluster's minor stream, the
managed resource group must differ from the customer one, and Key Vault names
must satisfy Azure's global naming rules.

Config can also come from `ARO_*` environment variables (`ARO_CLUSTER_NAME`, …).

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

`--destroy` points the same agent at the teardown plan, under a system prompt
that holds the dependency order and refuses to reorder it:

```bash
aro-hcp agent --destroy -c cluster.yaml            # review teardown
aro-hcp agent --destroy --apply -c cluster.yaml    # tear down
```

Inside Claude Code, use the bundled skill (`.claude/skills/provision-aro-hcp/`)
instead — Claude is already the agent there, so it drives the deterministic
subcommands directly and no API key is needed.

## Development

```bash
uv run pytest
```
