---
name: provision-aro-hcp
description: >-
  Provision, plan, or troubleshoot an Azure Red Hat OpenShift cluster with
  hosted control planes (ARO HCP) using the aro-hcp agent. Use when the user
  asks to create, plan, resume, debug, or tear down an ARO HCP cluster, node
  pool, managed identities, or the etcd encryption Key Vault — with either the
  az CLI or the Terraform backend.
---

# Provision an ARO HCP cluster

Wraps the `aro-hcp` CLI, which encodes the Microsoft Learn procedure
[Create a cluster — ARO with hosted control planes](https://learn.microsoft.com/azure/openshift/howto-create-custom-hosted-cluster?pivots=aro-az-cli)
as an ordered, idempotent, resumable plan of ~86 `az` steps. It can build the
same cluster from the same config with Red Hat's
[Terraform module](https://cloud.redhat.com/experts/aro/terraform-hcp/) instead
— see [Choosing a backend](#choosing-a-backend).

**Never hand-write the `az` commands, and never run `terraform` directly.** The
plan already has them, with the role definition GUIDs, the subnet delegation,
and the 13 managed identities wired up correctly. Hand-rolling them is how role
assignments get missed; a bare `terraform` invocation bypasses the tfvars
generation, the per-cluster state file, and the teardown workaround below.

## Choosing a backend

One `cluster.yaml`, two ways to build it. Set `backend:` in the config or pass
`--backend {az-cli,terraform}` on any subcommand.

| | `az-cli` (default) | `terraform` |
|---|---|---|
| Needs | nothing beyond the az CLI | `terraform` ≥ 1.9 and `git` |
| Mirrors | the Microsoft Learn doc, step by step | the upstream `rh-mobb` module |
| Resume | per step, from the state file | per step, plus Terraform's own state |
| Preview | the exact commands it would run | a real `terraform plan` diff |
| Drift detection | no — re-apply re-checks each resource exists | yes — fresh `terraform plan` every run |

Pick `az-cli` when the user wants no extra tooling, step-level resume, or a
run they can compare line by line against the Microsoft doc. Pick `terraform`
when they want a true diff before applying, drift detection afterwards, or they
already manage Azure with Terraform. If they have not said, ask rather than
guess — switching later is not free, for the reason below.

**The two backends are not interchangeable for one cluster.** They name
resources differently: the Key Vault is `<cluster>-kv` under `az-cli` and
`cust-kv-<random>` under Terraform, and the identities differ too
(`<cluster>-cp-cluster-api-azure` versus `<cluster>-cluster-api-azure`).
Terraform cannot adopt what the az path built — it would create a second,
overlapping set of resources. Whichever backend builds a cluster must also tear
it down. Either backend refuses to build or tear down a cluster whose state
under the *other* backend shows completed steps (or is unreadable); if a user
hits that, the answer is to use the original backend, not to work around the
guard. The footprints differ beyond names too: Terraform adds an `eso`
identity, grants the deployer Key Vault Administrator rather than Crypto
Officer, and does not support a private Key Vault, `skip_nodepool`, or fewer
than 2 replicas — validation rejects those combinations.

At the pinned module ref, Terraform builds in two stages with two `az` role
assignments in between (steps tagged `d31-workaround`): the module omits VNet
grants that the resource provider now requires. Do not remove those steps.

Terraform phases are `workspace` → `init` → `plan` → `apply` → `outputs`. The
first three write nothing to Azure, so `plan --backend terraform` runs a real
`terraform plan` and prints the actual diff. The module is cloned at a pinned
ref into `.aro-hcp/terraform-src/` (it is not vendored — upstream ships no
LICENSE); `terraform_dir:` points at your own checkout instead.

## Workflow

Commands below assume `aro-hcp` is on PATH
(`uv tool install git+https://github.com/kumuduh/aro-hcp-agent`). Inside a
clone of that repo, prefix them with `uv run` instead. Check with
`aro-hcp --help` before assuming either.

1. **Config.** If the user has no config file, `aro-hcp init -o cluster.yaml`,
   then edit it with their values. Required: `cluster_name`, `location`,
   `resource_group`, `cluster_version`, `nodepool_version`. Everything else is
   derived from `cluster_name`. Settle the backend here, before anything is
   built — every later command needs the same one. If the user wants Red Hat
   images or OperatorHub content, set `pull_secret_path:` to their pull secret
   (relative to the config file); never read, print or commit its contents.

2. **Preflight.** `aro-hcp preflight -c cluster.yaml`
   Resolve every `FAIL` before going further. Common ones:
   - `region` — ARO HCP is preview and regional; the remedy lists the live set.
   - `cluster-version` / `nodepool-version` — the remedy lists what is offered.
   - `quota` — needs 20+ cores in the node pool's VM family; requires a support ticket.
   - `managed-rg` — a stale managed resource group must be deleted first.
   - `terraform` / `terraform-module` — only on that backend; the binary is
     missing or older than the module's `required_version`.
   - `pull-secret` — `pull_secret_path` is set but neither `oc` nor `kubectl`
     is on PATH.
   - `identity` — users, service principals and managed identities
     (`az login --identity`) all work; a FAIL means the principal's object id
     could not be read from its access token.

3. **Plan.** `aro-hcp plan -c cluster.yaml -v`
   Show the user the phase breakdown and the pending write count. Nothing is
   created. Quote versions in the config: YAML reads `4.20` as `4.2`, and
   validation rejects it. Resource IDs that do not exist yet render as `${SUBNET_ID}` — that
   is expected on a greenfield run, not an error. On the terraform backend this
   clones the module, writes the tfvars and runs a genuine `terraform plan`;
   show the user its resource counts.

4. **Confirm.** Creating the cluster is billable and takes 15–20 minutes, plus
   the node pool. Get explicit confirmation before apply — do not infer it from
   "set up a cluster".

5. **Apply.** `aro-hcp apply -c cluster.yaml`
   Prompts once, after preflight, then runs straight through — it does not
   stop between phases. Add `-y` only if the user asked for unattended, or
   `--confirm-each-phase` if they want to approve each one. Phases run in
   order: providers → resource-group → network → identities →
   role-assignments → etcd-encryption → cluster → nodepool → pull-secret
   (the last only with `pull_secret_path`).
   On the terraform backend, apply refuses a fresh plan that deletes or
   replaces anything. Show the user the listed resources; pass
   `--allow-deletes` only after they confirm those deletions are intended.

6. **Resume.** Apply is idempotent and writes state to `.aro-hcp/<cluster>.state.json`
   after every step. Completed steps are re-checked against Azure, so a resource
   deleted out of band is recreated. A cluster still `Provisioning` stops the
   run with exit 5 ("re-run apply when the operation finishes") — wait and
   re-run; do not treat it as done. Exit codes: 0 ok, 1 failed, 2 config/state,
   3 declined, 4 preflight blocked, 5 incomplete.
   The state file is bound to its cluster, subscription and settings; changing
   the region, network or node pool after a partial build is refused.
   (`<cluster>.tf.state.json` on the terraform backend). After any failure, fix
   the cause and re-run the same command — completed steps are skipped.
   `aro-hcp status -c cluster.yaml` shows progress. Keep passing the
   same `--backend`: the two keep separate state files, and a resume under the
   wrong one starts from scratch.

## Teardown

`aro-hcp destroy -c cluster.yaml` prints the plan and deletes nothing.
Adding `--apply` deletes, and prompts the operator to type the cluster name.

**Always show the plan first and get explicit confirmation naming the cluster
and resource group.** Never infer a teardown from "clean up" or "I'm done" —
this deletes a cluster and a resource group and cannot be undone. Do not pass
`-y` unless the user asked for unattended teardown in those words.

Tear down with the backend that built it — see the warning above.

On `az-cli`, order is a dependency chain and must not be reordered: cluster →
managed RG → Key Vault delete → Key Vault purge → identities → Key Vault private
endpoint and DNS link/zone (if present) → VNet → NSG → resource group. The tool
enforces it per step: `--phase` and `--keep-going` cannot run the vault,
identity or network deletes while the cluster still exists. The confirmation
lists resources in the group that aro-hcp did not create — read them out to the
user; they will be deleted with the group.

- **There is no node pool delete step, and adding one would break the
  teardown.** OCPBUGS-86702: the RP rejects `DELETE` of a cluster's last node
  pool, and this tool only ever creates one. Deleting the cluster cascades
  them. If a user reports `The last node pool can not be deleted`, they are on
  an older version — the fix is to upgrade, not to delete the pool by hand.
- The purge is irreversible and frees the vault name. Skipping it leaves the
  name reserved by soft delete, and recreating the same cluster then fails.
- Cluster deletion takes 15–30 minutes.
- `skipped: already gone` is success, not a problem.
- Teardown has its own state file, so it never interferes with a build run.
  On success both the build and the teardown state files are removed, so a
  rebuilt cluster with the same name is torn down for real next time.

On `terraform`, phases are `workspace` → `init` → `nodepool-state` → `destroy`.

- **Never suggest a bare `terraform destroy`; it fails.** OCPBUGS-86702: the
  resource provider rejects `DELETE` of a cluster's last node pool, which is the
  first thing destroy attempts. The `nodepool-state` phase drops the node pools
  from Terraform state first and leaves ARM to cascade them when the cluster
  goes. That phase removes *state entries only* — it deletes nothing in Azure.
- The module and tfvars are refetched first, so a teardown works from a fresh
  checkout.
- Terraform purges the Key Vault itself (`purge_soft_delete_on_destroy`), so
  there is no separate purge step to check.

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `PrincipalNotFound` on a role assignment | Azure AD propagation lag after creating the identity | Apply retries this automatically (15/30/60/120s). If it still fails, re-run apply |
| `Forbidden` / `ForbiddenByRbac` on `kms-key-version` or another Key Vault step | The Crypto Officer grant has not reached the Key Vault **data plane** yet — the control plane shows it immediately, the data plane lags | Same automatic retry. Confirm the grant is real with `az role assignment list --scope <vault-id>`; if it is, just re-run apply |
| `AuthorizationFailed` on role assignments | Operator lacks User Access Administrator or Owner | Stop; the user needs the role granted. Do not retry |
| Node pool stuck provisioning | NSG denies required traffic | Check the NSG against [required traffic](https://learn.microsoft.com/azure/openshift/howto-plan-cluster-network) |
| Cluster create rejects the KMS key | `vault_visibility` does not match the Key Vault network config | Both must be `Private` when `--keyvault-private-endpoint` is passed |
| `unresolved variables` on a step | An earlier phase did not complete | Run the earlier phase; check `status` |
| `no longer accepted` on a config key | `keyvault_name`, `kms_key_name`, `keyvault_private_endpoint` stopped being config keys when the terraform backend landed | The error names the replacement; delete the line |
| `records N completed az-cli step(s)` on a terraform run | The az backend already built part of this cluster | Destroy with `--backend az-cli` first, or use a different `cluster_name`; do not try to force past it |
| `terraform plan` errors about an undeclared variable | The pinned module ref moved, or `terraform_dir` points at a different version | Check `terraform_ref`; point `terraform_dir` at a matching checkout |
| `MissingRequiredPermissions` for `dp-file-csi-driver` / `dp-image-registry` on a terraform build | The pinned module omits two VNet role grants (D31) | The `d31-workaround` steps add them; if they were disabled, re-enable `D31_ROLE_WORKAROUND`. If RBAC is still propagating, re-run apply |
| `records cluster X, not Y` / `recorded with different settings` | The state file belongs to another cluster, subscription or config | Do not edit or delete it to get past this; use the matching config, or tear down first |
| `another aro-hcp run is using ...` | A concurrent run holds the state lock | Wait for it; never run two applies against one cluster |
| `blocked: needs cluster-delete first` | A teardown step's prerequisite (usually the cluster) still exists | Run the earlier phase; never force past it — the vault holds the live etcd key |
| `exists but is still Provisioning` (exit 5) | A long-running create has not finished | Wait, then re-run apply |
| `terraform plan would delete or replace N resource(s)` | Drift, or a module change, makes the plan remove something | Show the user the list and `aro-hcp plan --backend terraform -v`; re-run with `--allow-deletes` only on their explicit go-ahead |
| `terraform_ref 'X' now resolves to …, but this cluster's state records …` | A branch or tag in `terraform_ref` moved upstream | Pin `terraform_ref` to the recorded SHA to keep the module the cluster was built with; moving to the new SHA is the user's decision |
| `pull-secret` step: `Unauthorized` / connection errors after retries | The API is unreachable from here (often `api_visibility: Private`) | Re-run `apply --phase pull-secret` from a host that reaches the API |

## Scoped runs

- One phase: `apply --phase network`, or `--phase plan` on the terraform backend
- Skip the node pool: set `skip_nodepool: true`
- Add or rotate only the pull secret: `apply --phase pull-secret` (re-applied
  whenever the file's content changes)
- Private Key Vault: pass `--keyvault-private-endpoint` (forces
  `vault_visibility: Private` and adds the private endpoint + DNS steps).
  **az-cli backend only** — the upstream module has no equivalent, and the
  combination is rejected rather than silently building a public vault.

## Standalone agent mode

`aro-hcp agent "..."` runs the same plan under Claude via the
Anthropic SDK — for CI or unattended use outside this session. It needs
`ANTHROPIC_API_KEY`. `--apply` runs preflight and the same confirmation as
`apply` first; `--destroy --apply` requires the typed cluster name (or `-y`). Inside Claude Code you are already the agent, so prefer the
deterministic subcommands above; mention `agent` only if the user wants it to
run outside the session.
