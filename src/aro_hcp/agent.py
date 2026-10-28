"""The provisioning agent: Claude driving the plan through tools.

The agent never constructs `az` commands itself. It can inspect the
environment, read the plan, and ask for phases to run; the executor owns every
write, and in plan mode it refuses them.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from .config import ClusterConfig
from .executor import Executor
from .preflight import run_preflight
from . import state as state_mod

MODEL = "claude-opus-5"
MAX_TOKENS = 16000

#: Verbs `inspect_azure` will run. Everything else is a potential write.
ALLOWED_INSPECT_VERBS = frozenset({
    "show", "list", "wait", "check-name", "get-versions",
    "list-usage", "list-sizes", "list-locations", "list-skus",
})

SYSTEM_PROMPT = """\
You provision Azure Red Hat OpenShift with hosted control planes (ARO HCP) \
clusters, following the Microsoft Learn procedure
"Create a cluster - Azure Red Hat OpenShift with hosted control planes":
https://learn.microsoft.com/azure/openshift/howto-create-custom-hosted-cluster?pivots=aro-az-cli

The procedure is already encoded as an ordered plan of `az` steps. You do not \
write commands; you drive the plan through tools.

Phases, in order:
  providers        register Microsoft.RedHatOpenShift / Compute / Storage / Authorization
  resource-group   create the customer resource group
  network          NSG, VNet, worker subnet, delegated VNet integration subnet
  identities       8 control-plane + 3 data-plane + service + KMS managed identities
  role-assignments ~30 assignments onto the VNet, NSG, and the identities themselves
  etcd-encryption  Key Vault, RSA-2048 KMS key, Crypto Officer/User grants
  cluster          az aro hcp cluster create (15-20 minutes)
  nodepool         az aro hcp cluster nodepool create

Rules:
- Run `preflight` first and resolve blocking findings before anything else. \
Report warnings; do not silently proceed past a FAIL.
- Work phase by phase in order. Never skip ahead: later phases consume resource \
IDs that earlier phases capture.
- Every step is idempotent. A step reported "skipped: already present" is a \
success — a resumed run is expected to skip a lot.
- On failure, read the error, use `inspect_azure` to check actual state, and \
explain the cause. Retry only when you have a specific reason to think it will \
behave differently (eventual consistency on a fresh identity, a transient \
throttle). Do not retry a permissions or quota error — surface it.
- Permission propagation is the common failure, and the executor already \
retries it for you with backoff: PrincipalNotFound after the identities phase, \
and ForbiddenByRbac on a Key Vault step whose own Crypto Officer grant has not \
reached the vault's data plane yet. If such a step still fails after the \
executor's retries, check with inspect_azure whether the role assignment \
exists; if it does, the fix is to run the step again, not to change anything. \
AuthorizationFailed is different — it means the operator lacks User Access \
Administrator or Owner. Stop and say so; do not retry it.
- Cluster creation is billable and slow. Mention it before starting that phase.
- When you are done, summarise: what was created, what was skipped, what failed, \
and the exact next command the operator should run.

In plan mode no writes happen: `execute_*` returns the commands it would run. \
Walk the plan, report what would be created, and flag risks. Do not pretend \
resources were created.
"""

#: Appended to whichever system prompt applies when the run uses Terraform.
#: The phases and the failure modes are different enough that the az-only
#: guidance above would be actively misleading.
TERRAFORM_NOTE = """\

THIS RUN USES THE TERRAFORM BACKEND, not the az CLI procedure. Ignore the \
az phase list above; call show_plan for the real one. The steps shell out to \
the upstream rh-mobb Terraform module, cloned at a pinned ref.

Phases, in order:
  workspace       fetch the module at the pinned ref, write the tfvars
  init            terraform init, downloading providers
  plan            terraform plan - a real diff, and it runs in plan mode too
  apply           terraform apply - creates everything, 15-20 minutes, billable
  outputs         read the API and console URLs back out

What differs from the az backend, and matters:
- Terraform owns its own state file. A step this tool records as "done" is \
not the same thing as a resource Terraform knows about. When they disagree, \
Terraform's state is the truth; read it with show_plan and the tf-plan output.
- The two backends name resources differently - the Key Vault is \
cust-kv-<random> here, and the identities drop the -cp- and \
-managed-identity affixes. Never tell the operator that a cluster built one \
way can be managed the other way.
- Teardown removes the node pools from Terraform state before destroying \
(OCPBUGS-86702: the resource provider rejects DELETE of the last node pool). \
Do not reorder those steps, and do not suggest a bare `terraform destroy`.
- inspect_azure still runs `az`, not `terraform`. Use it to check what is \
really in the subscription when Terraform's view looks wrong.
"""

DESTROY_SYSTEM_PROMPT = """\
You are tearing down an Azure Red Hat OpenShift hosted control plane (ARO HCP) \
cluster and the resources created alongside it. The teardown is already \
encoded as an ordered plan of `az` steps; you drive it through tools and do \
not write commands yourself.

Phases, in order — the order is a dependency chain, never reorder it:
  nodepool         delete the node pool, then the cluster's node pools are gone
  cluster          delete the cluster, then sweep the Azure-managed resource group
  etcd-encryption  delete the Key Vault, then purge it to free the name
  identities       delete the 13 managed identities
  network          delete the VNet, then the NSG attached to its subnet
  resource-group   delete the customer resource group

Rules:
- This destroys real infrastructure and cannot be undone. Before the first \
destructive phase, state plainly what will be deleted and confirm the cluster \
name and resource group match what the operator intended.
- Call show_plan first and report the full list. If anything in it looks like \
it belongs to a different cluster, stop and ask.
- A step reported "skipped: already gone" is a success, not a problem.
- Cluster deletion takes 15-30 minutes. Say so before starting it.
- `keyvault-purge` is irreversible and frees the vault name. Without it the \
name stays reserved by soft delete and recreating the cluster fails. Call that \
out rather than skipping it silently.
- If a delete fails because a resource is still in use, the usual cause is an \
earlier phase that has not finished. Use inspect_azure to check, wait, retry.
- Never unregister resource providers; they are subscription-wide.
- Finish with a summary: what was deleted, what was already gone, what failed, \
and anything left behind that the operator must clean up by hand.

In plan mode nothing is deleted: `execute_*` reports the commands it would run.
"""


@dataclass
class AgentResult:
    text: str
    turns: int
    stop_reason: str | None


def _json(payload) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def build_tools(executor: Executor, config: ClusterConfig):
    """Build the agent's tool set, bound to one executor."""
    from anthropic import beta_tool

    az = executor.az
    by_id = executor.steps_by_id()
    # Derived from the loaded plan, so the destroy plan's phases validate too.
    phases = tuple(dict.fromkeys(step.phase for step in executor.plan))

    @beta_tool
    def preflight() -> str:
        """Check the environment before provisioning.

        Validates the cluster configuration and checks the az CLI version, the
        aro extension, Azure sign-in, resource provider registration, VM core
        quota in the target region, OpenShift version availability, and name
        collisions. Run this first.
        """
        return _json(run_preflight(az, config).to_dict())

    @beta_tool
    def show_config() -> str:
        """Return the cluster configuration this run is working from."""
        return _json(config.to_dict())

    @beta_tool
    def show_plan(phase: str = "") -> str:
        """List the provisioning steps and their current status.

        Args:
            phase: Limit to one phase. One of providers, resource-group,
                network, identities, role-assignments, etcd-encryption,
                cluster, nodepool. Empty means every phase.
        """
        if phase and phase not in phases:
            return f"unknown phase {phase!r}; valid phases: {', '.join(phases)}"
        rows = executor.render_plan([phase] if phase else None)
        return _json([
            {
                "id": step.id,
                "phase": step.phase,
                "status": status,
                "description": step.description,
                "command": command,
                "unresolved": step.unresolved(executor.context),
            }
            for step, status, command in rows
        ])

    @beta_tool
    def show_state() -> str:
        """Return captured resource IDs and a count of steps by status."""
        return _json({
            "apply_mode": executor.apply,
            "summary": executor.state.summary(),
            "pending_steps": [s.id for s in executor.pending()],
            "context": executor.context,
        })

    @beta_tool
    def execute_phase(phase: str) -> str:
        """Run every incomplete step in one phase, stopping at the first failure.

        In plan mode this performs no writes and reports the commands instead.

        Args:
            phase: One of providers, resource-group, network, identities,
                role-assignments, etcd-encryption, cluster, nodepool.
        """
        if phase not in phases:
            return f"unknown phase {phase!r}; valid phases: {', '.join(phases)}"
        outcomes = executor.run_phase(phase)
        return _json({
            "phase": phase,
            "outcomes": [
                {
                    "id": o.step.id,
                    "status": o.status,
                    "message": o.message,
                    "stdout": o.stdout[:2000],
                    "stderr": o.stderr[:2000],
                    "command": o.command,
                }
                for o in outcomes
            ],
        })

    @beta_tool
    def execute_step(step_id: str, force: bool = False) -> str:
        """Run a single step by id.

        Args:
            step_id: The step id, as reported by show_plan.
            force: Re-run even if state records it as already complete. Use
                this only to retry a step whose recorded success you have
                reason to distrust.
        """
        step = by_id.get(step_id)
        if step is None:
            return f"unknown step {step_id!r}; call show_plan for valid ids"
        outcome = executor.run_step(step, force=force)
        if executor.persist:
            executor.state.save()
        return _json({
            "id": outcome.step.id,
            "status": outcome.status,
            "message": outcome.message,
            "stdout": outcome.stdout[:4000],
            "stderr": outcome.stderr[:4000],
            "command": outcome.command,
        })

    @beta_tool
    def inspect_azure(args: str) -> str:
        """Run a read-only `az` command to diagnose a problem.

        Only inspection verbs are permitted (show, list, get-*, check-*,
        wait, version); anything that could change state is rejected.

        Args:
            args: The az arguments without the leading "az", e.g.
                "network vnet subnet show --name worker-subnet --vnet-name v --resource-group rg".
        """
        import shlex

        try:
            argv = shlex.split(args)
        except ValueError as exc:
            return f"could not parse arguments: {exc}"
        if not argv:
            return "no arguments given"
        if argv[0] == "az":
            argv = argv[1:]
        # The verb is the last positional token before the first flag. Checking
        # only that position matters: `group create --name show` must not pass
        # just because "show" appears somewhere in the argv.
        positional = []
        for token in argv:
            if token.startswith("-"):
                break
            positional.append(token)
        verb = positional[-1] if positional else ""
        if verb not in ALLOWED_INSPECT_VERBS:
            return (
                f"rejected: {verb or '(none)'!r} is not a read-only verb. "
                f"inspect_azure accepts only {sorted(ALLOWED_INSPECT_VERBS)}. "
                "Use execute_step for writes."
            )
        result = az.run(argv, check=False, force=True)
        return _json({
            "command": result.command,
            "returncode": result.returncode,
            "stdout": result.stdout[:6000],
            "stderr": result.stderr[:2000],
        })

    return [
        preflight, show_config, show_plan, show_state,
        execute_phase, execute_step, inspect_azure,
    ]


def run_agent(
    executor: Executor,
    config: ClusterConfig,
    instruction: str,
    *,
    model: str = MODEL,
    max_turns: int = 80,
    destroy: bool = False,
    on_text: Callable[[str], None] | None = None,
) -> AgentResult:
    """Drive the plan with Claude until it stops calling tools."""
    import anthropic

    client = anthropic.Anthropic()
    tools = build_tools(executor, config)
    system = DESTROY_SYSTEM_PROMPT if destroy else SYSTEM_PROMPT
    if config.backend == "terraform":
        system += TERRAFORM_NOTE

    if destroy:
        mode = ("DESTROY MODE — deletions are live and irreversible."
                if executor.apply else
                "DESTROY PLAN MODE — nothing will be deleted; execute_* reports commands.")
    else:
        mode = "APPLY MODE — writes are live and billable." if executor.apply else (
            "PLAN MODE — no writes will happen; execute_* reports commands only."
        )
    prompt = (
        f"{mode}\n"
        f"Cluster: {config.cluster_name} in {config.location} "
        f"(resource group {config.resource_group}, subscription "
        f"{config.subscription_id or 'from the active az context'}).\n\n"
        f"{instruction}"
    )

    runner = client.beta.messages.tool_runner(
        model=model,
        max_tokens=MAX_TOKENS,
        system=system,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        tools=tools,
        messages=[{"role": "user", "content": prompt}],
    )

    turns = 0
    last = None
    for message in runner:
        turns += 1
        last = message
        for block in message.content:
            if block.type == "text" and on_text:
                on_text(block.text)
        if turns >= max_turns:
            break

    if last is None:
        return AgentResult("the model returned no messages", 0, None)
    if last.stop_reason == "refusal":
        detail = getattr(last.stop_details, "explanation", "") if last.stop_details else ""
        return AgentResult(f"the model declined this request. {detail}".strip(), turns, "refusal")

    text = "\n".join(b.text for b in last.content if b.type == "text")
    return AgentResult(text, turns, last.stop_reason)
