"""The provisioning agent: Claude driving the plan through tools.

The agent never constructs `az` commands itself. It can inspect the
environment, read the plan, and ask for phases to run; the executor owns every
write, and in plan mode it refuses them.

Two things here are easy to let drift, so they are derived rather than typed:
the phase lists in the system prompts come from the plan modules' phase
tuples (and, at run time, from the loaded plan), and the tools' valid-phase
text is filled in from the executor's plan when the tools are built. A prompt
that named a phase the plan does not have is how the agent ended up offering
to add a node-pool delete to the teardown (D13, OCPBUGS-86702).
"""

from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from .config import ClusterConfig
from .destroy import DESTROY_PHASES
from .executor import Executor
from .plan import PHASES
from .preflight import run_preflight
from .terraform import TERRAFORM_DESTROY_PHASES, TERRAFORM_PHASES
from . import executor as executor_mod

#: Default model id. Configurable: pass ``model=`` to run_agent (the CLI's
#: --model) or set ARO_HCP_MODEL, e.g. for a gateway that serves the model
#: under a different id.
MODEL = "claude-opus-5"
MODEL_ENV = "ARO_HCP_MODEL"
MAX_TOKENS = 16000

#: Longest `inspect_azure` argument string accepted. Real lookups are a few
#: hundred characters; anything near this is a mistake or an injection, and
#: is rejected without being echoed back into the conversation.
MAX_INSPECT_ARGS = 2000
#: Longest step id looked up. Real ones are under 40 characters.
MAX_ID_LENGTH = 100

#: The `az` commands `inspect_azure` will run, as command group -> verbs. An
#: allowlist rather than a verb check: "show"/"list" is not the same as
#: "harmless" (`keyvault secret show`, `storage account keys list`), so only
#: groups an ARO HCP diagnosis actually needs are open, and only their
#: metadata reads. Key Vault is limited to vault metadata and `key show`/
#: `key list`, which return the public half of the RSA KMS key only.
ALLOWED_INSPECT_COMMANDS: dict[tuple[str, ...], frozenset[str]] = {
    (): frozenset({"version"}),
    ("account",): frozenset({"show", "list-locations"}),
    ("ad", "signed-in-user"): frozenset({"show"}),
    ("aro", "hcp"): frozenset({"get-versions"}),
    ("aro", "hcp", "cluster"): frozenset({"show", "list", "wait"}),
    ("aro", "hcp", "cluster", "nodepool"): frozenset({"show", "list"}),
    ("extension",): frozenset({"show", "list"}),
    ("feature",): frozenset({"show", "list"}),
    ("group",): frozenset({"show", "list", "exists"}),
    ("identity",): frozenset({"show", "list"}),
    ("keyvault",): frozenset({"show", "list", "list-deleted", "show-deleted", "check-name"}),
    ("keyvault", "key"): frozenset({"show", "list"}),
    ("monitor", "activity-log"): frozenset({"list"}),
    ("network", "nsg"): frozenset({"show", "list"}),
    ("network", "nsg", "rule"): frozenset({"show", "list"}),
    ("network", "vnet"): frozenset({"show", "list"}),
    ("network", "vnet", "subnet"): frozenset({"show", "list"}),
    ("provider",): frozenset({"show", "list"}),
    ("resource",): frozenset({"show", "list"}),
    ("role", "assignment"): frozenset({"list"}),
    ("role", "definition"): frozenset({"list"}),
    ("vm",): frozenset({"list-usage", "list-skus", "list-sizes"}),
}

#: Command-path words that mark a secret-bearing command. Checked before the
#: allowlist, so widening the allowlist later cannot open one by accident.
_SECRET_WORDS = frozenset({
    "secret", "secrets", "certificate", "certificates", "keys", "download",
    "backup", "export", "appsettings", "get-credentials", "request-credential",
    "get-access-token", "list-keys", "list-secrets", "show-connection-string",
    "list-connection-strings", "generate-sas",
})
_SECRET_FRAGMENTS = ("credential", "secret", "token", "password", "connection-string",
                     "list-publishing", "sas")

#: Global flags refused in inspect_azure: --debug and --verbose put request
#: details (including auth headers) on stderr, and the file flags read or
#: write the operator's disk.
_REFUSED_FLAGS = frozenset({"--debug", "--verbose", "--output-file", "--out-file", "--file"})

_SUBSCRIPTION_IN_ID = re.compile(r"/subscriptions/([^/\s\"']+)", re.IGNORECASE)

SYSTEM_PROMPT_TEMPLATE = """\
You provision Azure Red Hat OpenShift with hosted control planes (ARO HCP) \
clusters, following the Microsoft Learn procedure
"Create a cluster - Azure Red Hat OpenShift with hosted control planes":
https://learn.microsoft.com/azure/openshift/howto-create-custom-hosted-cluster?pivots=aro-az-cli

The procedure is already encoded as an ordered plan of `az` steps. You do not \
write commands; you drive the plan through tools.

Phases, in order:
{phases}

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
- A tool result starting "refused:" comes from a safety interlock, not from \
Azure. Do not retry it or look for another route to the same write; report \
the reason to the operator.
- inspect_azure is limited to metadata reads in this run's subscription. It \
refuses secrets, keys, tokens and credentials by design; do not try to read them.
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
TERRAFORM_NOTE_TEMPLATE = """\

THIS RUN USES THE TERRAFORM BACKEND, not the az CLI procedure. Ignore the \
az phase list above; call show_plan for the real one. The steps shell out to \
the upstream rh-mobb Terraform module, cloned at a pinned ref.

Phases, in order:
{phases}

What differs from the az backend, and matters:
- Terraform owns its own state file. A step this tool records as "done" is \
not the same thing as a resource Terraform knows about. When they disagree, \
Terraform's state is the truth; read it with show_plan and the tf-plan output.
- The two backends name resources differently - the Key Vault is \
cust-kv-<random> here, and the identities drop the -cp- and \
-managed-identity affixes. Never tell the operator that a cluster built one \
way can be managed the other way.
- Teardown is a separate plan, phases {destroy_phases}. It removes the node \
pools from Terraform state before destroying (OCPBUGS-86702: the resource \
provider rejects DELETE of the last node pool). Do not reorder those steps, \
and do not suggest a bare `terraform destroy`.
- inspect_azure still runs `az`, not `terraform`. Use it to check what is \
really in the subscription when Terraform's view looks wrong.
"""

DESTROY_SYSTEM_PROMPT_TEMPLATE = """\
You are tearing down an Azure Red Hat OpenShift hosted control plane (ARO HCP) \
cluster and the resources created alongside it. The teardown is already \
encoded as an ordered plan of `az` steps; you drive it through tools and do \
not write commands yourself.

Phases, in order — the order is a dependency chain, never reorder it:
{phases}

There is no node-pool phase, on purpose. Deleting the cluster deletes its node \
pools with it. OCPBUGS-86702: the resource provider rejects DELETE of a \
cluster's last node pool, and this tool only creates one, so a separate \
node-pool delete can never succeed. Never add, offer or suggest a node-pool \
delete step, and do not report its absence as a gap in the plan.

Rules:
- This destroys real infrastructure and cannot be undone. Before the first \
destructive phase, state plainly what will be deleted and confirm the cluster \
name and resource group match what the operator intended.
- Call show_plan first and report the full list. If anything in it looks like \
it belongs to a different cluster, stop and ask.
- A step reported "skipped: already gone" is a success, not a problem.
- A tool result starting "refused:" comes from a safety interlock, not from \
Azure. Do not retry it or look for another route to the same delete; report \
the reason to the operator.
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

#: Appended to the destroy prompt when the teardown uses Terraform.
TERRAFORM_DESTROY_NOTE_TEMPLATE = """\

THIS TEARDOWN USES THE TERRAFORM BACKEND, not the az CLI plan. Ignore the az \
phase list and the keyvault-purge rule above; call show_plan for the real plan.

Phases, in order:
{phases}

- nodepool-state is `terraform state rm` of the node pools (OCPBUGS-86702). \
It deletes nothing in Azure; destroying the cluster takes the node pools with \
it. It must run before destroy. Never reorder these phases, never add a \
node-pool delete, and never suggest a bare `terraform destroy`.
- Terraform's state, not this tool's, decides what gets destroyed. If they \
disagree, use inspect_azure to check what is really in the subscription.
"""

#: One line per phase in the prompts. A phase missing here is still listed by
#: name, so a prompt can never omit a phase the plan has.
_PHASE_NOTES = {
    "build": {
        "providers": "register Microsoft.RedHatOpenShift / Compute / Storage / Authorization",
        "resource-group": "create the customer resource group",
        "network": "NSG, VNet, worker subnet, delegated VNet integration subnet",
        "identities": "8 control-plane + 3 data-plane + service + KMS managed identities",
        "role-assignments": "~30 assignments onto the VNet, NSG, and the identities themselves",
        "etcd-encryption": "Key Vault, RSA-2048 KMS key, Crypto Officer/User grants",
        "cluster": "az aro hcp cluster create (15-20 minutes)",
        "nodepool": "az aro hcp cluster nodepool create",
        "pull-secret": "only with pull_secret_path: add it as kube-system/additional-pull-secret",
    },
    "destroy": {
        "cluster": "delete the cluster (its node pools go with it), then sweep "
                   "the Azure-managed resource group",
        "etcd-encryption": "delete the Key Vault, then purge it to free the name",
        "identities": "delete the 13 managed identities",
        "network": "delete the VNet, then the NSG attached to its subnet",
        "resource-group": "delete the customer resource group",
    },
    "tf-build": {
        "workspace": "fetch the module at the pinned ref, write the tfvars",
        "init": "terraform init, downloading providers",
        "plan": "terraform plan - a real diff, and it runs in plan mode too",
        "apply": "terraform apply - creates everything, 15-20 minutes, billable",
        "outputs": "read the API and console URLs back out",
        "pull-secret": "only with pull_secret_path: add it as kube-system/additional-pull-secret",
    },
    "tf-destroy": {
        "workspace": "refetch the module at the pinned ref, rewrite the tfvars",
        "init": "terraform init",
        "nodepool-state": "terraform state rm of the node pools (OCPBUGS-86702)",
        "destroy": "terraform destroy - cluster, Key Vault, identities, network, "
                   "resource group; 15-30 minutes",
    },
}


def _phase_lines(phases: Iterable[str], kind: str) -> str:
    phases = list(phases)
    notes = _PHASE_NOTES[kind]
    width = max((len(p) for p in phases), default=0) + 2
    return "\n".join(f"  {p:<{width}}{notes.get(p, '')}".rstrip() for p in phases)


def _terraform_note(phases: Iterable[str]) -> str:
    return (TERRAFORM_NOTE_TEMPLATE
            .replace("{phases}", _phase_lines(phases, "tf-build"))
            .replace("{destroy_phases}", ", ".join(TERRAFORM_DESTROY_PHASES)))


def _terraform_destroy_note(phases: Iterable[str]) -> str:
    return TERRAFORM_DESTROY_NOTE_TEMPLATE.replace(
        "{phases}", _phase_lines(phases, "tf-destroy"))


def system_prompt(
    *, destroy: bool = False, backend: str = "az-cli", phases: Iterable[str] = ()
) -> str:
    """The system prompt for one run, listing the loaded plan's ``phases``.

    Empty ``phases`` means the full phase tuple for the mode, which is what
    the module-level constants below are rendered from.
    """
    phases = tuple(phases)
    if backend == "terraform":
        # The az base prompt keeps its full az list; the note says to ignore it.
        if destroy:
            return (DESTROY_SYSTEM_PROMPT
                    + _terraform_destroy_note(phases or TERRAFORM_DESTROY_PHASES))
        return SYSTEM_PROMPT + _terraform_note(phases or TERRAFORM_PHASES)
    if destroy:
        return DESTROY_SYSTEM_PROMPT_TEMPLATE.replace(
            "{phases}", _phase_lines(phases or DESTROY_PHASES, "destroy"))
    return SYSTEM_PROMPT_TEMPLATE.replace(
        "{phases}", _phase_lines(phases or PHASES, "build"))


SYSTEM_PROMPT = system_prompt()
DESTROY_SYSTEM_PROMPT = system_prompt(destroy=True)
TERRAFORM_NOTE = _terraform_note(TERRAFORM_PHASES)
TERRAFORM_DESTROY_NOTE = _terraform_destroy_note(TERRAFORM_DESTROY_PHASES)


@dataclass
class AgentResult:
    """What the run achieved, in enough detail for the CLI to pick an exit code.

    The model's closing text is not evidence of success — it can say "done"
    after a failed phase (AGT-7) — so ``pending`` is read back from the
    executor. When stop_reason is "refusal", ``text`` carries the model's
    explanation for the caller to print.
    """

    text: str
    turns: int
    stop_reason: str | None
    #: Step ids the executor still reports incomplete when the run ended.
    pending: list[str] = field(default_factory=list)
    #: The run was cut off by max_turns while the model still wanted tools.
    hit_turn_limit: bool = False
    #: Whether this run could write; pending steps only count against apply.
    apply: bool = False

    @property
    def ok(self) -> bool:
        """True only for a run that finished on its own and left nothing undone.

        False for a refusal, a max_tokens cut-off, an empty run, a run that
        ended mid tool call or on the turn limit, and an apply run with
        pending steps.
        """
        if self.hit_turn_limit or self.stop_reason != "end_turn":
            return False
        return not (self.apply and self.pending)


def _json(payload) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _clip(value: object, limit: int = 60) -> str:
    """repr() of a model-supplied value, short enough to echo back."""
    text = repr(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... ({len(str(value))} characters)"


# -- inspect_azure policy ----------------------------------------------------


_RG_IN_ID = re.compile(r"/resourcegroups/([^/\s]+)", re.IGNORECASE)


def check_inspect_args(
    argv: list[str], subscription: str, resource_groups: tuple[str, ...] = (),
) -> str | None:
    """Return why ``argv`` may not run under inspect_azure, or None if it may.

    ``resource_groups``, when given, pins lookups to this cluster's groups:
    the agent diagnoses one cluster, and has no reason to read other teams'
    resources in a shared subscription.
    """
    # The command path is the positional tokens before the first flag.
    # Checking only that matters: `group create --name show` must not pass
    # just because "show" appears somewhere in the argv.
    path: list[str] = []
    for token in argv:
        if token.startswith("-"):
            break
        path.append(token.lower())

    for word in path:
        if word in _SECRET_WORDS or any(f in word for f in _SECRET_FRAGMENTS):
            return (f"{' '.join(path)!r} reads secrets, keys, tokens or credentials, "
                    "which inspect_azure never returns")

    group, verb = tuple(path[:-1]), (path[-1] if path else "")
    if verb not in ALLOWED_INSPECT_COMMANDS.get(group, ()):
        return (f"{' '.join(path) or '(none)'!r} is not an allowed read. inspect_azure "
                "runs only metadata reads (show/list and similar) on the command "
                "groups an ARO HCP diagnosis needs. Use execute_step for writes.")

    flags = argv[len(path):]
    for i, token in enumerate(flags):
        name, _, inline = token.partition("=")
        if token.startswith("-") and name.lower() in _REFUSED_FLAGS:
            return f"{name} is not allowed in inspect_azure"
        # az expands any value starting with "@" into that file's contents,
        # and echoes invalid values back in its error text.
        if token.startswith("@") or inline.startswith("@"):
            return "'@file' values are not allowed; az would read a local file"
        if token.startswith("-") and name == "--subscription":
            value = inline or (flags[i + 1] if i + 1 < len(flags) else "")
            if not subscription or value.lower() != subscription.lower():
                return "--subscription is pinned to this run's subscription; omit it"
    for match in _SUBSCRIPTION_IN_ID.finditer(" ".join(flags)):
        if not subscription or match.group(1).lower() != subscription.lower():
            return ("resource IDs must be in this run's subscription "
                    f"({subscription or 'unknown: set subscription_id in the config'})")
    if resource_groups:
        allowed = {g.lower() for g in resource_groups}
        named: list[str] = []
        for i, token in enumerate(flags):
            name, _, inline = token.partition("=")
            value = inline or (flags[i + 1] if i + 1 < len(flags) else "")
            if name in ("-g", "--resource-group"):
                named.append(value)
            elif group == ("group",) and name in ("-n", "--name"):
                named.append(value)
        named += [m.group(1) for m in _RG_IN_ID.finditer(" ".join(flags))]
        outside = [g for g in named if g and g.lower() not in allowed]
        if outside:
            return (f"resource group {outside[0]!r} is not this cluster's; inspect_azure "
                    f"reads only {', '.join(sorted(resource_groups))}")
        if group == ("group",) and verb == "list":
            return "group list would read every resource group in the subscription; " \
                   "use group show for this cluster's groups"
    return None


#: JSON keys whose string values are withheld from the model, matched on the
#: lowercased key. Dicts and lists under such keys are walked, not dropped,
#: so a cluster's `activeKey` reference (name, vault, version) survives.
_SENSITIVE_KEY = re.compile(
    r"password|passwd|secret|token|credential|connectionstring|signature"
    r"|(?<!public)key$|^sas|sas$"
)
_TEXT_SECRETS = (
    # JWTs: bearer and access tokens.
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*){0,2}"), "[REDACTED-TOKEN]"),
    # Connection-string and SAS segments.
    (re.compile(r"(?i)\b(AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd|sig)"
                r"=[^;&\s\"']+"), r"\1=[REDACTED]"),
)
_BLOB = re.compile(r"[A-Za-z0-9+/_=-]{40,}")


def _redact_blob(match: re.Match) -> str:
    """Withhold long high-entropy runs (keys), but keep paths and names.

    Resource IDs contain "/" and resource names are mostly lowercase; a key
    is mixed-case alphanumerics with digits.
    """
    blob = match.group(0)
    if "/" in blob and not blob.endswith("="):
        return blob
    if re.search(r"[A-Z]", blob) and re.search(r"[a-z]", blob) and re.search(r"\d", blob):
        return "[REDACTED-BLOB]"
    return blob


def _redact_json(value, key: str = ""):
    if isinstance(value, dict):
        return {k: _redact_json(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json(v, key) for v in value]
    if isinstance(value, str) and value and key and _SENSITIVE_KEY.search(key.lower()):
        return "[REDACTED]"
    return value


def redact(text: str) -> str:
    """Strip secret-looking values from az output before the model sees it.

    The allowlist should keep secrets out already; this is the second layer,
    for the ones that ride along in otherwise harmless output.
    """
    parsed = None
    if text.strip()[:1] in ("{", "["):
        try:
            parsed = json.loads(text)
        except ValueError:
            pass
    if parsed is not None:
        text = json.dumps(_redact_json(parsed), indent=2)
    for pattern, replacement in _TEXT_SECRETS:
        text = pattern.sub(replacement, text)
    return _BLOB.sub(_redact_blob, text)


# -- tools -------------------------------------------------------------------


class _NeverRaised(Exception):
    """Stands in for executor.StepBlocked on an executor that predates it."""


def build_tools(executor: Executor, config: ClusterConfig):
    """Build the agent's tool set, bound to one executor."""
    from anthropic import beta_tool

    az = executor.az
    by_id = executor.steps_by_id()
    # Derived from the loaded plan, so the destroy plan's phases validate too.
    phases = tuple(dict.fromkeys(step.phase for step in executor.plan))
    phase_list = ", ".join(phases)
    # The executor's interlocks (D9) raise StepBlocked; the getattr keeps this
    # module working against an executor that does not define it yet.
    blocked = getattr(executor_mod, "StepBlocked", None) or _NeverRaised

    def with_phases(func):
        """Fill this plan's phases into a docstring, then make the tool.

        beta_tool reads the description and argument docs from __doc__, so
        the schema the model sees names this plan's phases and no others.
        """
        func.__doc__ = (func.__doc__ or "").replace("{phases}", phase_list)
        return beta_tool(func)

    def refused(what: str, exc: Exception) -> str:
        reason = getattr(exc, "reason", "") or str(exc)
        return (f"refused: {what} is blocked by a safety interlock: {reason}. "
                "Do not retry it or work around it; report this to the operator.")

    def subscription() -> str:
        # Read per call: the active subscription can be resolved mid-run.
        return (config.subscription_id or getattr(az, "subscription", None)
                or executor.context.get("SUBSCRIPTION_ID", "") or "")

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

    @with_phases
    def show_plan(phase: str = "") -> str:
        """List the steps of this run's plan and their current status.

        Args:
            phase: Limit to one phase. One of {phases}. Empty means every phase.
        """
        if phase and phase not in phases:
            return f"unknown phase {_clip(phase)}; valid phases: {phase_list}"
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

    @with_phases
    def execute_phase(phase: str) -> str:
        """Run every incomplete step in one phase, stopping at the first failure.

        In plan mode this performs no writes and reports the commands instead.

        Args:
            phase: One of {phases}.
        """
        if phase not in phases:
            return f"unknown phase {_clip(phase)}; valid phases: {phase_list}"
        try:
            outcomes = executor.run_phase(phase)
        except blocked as exc:
            return refused(f"phase {phase}", exc)
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
        step = by_id.get(step_id) if len(step_id) <= MAX_ID_LENGTH else None
        if step is None:
            return f"unknown step {_clip(step_id)}; call show_plan for valid ids"
        try:
            outcome = executor.run_step(step, force=force)
        except blocked as exc:
            return refused(step_id, exc)
        finally:
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
        """Run a read-only `az` metadata lookup to diagnose a problem.

        Permitted: group, resource, network vnet/subnet/nsg, identity, role
        assignment/definition list, keyvault show/list (vault metadata) and
        keyvault key show/list (public key only), aro hcp cluster and nodepool
        show/list, aro hcp get-versions, vm list-usage/list-skus/list-sizes,
        provider, feature, account show, monitor activity-log list. Rejected:
        anything that changes state; anything returning secrets, keys, tokens
        or credentials; @file values; --debug, --verbose and --output-file;
        --subscription or resource IDs outside this run's subscription.
        Secret-looking values in the output are redacted.

        Args:
            args: The az arguments without the leading "az", e.g.
                "network vnet subnet show --name worker-subnet --vnet-name v --resource-group rg".
        """
        if len(args) > MAX_INSPECT_ARGS:
            return (f"rejected: arguments are {len(args)} characters; the limit is "
                    f"{MAX_INSPECT_ARGS}. Send a shorter, specific lookup.")
        try:
            argv = shlex.split(args)
        except ValueError as exc:
            return f"could not parse arguments: {exc}"
        if not argv:
            return "no arguments given"
        if argv[0] == "az":
            argv = argv[1:]
        problem = check_inspect_args(
            argv, subscription(), (config.resource_group, config.managed_resource_group),
        )
        if problem:
            return f"rejected: {problem}"
        result = az.run(argv, check=False, force=True)
        return _json({
            "command": result.command,
            "returncode": result.returncode,
            "stdout": redact(result.stdout)[:6000],
            "stderr": redact(result.stderr)[:2000],
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
    model: str | None = None,
    max_turns: int = 80,
    destroy: bool = False,
    on_text: Callable[[str], None] | None = None,
) -> AgentResult:
    """Drive the plan with Claude until it stops calling tools.

    ``model`` falls back to $ARO_HCP_MODEL, then MODEL. max_turns < 1 raises
    ValueError before any API call is made.
    """
    if max_turns < 1:
        raise ValueError(f"max_turns must be at least 1, got {max_turns}")
    model = model or os.environ.get(MODEL_ENV) or MODEL

    import anthropic

    client = anthropic.Anthropic()
    tools = build_tools(executor, config)
    phases = tuple(dict.fromkeys(step.phase for step in executor.plan))
    system = system_prompt(destroy=destroy, backend=config.backend, phases=phases)

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

    def result(text: str, stop_reason: str | None) -> AgentResult:
        return AgentResult(
            text, turns, stop_reason,
            pending=[s.id for s in executor.pending()],
            # Stopping on the limit only matters if the model wanted to go on.
            hit_turn_limit=(last is not None and turns >= max_turns
                            and last.stop_reason == "tool_use"),
            apply=executor.apply,
        )

    if last is None:
        return result("the model returned no messages", None)
    if last.stop_reason == "refusal":
        details = getattr(last, "stop_details", None)
        detail = getattr(details, "explanation", "") or ""
        text = f"the model declined this request. {detail}".strip()
        # Also sent through on_text: a refusal often has no text block, and
        # the explanation is the only clue the operator gets (N1).
        if on_text:
            on_text(text)
        return result(text, "refusal")

    text = "\n".join(b.text for b in last.content if b.type == "text")
    return result(text, last.stop_reason)
