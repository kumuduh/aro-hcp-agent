"""Command line interface for the ARO HCP provisioning agent."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import state as state_mod
from .azure import AzCli, AzNotFound
from .config import BACKENDS, ClusterConfig, ConfigError
from .destroy import DESTROY_PHASES, build_destroy_plan
from .executor import Executor, resolve_signed_in_user
from .plan import PHASES, build_plan
from .preflight import FAIL, OK, WARN, run_preflight
from .state import RunState, default_state_path
from .terraform import (
    TERRAFORM_DESTROY_PHASES,
    TERRAFORM_PHASES,
    build_terraform_destroy_plan,
    build_terraform_plan,
    make_runner,
)

#: --phase accepts any phase from any backend; _setup builds the plan that
#: decides which of them actually exist for this run.
ALL_PHASES = tuple(dict.fromkeys(PHASES + TERRAFORM_PHASES))
ALL_DESTROY_PHASES = tuple(dict.fromkeys(DESTROY_PHASES + TERRAFORM_DESTROY_PHASES))

STATUS_MARK = {OK: "ok  ", WARN: "warn", FAIL: "FAIL"}
STEP_MARK = {
    state_mod.DONE: "done",
    state_mod.SKIPPED: "skip",
    state_mod.FAILED: "FAIL",
    state_mod.PENDING: "    ",
}


def _eprint(*args) -> None:
    print(*args, file=sys.stderr)


def _load_config(args: argparse.Namespace) -> ClusterConfig:
    if args.config:
        config = ClusterConfig.load(args.config)
    else:
        config = ClusterConfig.from_env()
    for name in ("cluster_name", "location", "resource_group", "subscription_id"):
        override = getattr(args, name, None)
        if override:
            setattr(config, name, override)
    if getattr(args, "cluster_version", None):
        config.cluster_version = args.cluster_version
    if getattr(args, "nodepool_version", None):
        config.nodepool_version = args.nodepool_version
    if getattr(args, "backend", None):
        config.backend = args.backend
    if getattr(args, "keyvault_private_endpoint", False):
        config.keyvault_private_endpoint = True
        # Mirrors __post_init__, which already ran with the config-file value.
        config.vault_visibility = "Private"
    return config


def _guard_mixed_backends(config: ClusterConfig, state_dir, *, apply: bool) -> None:
    """Refuse to run Terraform over a cluster the az backend already built.

    The two backends name the Key Vault and the managed identities
    differently, so Terraform would not adopt those resources — it would
    create a second, overlapping set alongside them.
    """
    az_state = default_state_path(config.cluster_name, state_dir)
    if not az_state.exists():
        return
    try:
        other = RunState.load(az_state)
    except (ValueError, json.JSONDecodeError):
        return
    done = [
        sid for sid, entry in other.steps.items()
        if entry.get("status") in (state_mod.DONE, state_mod.SKIPPED)
    ]
    if not done:
        return
    message = (
        f"{az_state} records {len(done)} completed az-cli step(s) for "
        f"{config.cluster_name}.\nThe terraform backend names the Key Vault and "
        "the managed identities differently, so it cannot adopt those resources "
        "— it would build a second, overlapping set.\nEither tear the cluster "
        "down with `aro-hcp destroy -c <config> --apply` first, or use a "
        "different cluster_name for the terraform run."
    )
    if apply:
        raise ConfigError(message)
    _eprint(f"warning: {message}\n")


def _setup(
    args: argparse.Namespace, *, apply: bool, destroy: bool = False
) -> tuple[ClusterConfig, Executor]:
    config = _load_config(args)
    config.require_valid()

    az = AzCli(config.subscription_id, dry_run=not apply)
    if not config.subscription_id:
        config.subscription_id = az.current_subscription()
        az.subscription = config.subscription_id

    terraform = config.backend == "terraform"

    # Each (backend, direction) pair keeps its own state. Teardown must not
    # read or clobber the build run's "already done" marks, and the two
    # backends' step ids and resources have nothing to do with each other.
    parts = [p for p in ("tf" if terraform else "", "destroy" if destroy else "") if p]
    suffix = ".".join(parts) or None
    state_path = Path(args.state) if args.state else default_state_path(
        config.cluster_name, args.state_dir, suffix=suffix
    )
    run_state = RunState.load(state_path)

    runners = None
    if terraform:
        if not destroy:
            # Only a build can collide. A teardown that finds nothing in
            # Terraform state simply deletes nothing.
            _guard_mixed_backends(config, args.state_dir, apply=apply)
        work_dir = args.state_dir or None
        plan = (
            build_terraform_destroy_plan(config, work_dir) if destroy
            else build_terraform_plan(config, work_dir)
        )
        runners = {"terraform": make_runner(config, directory=work_dir, dry_run=not apply)}
    else:
        plan = build_destroy_plan(config) if destroy else build_plan(config)

    # One confirmation per run is the default; the per-phase gate is opt-in.
    # `apply` and `destroy` each ask once, up front, before anything runs.
    confirm = (
        _interactive_confirm
        if apply and getattr(args, "confirm_each_phase", False) and not args.yes
        else None
    )
    executor = Executor(
        config, plan, az, run_state,
        apply=apply,
        confirm=confirm,
        on_event=(lambda msg: print(msg)) if not args.quiet else None,
        runners=runners,
    )
    resolve_signed_in_user(az, run_state)
    return config, executor


def _interactive_confirm(phase: str, steps) -> bool:
    """Per-phase gate, used only with --confirm-each-phase."""
    billable = any("billable" in s.tags for s in steps)
    print()
    print(f"Phase '{phase}': {len(steps)} command(s) will run against Azure.")
    for step in steps[:8]:
        print(f"  - {step.description}")
    if len(steps) > 8:
        print(f"  ... and {len(steps) - 8} more")
    if billable:
        print("  !! This phase creates billable resources.")
    if not sys.stdin.isatty():
        _eprint("stdin is not a TTY and --yes was not given; declining.")
        return False
    answer = input("Proceed? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def _confirm_apply(executor: Executor, phases) -> bool:
    """The single gate before an apply writes anything.

    One prompt for the whole run, so it has to carry everything the eight
    per-phase prompts used to: what will be built, where, and that it bills.
    """
    pending = [
        s for s in executor.plan
        if s.mutating
        and (not phases or s.phase in phases)
        and not executor.state.is_complete(s.id)
    ]
    if not pending:
        return True

    config = executor.config
    by_phase: dict[str, int] = {}
    for step in pending:
        by_phase[step.phase] = by_phase.get(step.phase, 0) + 1

    print()
    print(f"About to create {config.cluster_name} in {config.location} "
          f"(resource group {config.resource_group}, "
          f"subscription {config.subscription_id}).")
    # An upper bound: a step whose resource already exists is probed and
    # skipped at run time, which this cannot know yet.
    print(f"Up to {len(pending)} command(s) will run against Azure:")
    for phase, count in by_phase.items():
        print(f"  {phase}: {count}")
    billable = [s for s in pending if "billable" in s.tags]
    if billable:
        print("  !! This creates billable resources:")
        for step in billable:
            print(f"     - {step.description}")
    print("This is the only confirmation; the run will not stop between phases.")

    if not sys.stdin.isatty():
        sys.stdout.flush()  # so the reason lands after the summary, not before
        _eprint("stdin is not a TTY and --yes was not given; declining.")
        return False
    return input("Proceed? [y/N] ").strip().lower() in ("y", "yes")


# -- commands ---------------------------------------------------------------


def cmd_validate(args: argparse.Namespace) -> int:
    config = _load_config(args)
    problems = config.validate()
    if args.json:
        print(json.dumps({"valid": not problems, "problems": problems,
                          "config": config.to_dict()}, indent=2, sort_keys=True))
        return 1 if problems else 0
    if problems:
        print("Configuration is not usable:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"Configuration for {config.cluster_name} is valid.")
    print(f"  backend:         {config.backend}")
    print(f"  resource group:  {config.resource_group}")
    print(f"  managed group:   {config.managed_resource_group}")
    print(f"  location:        {config.location}")
    print(f"  version:         {config.cluster_version} (node pool {config.nodepool_version})")
    vault = ("cust-kv-<random>, named by the module" if config.backend == "terraform"
             else config.keyvault_name)
    print(f"  key vault:       {vault} ({config.vault_visibility})")
    print(f"  api / ingress:   {config.api_visibility} / {config.ingress_visibility}")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    config = _load_config(args)
    az = AzCli(config.subscription_id, dry_run=False)
    report = run_preflight(az, config, deep=not args.shallow)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 1 if report.blocked else 0
    for finding in report.findings:
        print(f"[{STATUS_MARK.get(finding.status, finding.status)}] {finding.check}: {finding.message}")
        if finding.remedy:
            print(f"        -> {finding.remedy}")
    print()
    print("BLOCKED — resolve the failures above before applying."
          if report.blocked else "Preflight passed.")
    return 1 if report.blocked else 0


def cmd_plan(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=False)
    phases = args.phase or None
    if config.backend == "terraform" and not args.json:
        return _terraform_plan(executor, phases)
    rows = executor.render_plan(phases)
    if args.json:
        print(json.dumps([
            {"id": s.id, "phase": s.phase, "status": st, "description": s.description,
             "command": cmd, "mutating": s.mutating}
            for s, st, cmd in rows
        ], indent=2))
        return 0

    current = None
    writes = 0
    for step, status, command in rows:
        if step.phase != current:
            current = step.phase
            print(f"\n=== {current} ===")
        mark = STEP_MARK.get(status, status)
        print(f"[{mark}] {step.id}: {step.description}")
        if args.verbose:
            print(f"        {command}")
        # A failed step is retried by the next apply, so it is a pending write
        # too; only done and skipped steps are behind us.
        if step.mutating and status not in (state_mod.DONE, state_mod.SKIPPED):
            writes += 1
    print(f"\n{writes} write(s) pending across {len(rows)} step(s).")
    print("Nothing was created. Run `aro-hcp apply` to execute.")
    return 0


def _terraform_plan(executor: Executor, phases) -> int:
    """Run the real `terraform plan`.

    Fetching the module, writing the tfvars, `init` and `plan` are all
    non-mutating, so the executor runs them even without --apply. That makes
    this a genuine diff rather than a rendered command, which is the main
    reason to prefer this backend.
    """
    # The outputs phase is skipped: those values do not exist until apply, so
    # running it here would only report a handful of confusing failures.
    wanted = phases or [p for p in TERRAFORM_PHASES if p != "outputs"]
    outcomes = executor.run_all(wanted, stop_on_error=True)
    for outcome in outcomes:
        step = outcome.step
        if outcome.status == state_mod.FAILED:
            print(f"\nFAILED {step.id}: {step.description}")
            print(f"  {outcome.command}")
            print(f"  {(outcome.message or outcome.stderr).strip()[:2000]}")
            return 1
        if step.id == "tf-plan":
            print(outcome.stdout or outcome.message)
        elif step.mutating and outcome.status == state_mod.PENDING:
            print(f"[hold] {step.id}: {step.description}")
        elif step.action:
            # Actions report one useful line; terraform's own banners do not.
            print(f"[ok  ] {step.id}: {outcome.stdout.strip()}")
        else:
            print(f"[ok  ] {step.id}: {step.description}")
    print("\nNothing was created. Run `aro-hcp apply --backend terraform` to execute.")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=True)

    if not args.skip_preflight:
        report = run_preflight(executor.az, config, deep=True)
        for finding in report.findings:
            if finding.status != OK:
                print(f"[{STATUS_MARK.get(finding.status)}] {finding.check}: {finding.message}")
                if finding.remedy:
                    print(f"        -> {finding.remedy}")
        if report.blocked:
            _eprint("\nPreflight failed. Fix the issues above, or pass --skip-preflight "
                    "to override.")
            return 1

    # After preflight, so nobody is asked to approve a run that cannot start.
    if not args.yes and not args.confirm_each_phase:
        if not _confirm_apply(executor, args.phase or None):
            print("Nothing was created.")
            return 1

    outcomes = executor.run_all(args.phase or None, stop_on_error=not args.keep_going)
    executor.state.save()

    failed = [o for o in outcomes if o.status == state_mod.FAILED]
    created = [o for o in outcomes if o.status == state_mod.DONE]
    skipped = [o for o in outcomes if o.status == state_mod.SKIPPED]
    print(f"\n{len(created)} executed, {len(skipped)} already present, {len(failed)} failed.")
    print(f"State: {executor.state.path}")
    for outcome in failed:
        print(f"\nFAILED {outcome.step.id}: {outcome.step.description}")
        print(f"  {outcome.command}")
        print(f"  {outcome.message.strip()[:1500]}")
    if failed:
        print("\nFix the cause and re-run `aro-hcp apply` — completed steps are skipped.")
        return 1

    pending = executor.pending()
    if pending:
        print(f"{len(pending)} step(s) still pending; re-run apply to continue.")
        return 1
    print(f"\nCluster {config.cluster_name} provisioned.")
    return 0


def cmd_destroy(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=args.apply, destroy=True)
    rows = executor.render_plan(args.phase or None)

    print(f"Teardown plan for {config.cluster_name} "
          f"(resource group {config.resource_group}, subscription {config.subscription_id}):\n")
    current = None
    for step, status, command in rows:
        if step.phase != current:
            current = step.phase
            print(f"=== {current} ===")
        print(f"[{STEP_MARK.get(status, status)}] {step.id}: {step.description}")
        if args.verbose:
            print(f"        {command}")

    if not args.apply:
        print("\nNothing was deleted. Re-run with --apply to execute.")
        return 0

    # Teardown is irreversible and the resource names are the only thing
    # standing between this and the wrong cluster, so make the operator type
    # one. A phase-level y/N is too easy to answer on autopilot.
    if not args.yes:
        if not sys.stdin.isatty():
            _eprint("\nstdin is not a TTY and --yes was not given; declining to delete.")
            return 1
        identities = "everything Terraform owns" if config.backend == "terraform" \
            else "13 managed identities"
        print(f"\nThis permanently deletes the cluster, the Key Vault and its etcd "
              f"encryption key, {identities}, the VNet, and the resource "
              f"group {config.resource_group}.")
        typed = input(f"Type the cluster name ({config.cluster_name}) to confirm: ").strip()
        if typed != config.cluster_name:
            _eprint("Name did not match; nothing was deleted.")
            return 1

    outcomes = executor.run_all(args.phase or None, stop_on_error=not args.keep_going)
    executor.state.save()

    failed = [o for o in outcomes if o.status == state_mod.FAILED]
    deleted = [o for o in outcomes if o.status == state_mod.DONE]
    gone = [o for o in outcomes if o.status == state_mod.SKIPPED]
    print(f"\n{len(deleted)} deleted, {len(gone)} already gone, {len(failed)} failed.")
    for outcome in failed:
        print(f"\nFAILED {outcome.step.id}: {outcome.step.description}")
        print(f"  {outcome.command}")
        print(f"  {outcome.message.strip()[:1500]}")
    if failed:
        print("\nFix the cause and re-run `aro-hcp destroy --apply` — "
              "resources already gone are skipped.")
        return 1

    # The build state now describes resources that no longer exist; leaving it
    # would make the next `apply` skip steps it needs to run.
    build_state = default_state_path(config.cluster_name, args.state_dir)
    if not args.phase and build_state.exists():
        build_state.unlink()
        print(f"Removed stale build state {build_state}")
    print(f"\nTeardown of {config.cluster_name} complete.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=False)
    summary = executor.state.summary()
    if args.json:
        print(json.dumps({
            "cluster": config.cluster_name,
            "state_file": str(executor.state.path),
            "summary": summary,
            "context": executor.context,
            "pending": [s.id for s in executor.pending()],
        }, indent=2, sort_keys=True))
        return 0
    print(f"Cluster:    {config.cluster_name}")
    print(f"State file: {executor.state.path}"
          f"{'' if executor.state.path.exists() else ' (not created yet)'}")
    print(f"Steps:      {summary[state_mod.DONE]} done, {summary[state_mod.SKIPPED]} skipped, "
          f"{summary[state_mod.FAILED]} failed, {len(executor.pending())} pending")
    if executor.context.get("CLUSTER_PROVISIONING_STATE"):
        print(f"Cluster state: {executor.context['CLUSTER_PROVISIONING_STATE']}")
    failed = [sid for sid in executor.state.steps
              if executor.state.status(sid) == state_mod.FAILED]
    for sid in failed:
        print(f"  FAILED {sid}: {executor.state.steps[sid].get('detail', '')[:300]}")
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from .agent import run_agent

    config, executor = _setup(args, apply=args.apply, destroy=args.destroy)
    if args.destroy:
        default = ("Tear down this cluster and everything created with it."
                   if args.apply
                   else "Review the teardown plan and report exactly what would be "
                        "deleted and anything that would be left behind.")
    else:
        default = ("Provision this cluster end to end."
                   if args.apply
                   else "Review the plan for this cluster and report what would be "
                        "created and any risks you find.")
    instruction = args.instruction or default
    # The SDK is an optional extra, so this is a routine install state rather
    # than a bug — say which extra, not just which module is missing.
    if importlib.util.find_spec("anthropic") is None:
        _eprint("agent mode needs the Anthropic SDK, which is an optional extra.\n"
                "  uv tool install 'git+https://github.com/kumuduh/aro-hcp-agent[agent]'\n"
                "  (or `uv sync --extra agent` in a clone)\n"
                "Every other subcommand works without it.")
        return 1
    try:
        result = run_agent(
            executor, config, instruction,
            model=args.model,
            max_turns=args.max_turns,
            destroy=args.destroy,
            on_text=lambda text: print(text, flush=True),
        )
    except Exception as exc:  # surfaced rather than a traceback
        _eprint(f"agent error: {type(exc).__name__}: {exc}")
        if executor.persist:
            executor.state.save()
        return 1
    if executor.persist:
        executor.state.save()
    if args.quiet:
        print(result.text)
    return 0 if result.stop_reason != "refusal" else 1


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.output)
    if path.exists() and not args.force:
        _eprint(f"{path} already exists; pass --force to overwrite.")
        return 1
    template = """\
# ARO HCP cluster configuration.
# Docs: https://learn.microsoft.com/azure/openshift/howto-create-custom-hosted-cluster

cluster_name: my-hcp-cluster
# ARO HCP is preview and offered in a subset of regions.
# `aro-hcp preflight` lists the current set if this one is not supported.
location: eastus2
resource_group: my-hcp-rg
cluster_version: "4.22"
nodepool_version: "4.22.1"

# How to provision. Both backends read this same file, but they name the Key
# Vault and the managed identities differently, so one cluster must be built
# and torn down by one backend throughout.
#   az-cli     the Microsoft Learn procedure, ~86 az commands
#   terraform  the upstream rh-mobb module, cloned at a pinned ref
backend: az-cli
# terraform_dir: /path/to/validated-pattern-aro-hcp/terraform

# subscription_id: 00000000-0000-0000-0000-000000000000

# Names below are derived from cluster_name when omitted.
# nsg_name: my-hcp-cluster-nsg
# vnet_name: my-hcp-cluster-vnet
# worker_subnet_name: worker-subnet
# vnet_integration_subnet_name: vnet-integration-subnet
# managed_resource_group: my-hcp-cluster-managed-rg

vnet_address_prefix: 10.0.0.0/16
worker_subnet_prefix: 10.0.0.0/24
vnet_integration_subnet_prefix: 10.0.1.0/24

api_visibility: Public        # Public | Private
ingress_visibility: Public    # Public | Private
vault_visibility: Public      # Public | Private — must match the Key Vault network config

nodepool_name: np-1
nodepool_replicas: 2
nodepool_vm_size: Standard_D8s_v6
"""
    path.write_text(template)
    print(f"Wrote {path}. Edit it, then run: aro-hcp plan --config {path}")
    return 0


# -- parser -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aro-hcp",
        description="Provision an Azure Red Hat OpenShift cluster with hosted control "
                    "planes, following the Microsoft Learn az CLI procedure.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser, *, state: bool = True) -> None:
        p.add_argument("-c", "--config", help="path to a YAML or JSON cluster config")
        p.add_argument("--cluster-name")
        p.add_argument("--location")
        p.add_argument("--resource-group")
        p.add_argument("--subscription-id")
        p.add_argument("--cluster-version")
        p.add_argument("--nodepool-version")
        p.add_argument("--backend", choices=BACKENDS,
                       help="how to provision: the az CLI procedure, or the "
                            "upstream Terraform module (default: az-cli)")
        p.add_argument("--keyvault-private-endpoint", action="store_true",
                       help="put the Key Vault behind a private endpoint "
                            "(az-cli backend only)")
        p.add_argument("-q", "--quiet", action="store_true")
        if state:
            p.add_argument("--state", help="path to the run state file")
            p.add_argument("--state-dir", help="directory for the default state file")
            p.add_argument("-y", "--yes", action="store_true",
                           help="do not prompt for confirmation at all")
            p.add_argument("--confirm-each-phase", action="store_true",
                           help="ask before every phase instead of once up front")

    p_init = sub.add_parser("init", help="write a starter config file")
    p_init.add_argument("-o", "--output", default="cluster.yaml")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_validate = sub.add_parser("validate", help="validate the configuration offline")
    add_common(p_validate, state=False)
    p_validate.add_argument("--json", action="store_true")
    p_validate.set_defaults(func=cmd_validate)

    p_pre = sub.add_parser("preflight", help="check the Azure environment")
    add_common(p_pre, state=False)
    p_pre.add_argument("--shallow", action="store_true",
                       help="skip checks that call Azure")
    p_pre.add_argument("--json", action="store_true")
    p_pre.set_defaults(func=cmd_preflight)

    p_plan = sub.add_parser("plan", help="render every command without running it")
    add_common(p_plan)
    p_plan.add_argument("--phase", action="append", choices=ALL_PHASES)
    p_plan.add_argument("-v", "--verbose", action="store_true",
                        help="print the full az command for each step")
    p_plan.add_argument("--json", action="store_true")
    p_plan.set_defaults(func=cmd_plan)

    p_apply = sub.add_parser("apply", help="create the cluster")
    add_common(p_apply)
    p_apply.add_argument("--phase", action="append", choices=ALL_PHASES)
    p_apply.add_argument("--skip-preflight", action="store_true")
    p_apply.add_argument("--keep-going", action="store_true",
                         help="continue to the next step after a failure")
    p_apply.set_defaults(func=cmd_apply)

    p_destroy = sub.add_parser(
        "destroy", help="delete everything this tool created, including the cluster")
    add_common(p_destroy)
    p_destroy.add_argument("--phase", action="append", choices=ALL_DESTROY_PHASES)
    p_destroy.add_argument("--apply", action="store_true",
                           help="actually delete (default: show the teardown plan)")
    p_destroy.add_argument("-v", "--verbose", action="store_true")
    p_destroy.add_argument("--keep-going", action="store_true",
                           help="continue to the next step after a failure")
    p_destroy.set_defaults(func=cmd_destroy)

    p_status = sub.add_parser("status", help="show progress from the state file")
    add_common(p_status)
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_agent = sub.add_parser("agent", help="let Claude drive the plan")
    add_common(p_agent)
    p_agent.add_argument("instruction", nargs="?",
                         help="what you want the agent to do")
    p_agent.add_argument("--apply", action="store_true",
                         help="allow the agent to create or delete (default: plan only)")
    p_agent.add_argument("--destroy", action="store_true",
                         help="drive the teardown plan instead of the build plan")
    p_agent.add_argument("--model", default="claude-opus-5")
    p_agent.add_argument("--max-turns", type=int, default=80)
    p_agent.set_defaults(func=cmd_agent)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        _eprint(str(exc))
        return 2
    except AzNotFound as exc:
        _eprint(str(exc))
        return 2
    except KeyboardInterrupt:
        _eprint("\ninterrupted; re-run the same command to resume")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
