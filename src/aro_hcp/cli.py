"""Command line interface for the ARO HCP provisioning agent."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
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
from .state import RunState, StateError, default_state_path, destroy_state_path
from .terraform import (
    TERRAFORM_DESTROY_PHASES,
    TERRAFORM_PHASES,
    build_terraform_destroy_plan,
    build_terraform_plan,
    make_runner,
    plan_json,
)

#: --phase accepts any phase from any backend at parse time; _setup rejects
#: one that the selected backend does not have.
ALL_PHASES = tuple(dict.fromkeys(PHASES + TERRAFORM_PHASES))
ALL_DESTROY_PHASES = tuple(dict.fromkeys(DESTROY_PHASES + TERRAFORM_DESTROY_PHASES))

#: Exit codes. Distinct, so a wrapper script can tell "nothing happened" from
#: "half happened" without parsing output.
EXIT_OK = 0
EXIT_FAILED = 1        # a step failed
EXIT_USAGE = 2         # config, state or argument problem; nothing ran
EXIT_DECLINED = 3      # the operator (or a non-TTY) declined
EXIT_BLOCKED = 4       # preflight failed
EXIT_INCOMPLETE = 5    # nothing failed, but requested work is still pending
EXIT_INTERRUPTED = 130

STATUS_MARK = {OK: "ok  ", WARN: "warn", FAIL: "FAIL"}
STEP_MARK = {
    state_mod.DONE: "done",
    state_mod.SKIPPED: "skip",
    state_mod.FAILED: "FAIL",
    state_mod.PENDING: "    ",
}

#: Settings a completed step depends on. Changing one after a partial build
#: would leave completed steps describing resources the config no longer
#: asks for, so a resume with different values is refused.
_FINGERPRINT_KEYS = (
    "location", "resource_group", "managed_resource_group", "backend",
    "cluster_version", "channel_group", "vnet_address_prefix", "worker_subnet_prefix",
    "vnet_integration_subnet_prefix", "api_visibility", "ingress_visibility",
    "vault_visibility", "nodepool_name", "nodepool_vm_size", "nodepool_replicas",
    "nodepool_version", "terraform_ref",
)


def _eprint(*args) -> None:
    print(*args, file=sys.stderr)


def _load_config(args: argparse.Namespace) -> ClusterConfig:
    if args.config:
        config = ClusterConfig.load(args.config)
    else:
        config = ClusterConfig.from_env()
    # with_overrides re-derives every name that came from cluster_name, so
    # --cluster-name beta cannot leave alpha's vault, VNet and managed group
    # in the plan.
    return config.with_overrides(
        cluster_name=getattr(args, "cluster_name", None) or None,
        location=getattr(args, "location", None) or None,
        resource_group=getattr(args, "resource_group", None) or None,
        subscription_id=getattr(args, "subscription_id", None) or None,
        cluster_version=getattr(args, "cluster_version", None) or None,
        nodepool_version=getattr(args, "nodepool_version", None) or None,
        backend=getattr(args, "backend", None) or None,
        keyvault_private_endpoint=True if getattr(args, "keyvault_private_endpoint", False) else None,
    )


def _fingerprint(config: ClusterConfig, *, destroy: bool) -> dict[str, str]:
    keys = ("location", "resource_group", "backend") if destroy else _FINGERPRINT_KEYS
    return {key: str(getattr(config, key)) for key in keys}


def _completed_steps(path: Path) -> int | None:
    """Completed steps recorded at ``path``; None when the file is unreadable."""
    if not path.exists():
        return 0
    try:
        other = RunState.load(path)
    except StateError:
        return None
    return sum(
        1 for entry in other.steps.values()
        if entry.get("status") in (state_mod.DONE, state_mod.SKIPPED)
    )


def _guard_mixed_backends(config: ClusterConfig, state_dir, *, apply: bool, destroy: bool) -> None:
    """Refuse to let one backend act on a cluster the other one built.

    The two backends name the Key Vault and the managed identities
    differently: Terraform over an az-built cluster creates a second,
    overlapping set, and either teardown run against the other's cluster
    misses resources (and used to delete the other backend's state file,
    disabling this very guard). An unreadable state file is treated as
    "may have built something" — failing open is how the guard was bypassed.
    """
    terraform = config.backend == "terraform"
    other_backend = "az-cli" if terraform else "terraform"
    other = default_state_path(config.cluster_name, state_dir, suffix=None if terraform else "tf")
    done = _completed_steps(other)
    if done == 0:
        return
    what = "an unreadable state file" if done is None else f"{done} completed {other_backend} step(s)"
    message = (
        f"{other} records {what} for {config.cluster_name}.\n"
        f"The {config.backend} backend names the Key Vault and the managed identities "
        f"differently, so it cannot {'tear down' if destroy else 'adopt'} what the "
        f"{other_backend} backend built.\n"
        f"Use --backend {other_backend} for this cluster, or a different cluster_name."
    )
    if apply:
        raise ConfigError(message)
    _eprint(f"warning: {message}\n")


def _state_paths(args: argparse.Namespace, config: ClusterConfig, *, destroy: bool) -> tuple[Path, Path]:
    """Return (path this run uses, the build state it pairs with)."""
    terraform = config.backend == "terraform"
    if args.state:
        build = Path(args.state)
    else:
        build = default_state_path(config.cluster_name, args.state_dir,
                                   suffix="tf" if terraform else None)
    return (destroy_state_path(build) if destroy else build), build


def _check_writable(path: Path) -> None:
    """Fail before the first Azure write if progress could not be recorded."""
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise ConfigError(f"cannot create state directory {directory}: {exc}") from exc
    if not os.access(directory, os.W_OK):
        raise ConfigError(
            f"state directory {directory} is not writable; progress could not be "
            "recorded, so nothing was started"
        )


def _setup(
    args: argparse.Namespace, *, apply: bool, destroy: bool = False
) -> tuple[ClusterConfig, Executor]:
    config = _load_config(args)
    config.require_valid()

    terraform = config.backend == "terraform"
    phases = getattr(args, "phase", None) or []
    valid = (TERRAFORM_DESTROY_PHASES if destroy else TERRAFORM_PHASES) if terraform \
        else (DESTROY_PHASES if destroy else PHASES)
    unknown = [p for p in phases if p not in valid]
    if unknown:
        raise ConfigError(
            f"--phase {', '.join(unknown)} is not a {config.backend} "
            f"{'teardown ' if destroy else ''}phase; valid: {', '.join(valid)}"
        )

    az = AzCli(config.subscription_id, dry_run=not apply)
    if not config.subscription_id:
        config.subscription_id = az.current_subscription()
        az.subscription = config.subscription_id

    # Each (backend, direction) pair keeps its own state. Teardown must not
    # read or clobber the build run's "already done" marks, and the two
    # backends' step ids and resources have nothing to do with each other.
    state_path, _build = _state_paths(args, config, destroy=destroy)
    if apply:
        _check_writable(state_path)
    run_state = RunState.load(state_path)

    _guard_mixed_backends(config, args.state_dir, apply=apply, destroy=destroy)

    runners = None
    if terraform:
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
        on_event=(lambda msg: print(msg, flush=True)) if not args.quiet else None,
        runners=runners,
        fingerprint=_fingerprint(config, destroy=destroy),
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


def _confirm_destroy(config: ClusterConfig, executor: Executor) -> bool:
    """Make the operator type the cluster name before anything is deleted.

    Teardown is irreversible and the resource names are the only thing
    standing between this and the wrong cluster. A y/N is too easy to
    answer on autopilot.
    """
    if not sys.stdin.isatty():
        _eprint("\nstdin is not a TTY and --yes was not given; declining to delete.")
        return False
    if config.backend == "terraform":
        scope = "everything Terraform owns, including its Key Vault (purged)"
    else:
        scope = (f"the Key Vault {config.keyvault_name} and its etcd encryption key "
                 "(purged, irreversible), 13 managed identities, the private endpoint "
                 "and DNS zone if present")
    print(f"\nThis permanently deletes cluster {config.cluster_name}, {scope}, the VNet, "
          f"and resource group {config.resource_group} with anything else in it, in "
          f"subscription {config.subscription_id}.")
    _warn_foreign_resources(config, executor)
    typed = input(f"Type the cluster name ({config.cluster_name}) to confirm: ").strip()
    if typed != config.cluster_name:
        _eprint("Name did not match; nothing was deleted.")
        return False
    return True


#: Resource types this tool (or ARO, inside the cluster's own resources)
#: creates in the customer resource group.
_OWNED_TYPES = {
    "microsoft.redhatopenshift/hcpopenshiftclusters",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/virtualnetworks",
    "microsoft.managedidentity/userassignedidentities",
    "microsoft.keyvault/vaults",
    "microsoft.network/privateendpoints",
    "microsoft.network/privatednszones",
    "microsoft.network/privatednszones/virtualnetworklinks",
    "microsoft.network/networkinterfaces",
}


def _warn_foreign_resources(config: ClusterConfig, executor: Executor) -> None:
    """List anything in the resource group this tool did not create.

    The last teardown step deletes the whole group, so unrelated resources
    that share it are deleted too. Say so by name before asking.
    """
    result = executor.az.run(
        ["resource", "list", "--resource-group", config.resource_group,
         "--query", "[].{name:name, type:type}", "--output", "json"],
        check=False, force=True,
    )
    try:
        items = result.json() or [] if result.ok else []
    except ValueError:
        items = []
    foreign = [i for i in items if str(i.get("type", "")).lower() not in _OWNED_TYPES]
    if foreign:
        print(f"!! {len(foreign)} resource(s) in {config.resource_group} were not created by "
              "aro-hcp and will be deleted with the group:")
        for item in foreign[:20]:
            print(f"     - {item.get('name')} ({item.get('type')})")


def _failure_text(outcome) -> str:
    """The useful part of a failed step's output.

    Terraform and the RP put the actual reason at the end of a long error;
    a fixed-length prefix used to cut it off.
    """
    text = (outcome.message or outcome.stderr or "").strip()
    if len(text) <= 4000:
        return text
    marker = text.rfind("Error:")
    if marker != -1:
        return "...\n" + text[marker:][:6000]
    return "...\n" + text[-4000:]


# -- commands ---------------------------------------------------------------


def cmd_validate(args: argparse.Namespace) -> int:
    config = _load_config(args)
    problems = config.validate()
    warnings = config.warnings()
    if args.json:
        print(json.dumps({"valid": not problems, "problems": problems, "warnings": warnings,
                          "config": config.to_dict()}, indent=2, sort_keys=True))
        return EXIT_FAILED if problems else EXIT_OK
    if problems:
        print("Configuration is not usable:")
        for problem in problems:
            print(f"  - {problem}")
        return EXIT_FAILED
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
    for warning in warnings:
        print(f"  warning: {warning}")
    return EXIT_OK


def cmd_preflight(args: argparse.Namespace) -> int:
    config = _load_config(args)
    az = AzCli(config.subscription_id, dry_run=False)
    report = run_preflight(az, config, deep=not args.shallow)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return EXIT_BLOCKED if report.blocked else EXIT_OK
    for finding in report.findings:
        print(f"[{STATUS_MARK.get(finding.status, finding.status)}] {finding.check}: {finding.message}")
        if finding.remedy:
            print(f"        -> {finding.remedy}")
    print()
    print("BLOCKED — resolve the failures above before applying."
          if report.blocked else "Preflight passed.")
    return EXIT_BLOCKED if report.blocked else EXIT_OK


def cmd_plan(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=False)
    phases = args.phase or None
    if config.backend == "terraform" and not args.json:
        return _terraform_plan(executor, phases)
    if config.backend == "terraform":
        return _terraform_plan_json(args, config, executor)
    rows = executor.render_plan(phases)
    if args.json:
        print(json.dumps({
            # On the terraform backend this lists the wrapper's steps; the
            # resource-level diff is only in the text output of `plan`.
            "kind": "aro-hcp-steps",
            "backend": config.backend,
            "steps": [
                {"id": s.id, "phase": s.phase, "status": st, "description": s.description,
                 "command": cmd, "mutating": s.mutating}
                for s, st, cmd in rows
            ],
        }, indent=2))
        return EXIT_OK

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
    return EXIT_OK


def _terraform_plan_json(args, config: ClusterConfig, executor: Executor) -> int:
    """`plan --json` on terraform: the real resource diff, not the wrapper's steps."""
    outcomes = executor.run_all(["workspace", "init"], stop_on_error=True)
    failed = [o for o in outcomes if o.status == state_mod.FAILED]
    if failed:
        _print_failures(failed)
        return EXIT_FAILED
    try:
        print(json.dumps(plan_json(config, executor.runners["terraform"], args.state_dir or None),
                         indent=2))
    except Exception as exc:  # AzError from terraform, reported cleanly
        _eprint(f"terraform plan failed: {exc}")
        return EXIT_FAILED
    return EXIT_OK


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
            print(f"  {_failure_text(outcome)}")
            return EXIT_FAILED
        if step.id == "tf-plan":
            print(outcome.stdout or outcome.message)
        elif step.mutating and outcome.status == state_mod.PENDING:
            print(f"[hold] {step.id}: {step.description}")
        elif outcome.status == state_mod.PENDING:
            # A lookup of something the apply has not created yet.
            print(f"[wait] {step.id}: {outcome.message or step.description}")
        elif step.action:
            # Actions report one useful line; terraform's own banners do not.
            print(f"[ok  ] {step.id}: {outcome.stdout.strip()}")
        else:
            print(f"[ok  ] {step.id}: {step.description}")
    print("\nNothing was created. Run `aro-hcp apply --backend terraform` to execute.")
    return EXIT_OK


def _print_failures(failed) -> None:
    for outcome in failed:
        print(f"\nFAILED {outcome.step.id}: {outcome.step.description}")
        print(f"  {outcome.command}")
        print(f"  {_failure_text(outcome)}")


def cmd_apply(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=True)
    phases = args.phase or None

    if args.skip_preflight:
        # An override, so it is said out loud and written down.
        print("warning: --skip-preflight given; environment checks were not run.")
        executor.state.note("skip-preflight", "operator bypassed preflight")
    else:
        report = run_preflight(executor.az, config, deep=True)
        for finding in report.findings:
            if finding.status != OK:
                print(f"[{STATUS_MARK.get(finding.status)}] {finding.check}: {finding.message}")
                if finding.remedy:
                    print(f"        -> {finding.remedy}")
        if report.blocked:
            _eprint("\nPreflight failed. Fix the issues above, or pass --skip-preflight "
                    "to override.")
            return EXIT_BLOCKED

    # After preflight, so nobody is asked to approve a run that cannot start.
    if not args.yes and not args.confirm_each_phase:
        if not _confirm_apply(executor, phases):
            print("Nothing was created.")
            return EXIT_DECLINED

    with executor.state.lock():
        outcomes = executor.run_all(phases, stop_on_error=not args.keep_going)
        executor.state.save()

    failed = [o for o in outcomes if o.status == state_mod.FAILED]
    created = [o for o in outcomes if o.status == state_mod.DONE and o.step.mutating]
    skipped = [o for o in outcomes if o.status == state_mod.SKIPPED]
    print(f"\n{len(created)} executed, {len(skipped)} already present or verified, "
          f"{len(failed)} failed.")
    print(f"State: {executor.state.path}")
    _print_failures(failed)
    if failed:
        print("\nFix the cause and re-run `aro-hcp apply` — completed steps are re-verified "
              "and skipped.")
        return EXIT_FAILED
    if executor.declined:
        print("\nDeclined; the remaining phases were not run.")
        return EXIT_DECLINED

    pending = executor.pending(phases)
    if pending:
        print(f"{len(pending)} step(s) still pending; re-run apply to continue.")
        return EXIT_INCOMPLETE
    if phases:
        print(f"\nPhase(s) {', '.join(phases)} of {config.cluster_name} complete.")
        return EXIT_OK
    print(f"\nCluster {config.cluster_name} provisioned.")
    return EXIT_OK


def cmd_destroy(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=args.apply, destroy=True)
    rows = executor.render_plan(args.phase or None)

    print(f"Teardown plan for {config.cluster_name} ({config.backend} backend; "
          f"resource group {config.resource_group}, subscription {config.subscription_id}):\n")
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
        return EXIT_OK

    if not args.yes and not _confirm_destroy(config, executor):
        return EXIT_DECLINED

    with executor.state.lock():
        outcomes = executor.run_all(args.phase or None, stop_on_error=not args.keep_going)
        executor.state.save()

    failed = [o for o in outcomes if o.status == state_mod.FAILED]
    # Only steps that delete something count as deletions; fetching the
    # module or running init is bookkeeping.
    deleted = [o for o in outcomes if o.status == state_mod.DONE and o.step.deletes
               and "bookkeeping" not in o.step.tags]
    gone = [o for o in outcomes if o.status == state_mod.SKIPPED and o.step.deletes
            and "bookkeeping" not in o.step.tags]
    print(f"\n{len(deleted)} deleted, {len(gone)} already gone, {len(failed)} failed.")
    _print_failures(failed)
    if failed:
        print("\nFix the cause and re-run `aro-hcp destroy --apply` — "
              "resources already gone are skipped.")
        return EXIT_FAILED
    if args.phase:
        return EXIT_OK

    # The teardown is complete, so both records of this lifecycle go: the
    # build state describes resources that no longer exist (the next apply
    # would skip steps it needs), and the teardown state's "done" marks would
    # make the next lifecycle's teardown skip a cluster that exists again.
    _, build_state = _state_paths(args, config, destroy=False)
    if build_state.exists():
        build_state.unlink()
        print(f"Removed stale build state {build_state}")
    executor.state.delete()
    print(f"\nTeardown of {config.cluster_name} complete.")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    config, executor = _setup(args, apply=False)
    summary = executor.state.summary()
    failed = {sid: executor.state.steps[sid].get("detail", "")
              for sid in executor.state.steps
              if executor.state.status(sid) == state_mod.FAILED}
    if args.json:
        print(json.dumps({
            "cluster": config.cluster_name,
            "backend": config.backend,
            "state_file": str(executor.state.path),
            # What this tool recorded, not a live query of Azure.
            "source": "local state snapshot",
            "summary": summary,
            "failed": failed,
            "context": executor.context,
            "pending": [s.id for s in executor.pending()],
        }, indent=2, sort_keys=True))
        return EXIT_OK
    print(f"Cluster:    {config.cluster_name} ({config.backend} backend)")
    print(f"State file: {executor.state.path}"
          f"{'' if executor.state.path.exists() else ' (not created yet)'}")
    print("            (a local record of what aro-hcp did, not a live check of Azure)")
    print(f"Steps:      {summary[state_mod.DONE]} done, {summary[state_mod.SKIPPED]} skipped, "
          f"{summary[state_mod.FAILED]} failed, {len(executor.pending())} pending")
    if executor.context.get("CLUSTER_PROVISIONING_STATE"):
        print(f"Cluster state when last read: {executor.context['CLUSTER_PROVISIONING_STATE']}")
    for sid, detail in failed.items():
        print(f"  FAILED {sid}: {detail[:300]}")
    return EXIT_OK


def cmd_agent(args: argparse.Namespace) -> int:
    from .agent import run_agent

    # The SDK is an optional extra, so this is a routine install state rather
    # than a bug — say which extra, not just which module is missing.
    if importlib.util.find_spec("anthropic") is None:
        _eprint("agent mode needs the Anthropic SDK, which is an optional extra.\n"
                "  uv tool install 'git+https://github.com/kumuduh/aro-hcp-agent[agent]'\n"
                "  (or `uv sync --extra agent` in a clone)\n"
                "Every other subcommand works without it.")
        return EXIT_USAGE

    config, executor = _setup(args, apply=args.apply, destroy=args.destroy)

    # The model is not a safety gate. A live agent run passes the same
    # deterministic checks as the equivalent CLI command before it starts.
    if args.apply:
        if args.destroy:
            if not args.yes and not _confirm_destroy(config, executor):
                return EXIT_DECLINED
        else:
            report = run_preflight(executor.az, config, deep=True)
            if report.blocked:
                for finding in report.findings:
                    if finding.blocking:
                        print(f"[FAIL] {finding.check}: {finding.message}")
                _eprint("\nPreflight failed; the agent was not started.")
                return EXIT_BLOCKED
            if not args.yes and not _confirm_apply(executor, None):
                print("Nothing was created.")
                return EXIT_DECLINED

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
    try:
        if args.apply:
            with executor.state.lock():
                result = _run_agent(run_agent, executor, config, instruction, args)
        else:
            result = _run_agent(run_agent, executor, config, instruction, args)
    except state_mod.StateLocked:
        raise
    except Exception as exc:  # surfaced rather than a traceback
        _eprint(f"agent error: {type(exc).__name__}: {exc}")
        if executor.persist:
            executor.state.save()
        return EXIT_FAILED
    if executor.persist:
        executor.state.save()

    stop = getattr(result, "stop_reason", None)
    if args.quiet:
        print(result.text)
    if stop == "refusal":
        return EXIT_FAILED
    # The model saying "done" is not the oracle; the plan's state is.
    if getattr(result, "hit_turn_limit", False) or stop in ("max_tokens", "tool_use", None):
        _eprint(f"\nagent stopped before finishing ({stop or 'turn limit'}).")
        return EXIT_INCOMPLETE
    if args.apply:
        failed = [s for s in executor.plan if executor.state.status(s.id) == state_mod.FAILED]
        if failed:
            _eprint(f"\n{len(failed)} step(s) failed: {', '.join(s.id for s in failed[:10])}")
            return EXIT_FAILED
        pending = executor.pending()
        if pending:
            _eprint(f"\n{len(pending)} step(s) still pending.")
            return EXIT_INCOMPLETE
        if args.destroy:
            _, build_state = _state_paths(args, config, destroy=False)
            build_state.unlink(missing_ok=True)
            executor.state.delete()
    return EXIT_OK


def _run_agent(run_agent, executor, config, instruction, args):
    return run_agent(
        executor, config, instruction,
        model=args.model,
        max_turns=args.max_turns,
        destroy=args.destroy,
        on_text=None if args.quiet else (lambda text: print(text, flush=True)),
    )


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.output)
    if path.exists() and not args.force:
        _eprint(f"{path} already exists; pass --force to overwrite.")
        return EXIT_USAGE
    template = """\
# ARO HCP cluster configuration.
# Docs: https://learn.microsoft.com/azure/openshift/howto-create-custom-hosted-cluster

cluster_name: my-hcp-cluster
# ARO HCP is preview and offered in a subset of regions.
# `aro-hcp preflight` lists the current set if this one is not supported.
location: eastus2
resource_group: my-hcp-rg
# Quote versions: YAML reads an unquoted 4.20 as the number 4.2.
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

# IPv4 only. The integration subnet must be /28 or larger, the worker subnet
# /24 or larger, and neither may overlap 10.128.0.0/14 or 172.30.0.0/16.
vnet_address_prefix: 10.0.0.0/16
worker_subnet_prefix: 10.0.0.0/24
vnet_integration_subnet_prefix: 10.0.1.0/24

api_visibility: Public        # Public | Private
ingress_visibility: Public    # Public | Private
# Private requires --keyvault-private-endpoint (az-cli backend only).
vault_visibility: Public      # Public | Private

nodepool_name: np-1
nodepool_replicas: 2
nodepool_vm_size: Standard_D8s_v6
"""
    try:
        path.write_text(template)
    except OSError as exc:
        _eprint(f"cannot write {path}: {exc}")
        return EXIT_USAGE
    print(f"Wrote {path}. Edit it, then run: aro-hcp plan --config {path}")
    return EXIT_OK


# -- parser -----------------------------------------------------------------


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aro-hcp",
        description="Provision an Azure Red Hat OpenShift cluster with hosted control "
                    "planes, following the Microsoft Learn az CLI procedure.",
        epilog="Exit codes: 0 ok, 1 a step failed, 2 usage/config/state error, "
               "3 declined, 4 preflight blocked, 5 incomplete, 130 interrupted.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser, *, state: bool = True) -> None:
        p.add_argument("-c", "--config", help="path to a YAML or JSON cluster config "
                       "(default: ARO_* environment variables)")
        p.add_argument("--cluster-name", help="override cluster_name; derived names follow it")
        p.add_argument("--location", help="override location (Azure region short name)")
        p.add_argument("--resource-group", help="override resource_group")
        p.add_argument("--subscription-id", help="override subscription_id "
                       "(default: the active az subscription)")
        p.add_argument("--cluster-version", help="override cluster_version (major.minor)")
        p.add_argument("--nodepool-version", help="override nodepool_version (major.minor.patch)")
        p.add_argument("--backend", choices=BACKENDS,
                       help="how to provision: the az CLI procedure, or the "
                            "upstream Terraform module (default: az-cli)")
        p.add_argument("--keyvault-private-endpoint", action="store_true",
                       help="put the Key Vault behind a private endpoint "
                            "(az-cli backend only)")
        p.add_argument("-q", "--quiet", action="store_true", help="print only the result")
        if state:
            p.add_argument("--state", help="path to the build state file (teardown uses "
                           "a paired .destroy file next to it)")
            p.add_argument("--state-dir", help="directory for state files and the terraform "
                           "work directory (default: ./.aro-hcp)")
            p.add_argument("-y", "--yes", action="store_true",
                           help="do not prompt for confirmation at all")
            p.add_argument("--confirm-each-phase", action="store_true",
                           help="ask before every phase instead of once up front")

    p_init = sub.add_parser("init", help="write a starter config file")
    p_init.add_argument("-o", "--output", default="cluster.yaml", help="file to write")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing file")
    p_init.set_defaults(func=cmd_init)

    p_validate = sub.add_parser("validate", help="validate the configuration offline")
    add_common(p_validate, state=False)
    p_validate.add_argument("--json", action="store_true", help="machine-readable output")
    p_validate.set_defaults(func=cmd_validate)

    p_pre = sub.add_parser("preflight", help="check the Azure environment")
    add_common(p_pre, state=False)
    p_pre.add_argument("--shallow", action="store_true",
                       help="skip checks that call Azure")
    p_pre.add_argument("--json", action="store_true", help="machine-readable output")
    p_pre.set_defaults(func=cmd_preflight)

    p_plan = sub.add_parser("plan", help="render every command without running it")
    add_common(p_plan)
    p_plan.add_argument("--phase", action="append", choices=ALL_PHASES,
                        help="limit to a phase of the selected backend (repeatable)")
    p_plan.add_argument("-v", "--verbose", action="store_true",
                        help="print the full az command for each step")
    p_plan.add_argument("--json", action="store_true",
                        help="machine-readable list of the wrapper's steps")
    p_plan.set_defaults(func=cmd_plan)

    p_apply = sub.add_parser("apply", help="create the cluster")
    add_common(p_apply)
    p_apply.add_argument("--phase", action="append", choices=ALL_PHASES,
                         help="run only this phase of the selected backend (repeatable)")
    p_apply.add_argument("--skip-preflight", action="store_true",
                         help="run without environment checks (recorded in state)")
    p_apply.add_argument("--keep-going", action="store_true",
                         help="continue past a failure to steps that do not depend on it")
    p_apply.set_defaults(func=cmd_apply)

    p_destroy = sub.add_parser(
        "destroy", help="delete everything this tool created, including the cluster")
    add_common(p_destroy)
    p_destroy.add_argument("--phase", action="append", choices=ALL_DESTROY_PHASES,
                           help="run only this teardown phase (its prerequisites are "
                                "still enforced)")
    p_destroy.add_argument("--apply", action="store_true",
                           help="actually delete (default: show the teardown plan)")
    p_destroy.add_argument("-v", "--verbose", action="store_true",
                           help="print the full command for each step")
    p_destroy.add_argument("--keep-going", action="store_true",
                           help="continue past a failure to steps that do not depend on it")
    p_destroy.set_defaults(func=cmd_destroy)

    p_status = sub.add_parser("status", help="show progress from the state file")
    add_common(p_status)
    p_status.add_argument("--json", action="store_true", help="machine-readable output")
    p_status.set_defaults(func=cmd_status)

    p_agent = sub.add_parser("agent", help="let Claude drive the plan")
    add_common(p_agent)
    p_agent.add_argument("instruction", nargs="?",
                         help="what you want the agent to do")
    p_agent.add_argument("--apply", action="store_true",
                         help="allow the agent to create or delete (default: plan only); "
                              "the same confirmation as apply/destroy is required")
    p_agent.add_argument("--destroy", action="store_true",
                         help="drive the teardown plan instead of the build plan")
    p_agent.add_argument("--model", default=os.environ.get("ARO_HCP_MODEL", "claude-opus-5"),
                         help="Claude model id (default: $ARO_HCP_MODEL or claude-opus-5)")
    p_agent.add_argument("--max-turns", type=_positive_int, default=80,
                         help="stop after this many model turns (default 80)")
    p_agent.set_defaults(func=cmd_agent)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, StateError, AzNotFound) as exc:
        _eprint(str(exc))
        return EXIT_USAGE
    except KeyboardInterrupt:
        _eprint("\ninterrupted; re-run the same command to resume")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    raise SystemExit(main())
