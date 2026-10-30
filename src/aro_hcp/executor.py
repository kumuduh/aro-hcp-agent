"""Executes a plan: dry-run rendering, idempotent apply, resume."""

from __future__ import annotations

import shlex
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from . import state as state_mod
from .azure import AzCli, AzError, AzResult  # noqa: F401  (AzError re-exported)
from .config import ClusterConfig
from .plan import IN_PROGRESS_STATES, Step
from .state import RunState

#: Substrings that mean "the write already happened" rather than a real failure.
#: A match is only trusted once the step's own probe confirms the resource now
#: exists: "already exists" alone also describes a *different* resource that
#: blocks this one (a taken Key Vault name, a stale managed resource group).
_BENIGN = (
    "RoleAssignmentExists",
    "The role assignment already exists",
    "already exists",
    "AlreadyExists",
)

#: Benign without a probe: a role assignment conflict can only be about the
#: assignment being created.
_BENIGN_UNPROBED = ("RoleAssignmentExists", "The role assignment already exists")

#: Substrings that mean a resource is not there. Used to read both a failed
#: delete and a failed existence probe; anything else is "unknown".
_NOT_FOUND = (
    "ResourceNotFound",
    "ResourceGroupNotFound",
    "ParentResourceNotFound",
    "DeletedVaultNotFound",
    "VaultNotFound",
    "KeyNotFound",
    "could not be found",
    "was not found",
    "does not exist",
    "NotFound",
)

#: Substrings that mean "Azure has not finished propagating a role assignment",
#: or is throttling. Retrying the identical command is the documented remedy.
#:
#: A bare "AuthorizationFailed" is deliberately absent: that is the ordinary
#: "you do not hold this role" error, and retrying it just delays the report.
_TRANSIENT = (
    "please observe propagation time",  # Azure's own hint that it is lagging
    "ForbiddenByRbac",
    "PrincipalNotFound",
    "does not exist in the directory",
    "TooManyRequests",
    "RetryableError",
)

#: Backoff between retries of a step failing for propagation. Key Vault RBAC
#: is documented as taking up to ~10 minutes in the worst case; this waits
#: just under four, which covers it in practice without stalling a bad run.
RETRY_DELAYS = (15, 30, 60, 120)

#: Seconds between probes while waiting for a long-running operation.
POLL_INTERVAL = 30

PRESENT = "present"
ABSENT = "absent"
UNKNOWN = "unknown"


class StepBlocked(Exception):
    """A step's prerequisites are not in place, so running it would be unsafe."""

    def __init__(self, step_id: str, reason: str) -> None:
        super().__init__(f"{step_id}: {reason}")
        self.step_id = step_id
        self.reason = reason


@dataclass
class StepOutcome:
    step: Step
    status: str
    command: str
    stdout: str = ""
    stderr: str = ""
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status in (state_mod.DONE, state_mod.SKIPPED)


class Executor:
    def __init__(
        self,
        config: ClusterConfig,
        plan: list[Step],
        az: AzCli,
        run_state: RunState,
        *,
        apply: bool = False,
        confirm: Callable[[str, list[Step]], bool] | None = None,
        on_event: Callable[[str], None] | None = None,
        retry_delays: tuple[int, ...] = RETRY_DELAYS,
        sleep: Callable[[float], None] = time.sleep,
        runners: dict[str, object] | None = None,
        poll_interval: float = POLL_INTERVAL,
        fingerprint: dict[str, str] | None = None,
    ) -> None:
        self.config = config
        self.plan = plan
        self.az = az
        #: Step.runner -> runner. "az" is always present; the terraform backend
        #: adds "terraform". preflight and the agent's inspect_azure keep using
        #: self.az directly, so they are unaffected by the backend choice.
        self.runners: dict[str, object] = {"az": az, **(runners or {})}
        self.state = run_state
        self.apply = apply
        self.confirm = confirm
        self.on_event = on_event or (lambda _msg: None)
        self.retry_delays = retry_delays
        self.sleep = sleep
        self.poll_interval = poll_interval
        self._confirmed_phases: set[str] = set()
        #: Set when the operator declines a phase; the rest of the run stops.
        self.declined = False
        #: Set when a long-running operation is still in progress; the run
        #: stops so nothing is built on a resource that is not ready yet.
        self.halted = False
        #: A dry run must not leave a state file claiming work was done.
        self.persist = apply

        self.state.bind(config.cluster_name, config.subscription_id or "", fingerprint or {})
        for key, value in config.base_context().items():
            # On the terraform backend the module names the vault itself; the
            # az-derived name must not sit in context posing as the real one.
            if config.backend == "terraform" and key in ("KEYVAULT_NAME", "KMS_KEY_NAME"):
                continue
            self.state.set_context(key, value)

    # -- context ------------------------------------------------------------

    @property
    def context(self) -> dict[str, str]:
        return self.state.context

    def steps_by_id(self) -> dict[str, Step]:
        return {step.id: step for step in self.plan}

    def pending(self, phases: Iterable[str] | None = None) -> list[Step]:
        wanted = set(phases) if phases else None
        return [
            s for s in self.plan
            if (wanted is None or s.phase in wanted)
            and not self.state.is_complete(s.id)
            and not (self._always(s) and not s.mutating)
        ]

    # -- rendering ----------------------------------------------------------

    def runner_for(self, step: Step) -> AzCli:
        try:
            return self.runners[step.runner]  # type: ignore[return-value]
        except KeyError:
            raise KeyError(
                f"step {step.id} wants the {step.runner!r} runner, which this "
                f"executor was not given (have: {', '.join(sorted(self.runners))})"
            ) from None

    def render(self, step: Step) -> str:
        argv = step.render(self.context)
        if step.action is None and step.runner in self.runners:
            argv = self.runner_for(step).build(argv)
        return " ".join(shlex.quote(a) for a in argv)

    def render_plan(self, phases: Iterable[str] | None = None) -> list[tuple[Step, str, str]]:
        """Return ``(step, status, rendered command)`` for review."""
        wanted = set(phases) if phases else None
        out = []
        for step in self.plan:
            if wanted and step.phase not in wanted:
                continue
            out.append((step, self.state.status(step.id), self.render(step)))
        return out

    # -- execution ----------------------------------------------------------

    @staticmethod
    def _always(step: Step) -> bool:
        return step.always or "always" in step.tags

    def _reverify(self, step: Step) -> bool:
        """True if a completed step should be re-checked against Azure."""
        return self.apply and step.exists is not None and step.mutating

    def run_step(self, step: Step, *, force: bool = False) -> StepOutcome:
        """Run one step. Raises StepBlocked (apply mode) if its prerequisites are missing."""
        if step.runner not in self.runners:
            message = (f"step {step.id} wants the {step.runner!r} runner, which this "
                       f"executor was not given (have: {', '.join(sorted(self.runners))})")
            self._record(step.id, state_mod.FAILED, detail=message)
            return StepOutcome(step, state_mod.FAILED, self.render(step), message=message)

        command = self.render(step)

        if self.state.is_complete(step.id) and not force and not self._always(step):
            recorded = self.state.status(step.id)
            # Outside apply, a recorded result is all a report needs. During an
            # apply, a recorded delete or create is re-checked against Azure:
            # a teardown state left over from an earlier lifecycle must not
            # make a later teardown skip a cluster that exists again, and a
            # resource removed out of band must be recreated, not assumed.
            if not self._reverify(step):
                return StepOutcome(
                    step, recorded, command, message="already recorded complete in state",
                )
            found, text, err = self._probe(step)
            if found == UNKNOWN:
                message = f"recorded complete, but could not verify against Azure: {err}"
                self._record(step.id, state_mod.FAILED, command=command, detail=message)
                return StepOutcome(step, state_mod.FAILED, command, message=message)
            if (found == ABSENT) is step.deletes and self._ready(step, text) is not False:
                self._capture(step, AzResult([], 0, text, ""))
                return StepOutcome(step, state_mod.SKIPPED, command, stdout=text,
                                   message="verified against Azure")
            note = "exists again" if step.deletes else "is missing from Azure or not ready"
            self.on_event(f"redo  {step.id}: recorded complete but the resource {note}")
            self.state.reset(step.id)

        self._check_after(step)

        missing = step.unresolved(self.context)
        if missing:
            message = (
                f"cannot run {step.id}: unresolved variables {', '.join(missing)} — "
                "run the earlier phases first"
            )
            if not self.apply:
                # Expected during a dry run of a greenfield deployment.
                return StepOutcome(step, state_mod.PENDING, command, message=message)
            self._record(step.id, state_mod.FAILED, detail=message)
            return StepOutcome(step, state_mod.FAILED, command, message=message)

        # Idempotency: for a create, a lookup that returns something means the
        # resource is there and the create is a no-op. For a delete the sense
        # is inverted — nothing to look up means the teardown already happened.
        # A lookup that fails for any reason other than "not found" proves
        # nothing either way, and is never read as absence.
        if step.exists is not None:
            found, text, err = self._probe(step)
            if found == UNKNOWN:
                message = f"could not tell whether the resource exists: {err}"
                if not self.apply:
                    return StepOutcome(step, state_mod.PENDING, command, message=message)
                self._record(step.id, state_mod.FAILED, command=command, detail=message)
                self.on_event(f"FAIL  {step.id}: {message.splitlines()[0]}")
                return StepOutcome(step, state_mod.FAILED, command, stderr=err, message=message)
            if step.deletes and found == ABSENT:
                self._record(step.id, state_mod.SKIPPED, command=command, detail="already gone")
                self.on_event(f"skip  {step.id}: already gone")
                return StepOutcome(step, state_mod.SKIPPED, command, message="already gone")
            if not step.deletes and found == PRESENT:
                return self._existing(step, command, text)

        if step.mutating and not self.apply:
            self.on_event(f"plan  {step.id}: {command}")
            return StepOutcome(
                step, state_mod.PENDING, command,
                message="dry run — not executed (pass --apply to create resources)",
            )

        if step.mutating and not self._ensure_confirmed(step):
            return StepOutcome(
                step, state_mod.PENDING, command, message="declined by operator"
            )

        self.on_event(f"run   {step.id}: {step.description}")
        result = self._run_with_retries(step)

        if not result.ok:
            return self._failed(step, command, result)

        if step.capture and not result.text and self.apply:
            # Recording this as done would leave the variable unset and every
            # later run failing "unresolved" with nothing left to re-run.
            message = f"{step.id} succeeded but returned no value for {step.capture}"
            self._record(step.id, state_mod.FAILED, command=command, detail=message)
            return StepOutcome(step, state_mod.FAILED, command, message=message)

        if self._reverify(step):
            settled = self._settle(step, command)
            if settled is not None:
                return settled

        self._capture(step, result)
        self._record(step.id, state_mod.DONE, command=command, detail=result.text[:200])
        return StepOutcome(step, state_mod.DONE, command, stdout=result.text)

    def run_phase(self, phase: str, *, stop_on_error: bool = True) -> list[StepOutcome]:
        outcomes = []
        for step in self.plan:
            if step.phase != phase:
                continue
            # Outside apply, completed steps are left alone; during an apply
            # run_step re-verifies them against Azure.
            if (self.state.is_complete(step.id) and not self._always(step)
                    and not self._reverify(step)):
                continue
            try:
                outcome = self.run_step(step)
            except StepBlocked as exc:
                self._record(step.id, state_mod.FAILED, detail=exc.reason)
                self.on_event(f"FAIL  {step.id}: blocked — {exc.reason}")
                outcome = StepOutcome(step, state_mod.FAILED, self.render(step),
                                      message=f"blocked: {exc.reason}")
            outcomes.append(outcome)
            if self.declined or self.halted:
                break
            if outcome.status == state_mod.FAILED and stop_on_error:
                break
        if self.persist:
            self.state.save()
        return outcomes

    def run_all(
        self, phases: Iterable[str] | None = None, *, stop_on_error: bool = True
    ) -> list[StepOutcome]:
        wanted = list(phases) if phases else None
        outcomes: list[StepOutcome] = []
        seen: list[str] = []
        for step in self.plan:
            if wanted and step.phase not in wanted:
                continue
            if step.phase not in seen:
                seen.append(step.phase)
        if wanted and seen:
            # A phase-scoped run still refreshes what it builds on: earlier
            # phases' always-steps (reads, terraform workspace/init/plan) run
            # first, so `--phase apply` never applies against stale tfvars and
            # `--phase cluster` never uses stale captured IDs.
            first = next(i for i, s in enumerate(self.plan) if s.phase == seen[0])
            for step in self.plan[:first]:
                if self._always(step) and step.phase not in seen:
                    outcome = self.run_step(step)
                    outcomes.append(outcome)
                    if outcome.status == state_mod.FAILED and stop_on_error:
                        return outcomes
        for phase in seen:
            phase_outcomes = self.run_phase(phase, stop_on_error=stop_on_error)
            outcomes += phase_outcomes
            if self.declined or self.halted:
                break
            if stop_on_error and any(o.status == state_mod.FAILED for o in phase_outcomes):
                break
        return outcomes

    # -- helpers ------------------------------------------------------------

    def _probe(self, step: Step) -> tuple[str, str, str]:
        """Return (PRESENT|ABSENT|UNKNOWN, stdout, error) for the step's resource.

        Propagation lag hits probes as well as writes: the probe for the KMS
        key runs moments after this run granted itself Crypto Officer, and the
        vault's data plane answers ForbiddenByRbac until the grant arrives. So
        a transient probe error is retried on the same backoff before it is
        reported as "unknown".
        """
        argv = step.render_exists(self.context)
        runner = self.runner_for(step)
        probe = runner.run(argv, check=False, force=True)
        for delay in self.retry_delays:
            if probe.ok or not self._is_transient(probe):
                break
            self.on_event(f"wait  {step.id}: Azure is still propagating permissions; "
                          f"checking again in {delay}s")
            self.sleep(delay)
            probe = runner.run(argv, check=False, force=True)
        if probe.ok:
            return (PRESENT if probe.text else ABSENT), probe.text, ""
        err = probe.stderr.strip() or probe.stdout.strip() or f"exit {probe.returncode}"
        if self._is_transient(probe) or probe.returncode == 124:
            return UNKNOWN, "", err
        if self._matches(probe, _NOT_FOUND):
            return ABSENT, "", err
        return UNKNOWN, "", err

    @staticmethod
    def _ready(step: Step, text: str) -> bool | None:
        """True if a create's probe output means done, False if not, None if N/A."""
        if not step.ready_states or step.deletes:
            return None
        return text in step.ready_states

    def _existing(self, step: Step, command: str, text: str) -> StepOutcome:
        """The create's resource already exists: decide whether that is done."""
        if step.ready_states:
            if text in IN_PROGRESS_STATES:
                return self._in_progress(step, command, text)
            if text not in step.ready_states:
                message = (
                    f"the resource already exists in state {text!r}, which is not "
                    f"{' / '.join(step.ready_states)}. "
                    + ("It is still in progress; re-run when it finishes."
                       if text in IN_PROGRESS_STATES else
                       "Delete it (aro-hcp destroy, or az) and re-run apply.")
                )
                if not self.apply:
                    return StepOutcome(step, state_mod.PENDING, command, message=message)
                self._record(step.id, state_mod.FAILED, command=command, detail=message)
                self.on_event(f"FAIL  {step.id}: exists in state {text}")
                return StepOutcome(step, state_mod.FAILED, command, stdout=text, message=message)
        elif step.expect is not None and text != step.expect:
            message = (
                f"the resource already exists with different settings: found {text!r}, "
                f"the config wants {step.expect!r}. Remove it or change the config"
            )
            if self.apply:
                self._record(step.id, state_mod.FAILED, command=command, detail=message)
                return StepOutcome(step, state_mod.FAILED, command, stdout=text, message=message)
            return StepOutcome(step, state_mod.PENDING, command, message=message)
        self._record(step.id, state_mod.SKIPPED, command=command, detail=f"already present: {text}")
        self._capture(step, AzResult([], 0, text, ""))
        self.on_event(f"skip  {step.id}: already present")
        return StepOutcome(step, state_mod.SKIPPED, command, stdout=text, message="already present")

    def _in_progress(self, step: Step, command: str, text: str) -> StepOutcome:
        """The resource exists but its long-running operation has not finished.

        Never "done": that is how a still-provisioning cluster was reported as
        provisioned and a node pool was sent at it. The run stops here instead
        of blocking for up to the step timeout; re-running apply resumes.
        """
        message = (f"the resource exists but is still {text}; re-run apply when the "
                   "operation finishes")
        if self.apply:
            self.halted = True
            self.on_event(f"hold  {step.id}: still {text}")
        return StepOutcome(step, state_mod.PENDING, command, stdout=text, message=message)

    def _settle(self, step: Step, command: str) -> StepOutcome | None:
        """After a successful command, confirm Azure agrees. None means it does."""
        if step.deletes:
            # A delete that returned 0 is not proof the resource is gone; some
            # deletes return before the resource disappears.
            # The az deletes used here wait for completion, so a short grace
            # period covers read-after-delete lag; anything longer is a failure
            # to report, not something to block on.
            for attempt in range(3):
                found, _text, err = self._probe(step)
                if found == ABSENT:
                    return None
                if attempt < 2:
                    self.sleep(self.poll_interval)
            message = ("delete returned success but the resource is still "
                       + ("present" if found == PRESENT else f"unverifiable: {err}"))
            self._record(step.id, state_mod.FAILED, command=command, detail=message)
            return StepOutcome(step, state_mod.FAILED, command, message=message)
        if step.ready_states:
            found, text, err = self._probe(step)
            if found == PRESENT and text in IN_PROGRESS_STATES:
                return self._in_progress(step, command, text)
            if text not in step.ready_states:
                message = (f"create returned but the resource is in state {text or found!r}"
                           + (f": {err}" if err else ""))
                self._record(step.id, state_mod.FAILED, command=command, detail=message)
                self.on_event(f"FAIL  {step.id}: {message}")
                return StepOutcome(step, state_mod.FAILED, command, message=message)
        return None

    def _failed(self, step: Step, command: str, result: AzResult) -> StepOutcome:
        detail = result.stderr.strip() or result.stdout.strip()
        # A retry budget exhausted on propagation lag is still a failure, even
        # when its text also contains a "not found" phrase.
        if not self._is_transient(result):
            if step.deletes and self._matches(result, _NOT_FOUND):
                self._record(step.id, state_mod.SKIPPED, command=command, detail=detail)
                return StepOutcome(step, state_mod.SKIPPED, command, stderr=result.stderr,
                                   message="already gone")
            if not step.deletes and self._matches(result, _BENIGN):
                if step.exists is not None:
                    found, text, _err = self._probe(step)
                    confirmed = found == PRESENT and self._ready(step, text) is not False
                    if confirmed:
                        self._capture(step, AzResult([], 0, text, ""))
                else:
                    confirmed = self._matches(result, _BENIGN_UNPROBED)
                if confirmed:
                    self._record(step.id, state_mod.SKIPPED, command=command, detail=detail)
                    return StepOutcome(step, state_mod.SKIPPED, command,
                                       stderr=result.stderr, message="already exists")

        # In a dry run the only commands that reach here are lookups, and
        # they fail simply because nothing has been created yet.
        status = state_mod.FAILED if self.apply else state_mod.PENDING
        self._record(step.id, status, command=command, detail=detail)
        if status == state_mod.FAILED:
            self.on_event(f"FAIL  {step.id}: {detail.splitlines()[0] if detail else '?'}")
        return StepOutcome(
            step, status, command, stdout=result.stdout, stderr=result.stderr, message=detail,
        )

    def _check_after(self, step: Step) -> None:
        """Refuse to run a step whose prerequisite resources are not in place."""
        if not step.after:
            return
        by_id = self.steps_by_id()
        for dep_id in step.after:
            dep = by_id.get(dep_id)
            if dep is None or self.state.is_complete(dep_id):
                continue
            satisfied = False
            if dep.exists is not None:
                found, text, _err = self._probe(dep)
                if dep.deletes:
                    satisfied = found == ABSENT
                else:
                    satisfied = found == PRESENT and self._ready(dep, text) is not False
            if not satisfied:
                verb = "gone" if dep.deletes else "in place"
                reason = (f"needs {dep_id} first ({dep.description}); its resource is not "
                          f"confirmed {verb}")
                if self.apply:
                    raise StepBlocked(step.id, reason)
                self.on_event(f"plan  {step.id}: waits for {dep_id}")
                return

    def _run_with_retries(self, step: Step) -> AzResult:
        """Run a step, repeating it while Azure reports propagation lag.

        The alternative is failing a step that would have succeeded moments
        later — which is what makes the etcd-encryption phase flaky, since it
        grants itself Key Vault access and then immediately uses it.
        """
        if step.action is not None:
            return self._run_action(step)

        runner = self.runner_for(step)
        argv = step.render(self.context)
        force = not step.mutating
        result = runner.run(argv, check=False, timeout=step.timeout, force=force)
        for delay in self.retry_delays:
            if result.ok or not self._is_transient(result):
                return result
            self.on_event(
                f"wait  {step.id}: Azure is still propagating permissions; "
                f"retrying in {delay}s"
            )
            self.sleep(delay)
            result = runner.run(argv, check=False, timeout=step.timeout, force=force)
        return result

    def _run_action(self, step: Step) -> AzResult:
        """Run an in-process step (fetching the module, writing tfvars)."""
        from .terraform import ACTIONS  # local: terraform.py imports from plan

        handler = ACTIONS.get(step.action or "")
        if handler is None:
            return AzResult([step.action or "?"], 1, "", f"unknown action {step.action!r}")
        try:
            return handler(self, step)
        except Exception as exc:  # reported as a step failure, not a traceback
            return AzResult(
                step.render(self.context), 1, "", f"{type(exc).__name__}: {exc}"
            )

    def _record(self, step_id: str, status: str, *, command: str = "", detail: str = "") -> None:
        if self.persist:
            self.state.record(step_id, status, command=command, detail=detail)
            # Saved per step, not per phase: an interrupted run must not lose
            # the record of resources it already created.
            self.state.save()

    def _capture(self, step: Step, result: AzResult) -> None:
        if not (step.capture and result.text):
            return
        value = result.text
        if step.capture_transform == "basename":
            value = value.rstrip("/").rsplit("/", 1)[-1]
        self.state.set_context(step.capture, value)

    @staticmethod
    def _matches(result: AzResult, markers: tuple[str, ...]) -> bool:
        blob = f"{result.stderr}\n{result.stdout}".lower()
        return any(marker.lower() in blob for marker in markers)

    @classmethod
    def _is_benign(cls, result: AzResult, *, deletes: bool = False) -> bool:
        return cls._matches(result, _NOT_FOUND if deletes else _BENIGN)

    @classmethod
    def _is_transient(cls, result: AzResult) -> bool:
        return cls._matches(result, _TRANSIENT)

    def _ensure_confirmed(self, step: Step) -> bool:
        if self.confirm is None or step.phase in self._confirmed_phases:
            return True
        if self.declined:
            return False
        remaining = [
            s for s in self.plan
            if s.phase == step.phase and s.mutating and not self.state.is_complete(s.id)
        ]
        if not self.confirm(step.phase, remaining):
            # Later phases consume this one's resources, so a decline ends the
            # run rather than moving on and prompting again.
            self.declined = True
            return False
        self._confirmed_phases.add(step.phase)
        return True


def resolve_signed_in_user(az: AzCli, run_state: RunState) -> str:
    """Populate ``SIGNED_IN_USER``, needed by the Key Vault Crypto Officer grant.

    The object id is preferred over ``account show``'s user name: under a
    managed-identity login that name is the literal "systemAssignedIdentity",
    which is not a principal and made the grant fail late. When no assignee
    can be resolved the variable stays unset, so the grant fails up front as
    "unresolved" (and preflight has already said why).
    """
    from .preflight import _resolve_principal  # local: preflight imports config only

    existing = run_state.get("SIGNED_IN_USER")
    if existing:
        return existing
    assignee, _kind = _resolve_principal(az)
    if assignee:
        run_state.set_context("SIGNED_IN_USER", assignee)
    return assignee
