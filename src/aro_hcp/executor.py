"""Executes a plan: dry-run rendering, idempotent apply, resume."""

from __future__ import annotations

import shlex
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from . import state as state_mod
from .azure import AzCli, AzError, AzResult
from .config import ClusterConfig
from .plan import Step
from .state import RunState

#: Substrings that mean "the write already happened" rather than a real failure.
#: Kept deliberately narrow — a broad match here would swallow real errors.
_BENIGN = (
    "RoleAssignmentExists",
    "The role assignment already exists",
    "already exists",
    "AlreadyExists",
)

#: The same idea for teardown: the resource is gone, which is the goal.
_BENIGN_DELETE = (
    "ResourceNotFound",
    "ResourceGroupNotFound",
    "ParentResourceNotFound",
    "could not be found",
    "was not found",
    "does not exist",
)

#: Substrings that mean "Azure has not finished propagating a role assignment".
#: A role assignment is visible to the control plane immediately, but the Key
#: Vault data plane and Azure AD lag it by seconds to minutes — so the very
#: next step, which uses the permission just granted, can be refused. Retrying
#: the identical command is the documented remedy.
#:
#: A bare "AuthorizationFailed" is deliberately absent: that is the ordinary
#: "you do not hold this role" error, and retrying it just delays the report.
_TRANSIENT = (
    "please observe propagation time",  # Azure's own hint that it is lagging
    "ForbiddenByRbac",
    "PrincipalNotFound",
    "does not exist in the directory",
)

#: Backoff between retries of a step failing for propagation. Key Vault RBAC
#: is documented as taking up to ~10 minutes in the worst case; this waits
#: just under four, which covers it in practice without stalling a bad run.
RETRY_DELAYS = (15, 30, 60, 120)


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
        self._confirmed_phases: set[str] = set()
        #: A dry run must not leave a state file claiming work was done.
        self.persist = apply

        self.state.cluster_name = config.cluster_name
        self.state.subscription_id = config.subscription_id or ""
        for key, value in config.base_context().items():
            self.state.set_context(key, value)

    # -- context ------------------------------------------------------------

    @property
    def context(self) -> dict[str, str]:
        return self.state.context

    def steps_by_id(self) -> dict[str, Step]:
        return {step.id: step for step in self.plan}

    def pending(self) -> list[Step]:
        return [s for s in self.plan if not self.state.is_complete(s.id)]

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
        if step.action is None:
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

    def run_step(self, step: Step, *, force: bool = False) -> StepOutcome:
        if self.state.is_complete(step.id) and not force:
            return StepOutcome(
                step, self.state.status(step.id), self.render(step),
                message="already recorded complete in state",
            )

        missing = step.unresolved(self.context)
        if missing:
            message = (
                f"cannot run {step.id}: unresolved variables {', '.join(missing)} — "
                "run the earlier phases first"
            )
            if not self.apply:
                # Expected during a dry run of a greenfield deployment.
                return StepOutcome(step, state_mod.PENDING, self.render(step), message=message)
            self._record(step.id, state_mod.FAILED, detail=message)
            return StepOutcome(step, state_mod.FAILED, self.render(step), message=message)

        command = self.render(step)

        # Idempotency: for a create, a lookup that returns something means the
        # resource is there and the create is a no-op. For a delete the sense
        # is inverted — nothing to look up means the teardown already happened.
        if step.exists is not None:
            probe = self.runner_for(step).run(
                step.render_exists(self.context), check=False, force=True
            )
            present = bool(probe.ok and probe.text)
            if present is not step.deletes:
                note = "already gone" if step.deletes else "already present"
                self._record(
                    step.id, state_mod.SKIPPED, command=command,
                    detail=f"{note}: {probe.text}" if probe.text else note,
                )
                self._capture(step, probe)
                self.on_event(f"skip  {step.id}: {note}")
                return StepOutcome(
                    step, state_mod.SKIPPED, command, stdout=probe.text, message=note,
                )

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

        if not result.ok and self._is_benign(result, deletes=step.deletes):
            self._record(
                step.id, state_mod.SKIPPED, command=command, detail=result.stderr.strip()
            )
            return StepOutcome(
                step, state_mod.SKIPPED, command, stderr=result.stderr,
                message="already gone" if step.deletes else "already exists",
            )

        if not result.ok:
            detail = result.stderr.strip() or result.stdout.strip()
            # In a dry run the only commands that reach here are lookups, and
            # they fail simply because nothing has been created yet.
            status = state_mod.FAILED if self.apply else state_mod.PENDING
            self._record(step.id, status, command=command, detail=detail)
            if status == state_mod.FAILED:
                self.on_event(f"FAIL  {step.id}: {detail.splitlines()[0] if detail else '?'}")
            return StepOutcome(
                step, status, command, stdout=result.stdout,
                stderr=result.stderr, message=detail,
            )

        self._capture(step, result)
        self._record(step.id, state_mod.DONE, command=command, detail=result.text[:200])
        return StepOutcome(step, state_mod.DONE, command, stdout=result.text)

    def run_phase(self, phase: str, *, stop_on_error: bool = True) -> list[StepOutcome]:
        outcomes = []
        for step in self.plan:
            if step.phase != phase or self.state.is_complete(step.id):
                continue
            outcome = self.run_step(step)
            outcomes.append(outcome)
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
        for phase in seen:
            phase_outcomes = self.run_phase(phase, stop_on_error=stop_on_error)
            outcomes += phase_outcomes
            if stop_on_error and any(o.status == state_mod.FAILED for o in phase_outcomes):
                break
        return outcomes

    # -- helpers ------------------------------------------------------------

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

    def _capture(self, step: Step, result: AzResult) -> None:
        if not (step.capture and result.text):
            return
        value = result.text
        if step.capture_transform == "basename":
            value = value.rstrip("/").rsplit("/", 1)[-1]
        self.state.set_context(step.capture, value)

    @staticmethod
    def _is_benign(result: AzResult, *, deletes: bool = False) -> bool:
        blob = f"{result.stderr}\n{result.stdout}".lower()
        markers = _BENIGN_DELETE if deletes else _BENIGN
        return any(marker.lower() in blob for marker in markers)

    @staticmethod
    def _is_transient(result: AzResult) -> bool:
        blob = f"{result.stderr}\n{result.stdout}"
        return any(marker.lower() in blob.lower() for marker in _TRANSIENT)

    def _ensure_confirmed(self, step: Step) -> bool:
        if self.confirm is None or step.phase in self._confirmed_phases:
            return True
        remaining = [
            s for s in self.plan
            if s.phase == step.phase and s.mutating and not self.state.is_complete(s.id)
        ]
        if not self.confirm(step.phase, remaining):
            return False
        self._confirmed_phases.add(step.phase)
        return True


def resolve_signed_in_user(az: AzCli, run_state: RunState) -> str:
    """Populate ``SIGNED_IN_USER``, needed by the Key Vault Crypto Officer grant."""
    existing = run_state.get("SIGNED_IN_USER")
    if existing:
        return existing
    user = az.signed_in_user()
    if user:
        run_state.set_context("SIGNED_IN_USER", user)
    return user or ""
