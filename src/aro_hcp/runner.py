"""The command runners a plan step can be dispatched to.

``Executor`` never spawns a process itself — it asks a runner to build an argv
and to run it. ``AzCli`` was the only runner; this adds ``TerraformCli`` so the
same plan machinery (idempotency probes, retries, state, confirmation gates)
drives the Terraform backend too.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from .azure import DEFAULT_TIMEOUT, AzError, AzNotFound, AzResult

#: The runners' shared result type. Named for `az` only for historical reasons.
CommandResult = AzResult

#: Terraform ``>= 1.9.0`` per the upstream module's required_version.
MIN_TERRAFORM_VERSION = (1, 9, 0)


@runtime_checkable
class Runner(Protocol):
    """What ``Executor`` needs from a command runner."""

    def build(self, args: Sequence[str]) -> list[str]:
        """Return the full argv, including the program name."""

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        force: bool = False,
    ) -> CommandResult:
        """Run the command. ``force=True`` runs even in dry-run mode."""


class TerraformNotFound(AzNotFound):
    """The `terraform` CLI is not on PATH."""


class TerraformCli:
    """Runs `terraform` against one module directory.

    The upstream module's ``provider "azurerm"`` block sets no
    ``subscription_id``, and azurerm v4 requires one, so the subscription is
    passed through the environment rather than on the command line.
    """

    def __init__(
        self,
        module_dir: str | Path,
        subscription: str | None = None,
        *,
        dry_run: bool = False,
        echo: Callable[[str], None] | None = None,
        data_dir: str | Path | None = None,
    ) -> None:
        self.module_dir = Path(module_dir)
        self.subscription = subscription
        self.dry_run = dry_run
        self.echo = echo
        #: Keeps .terraform/ out of the module checkout, so one checkout can
        #: back several clusters without their provider caches colliding.
        self.data_dir = Path(data_dir) if data_dir else None
        self._log: list[CommandResult] = []

    @property
    def log(self) -> list[CommandResult]:
        return list(self._log)

    def ensure_available(self) -> str:
        path = shutil.which("terraform")
        if path is None:
            raise TerraformNotFound(
                "the `terraform` CLI was not found on PATH; see "
                "https://developer.hashicorp.com/terraform/install"
            )
        return path

    def build(self, args: Sequence[str]) -> list[str]:
        """Return the full argv for a `terraform` invocation.

        ``-chdir`` is a global option and must precede the subcommand, which
        is why it cannot simply be appended by the caller.
        """
        return ["terraform", f"-chdir={self.module_dir}", *args]

    def environ(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.subscription:
            env["ARM_SUBSCRIPTION_ID"] = self.subscription
        if self.data_dir:
            env["TF_DATA_DIR"] = str(self.data_dir)
        # Terraform prompts on a TTY otherwise, which would hang an unattended
        # run behind an invisible question.
        env["TF_IN_AUTOMATION"] = "1"
        env["TF_INPUT"] = "0"
        return env

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        force: bool = False,
    ) -> CommandResult:
        argv = self.build(args)
        if self.echo:
            self.echo(" ".join(shlex.quote(a) for a in argv))
        if self.dry_run and not force:
            result = CommandResult(argv, 0, "", "")
            self._log.append(result)
            return result

        self.ensure_available()
        if self.data_dir:
            self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=self.environ(),
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(argv, 124, exc.stdout or "", f"timed out after {timeout}s")
            self._log.append(result)
            if check:
                raise AzError(result) from exc
            return result

        result = CommandResult(argv, proc.returncode, proc.stdout, proc.stderr)
        self._log.append(result)
        if check and not result.ok:
            raise AzError(result)
        return result

    def version(self) -> tuple[int, ...] | None:
        """Return the installed Terraform version, or None if unreadable."""
        if shutil.which("terraform") is None:
            return None
        # `terraform version` is a subcommand, but -chdir on a directory that
        # does not exist yet makes it fail, so bypass build().
        proc = subprocess.run(
            ["terraform", "version", "-json"],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if proc.returncode != 0:
            return None
        import json
        import re

        try:
            raw = json.loads(proc.stdout).get("terraform_version", "")
        except (ValueError, AttributeError):
            raw = proc.stdout
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
        return tuple(int(g) for g in match.groups()) if match else None
