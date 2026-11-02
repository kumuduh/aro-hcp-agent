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

#: Environment variables passed through to `terraform`, by exact name. The rest
#: of the caller's environment is dropped: TF_CLI_ARGS*, TF_VAR_* and
#: TF_WORKSPACE would otherwise widen or redirect an apply without appearing
#: in the reviewed command line (D30, TF-21/23).
_ENV_ALLOW = frozenset({
    # process basics
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TEMP", "TMP",
    "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "NO_COLOR",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
    # Windows equivalents of the above
    "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR",
    "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    # network: proxies and private CAs, without which providers cannot download
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    # managed identity / workload identity endpoints for provider auth
    "MSI_ENDPOINT", "MSI_SECRET", "IDENTITY_ENDPOINT", "IDENTITY_HEADER",
    # Terraform operational settings that cannot change what is planned.
    # TF_CLI_CONFIG_FILE stays: ~/.terraformrc is read via HOME regardless, and
    # mirrors configured there are how air-gapped sites install providers.
    "TF_LOG", "TF_LOG_PATH", "TF_LOG_CORE", "TF_LOG_PROVIDER",
    "TF_PLUGIN_CACHE_DIR", "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE",
    "TF_CLI_CONFIG_FILE",
})

#: ...and by prefix: azurerm/azapi authentication (ARM_CLIENT_ID, ARM_USE_OIDC,
#: ...) and the az CLI's own settings (AZURE_CONFIG_DIR), which the providers'
#: default CLI authentication shells out to.
_ENV_ALLOW_PREFIXES = ("ARM_", "AZURE_")

#: Subcommands that do not take -no-color.
_NO_COLOR_EXEMPT = frozenset({"version", "-version", "help", "-help", "fmt"})

#: Subcommands whose second word is part of the command (`state list`).
_NESTED = frozenset({"state", "workspace", "providers"})


def _text(value) -> str:
    """``TimeoutExpired.stdout`` is bytes even under ``text=True`` (O8)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


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
        is why it cannot simply be appended by the caller. ``-no-color`` goes
        straight after the subcommand: output is captured into logs, state
        details and the agent's context, where ANSI escapes are noise (NFR-8).
        """
        args = list(args)
        if args and args[0] not in _NO_COLOR_EXEMPT and "-no-color" not in args:
            words = 2 if (args[0] in _NESTED and len(args) > 1
                          and not args[1].startswith("-")) else 1
            args = [*args[:words], "-no-color", *args[words:]]
        return ["terraform", f"-chdir={self.module_dir}", *args]

    def environ(self) -> dict[str, str]:
        env = {
            key: value for key, value in os.environ.items()
            if key in _ENV_ALLOW or key.startswith(_ENV_ALLOW_PREFIXES)
        }
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
                # Terraform's state and its .backup hold every resource's
                # attributes in plain text, Key Vault secret values included
                # (the pull secret): create them private, like aro-hcp state.
                **({"umask": 0o077} if os.name == "posix" else {}),
            )
        except subprocess.TimeoutExpired as exc:
            partial_err = _text(exc.stderr).strip()
            message = f"timed out after {timeout}s" + (f"\n{partial_err}" if partial_err else "")
            result = CommandResult(argv, 124, _text(exc.stdout), message)
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
