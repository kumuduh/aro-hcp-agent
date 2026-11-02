"""Thin, testable wrapper around the `az` CLI."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

DEFAULT_TIMEOUT = 300
# `az aro hcp cluster create` routinely runs 15-20 minutes.
LONG_TIMEOUT = 2700

# Command groups that must not carry --subscription (Entra ID commands reject it).
_NO_SUBSCRIPTION = {"account", "ad", "extension", "login", "logout"}

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class AzNotFound(RuntimeError):
    """The `az` CLI is not on PATH."""


def token_object_id(token: str) -> str | None:
    """The ``oid`` claim of a JWT access token, or None if it has none.

    The signature is not checked: the token came straight from `az`, and only
    the caller's own object id is read from it.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    oid = claims.get("oid") if isinstance(claims, dict) else None
    return oid if isinstance(oid, str) and _GUID.match(oid) else None


def _text(value) -> str:
    """Partial output from a timed-out process may be bytes even with text=True."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


@dataclass
class AzResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def text(self) -> str:
        return self.stdout.strip()

    def json(self):
        if not self.text:
            return None
        return json.loads(self.text)

    @property
    def command(self) -> str:
        return " ".join(shlex.quote(a) for a in self.args)


class AzError(RuntimeError):
    def __init__(self, result: AzResult):
        self.result = result
        detail = result.stderr.strip() or result.stdout.strip() or "(no output)"
        super().__init__(f"`{result.command}` exited {result.returncode}: {detail}")


class AzCli:
    """Runs `az` commands, optionally in dry-run mode.

    In dry-run mode no process is spawned: every call returns an empty
    successful result, so plan rendering can walk the full step list without
    touching Azure.
    """

    def __init__(
        self,
        subscription: str | None = None,
        *,
        dry_run: bool = False,
        echo: Callable[[str], None] | None = None,
    ) -> None:
        self.subscription = subscription
        self.dry_run = dry_run
        self.echo = echo
        self._log: list[AzResult] = []
        self._principal_oid: str | None = None

    @property
    def log(self) -> list[AzResult]:
        return list(self._log)

    def ensure_available(self) -> str:
        if shutil.which("az") is None:
            raise AzNotFound(
                "the `az` CLI was not found on PATH; see "
                "https://learn.microsoft.com/cli/azure/install-azure-cli"
            )
        return shutil.which("az")  # type: ignore[return-value]

    def build(self, args: Sequence[str]) -> list[str]:
        """Return the full argv for an `az` invocation."""
        argv = ["az", *args]
        if not args or args[0].startswith("-"):
            # Bare flags such as `az --version` take no common arguments.
            return argv
        if "--only-show-errors" not in argv:
            argv.append("--only-show-errors")
        if (
            self.subscription
            and "--subscription" not in argv
            and args[0] not in _NO_SUBSCRIPTION
        ):
            argv += ["--subscription", self.subscription]
        return argv

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        force: bool = False,
    ) -> AzResult:
        """Run an `az` command.

        ``force=True`` runs even in dry-run mode — use it for read-only
        inspection (``show``/``list``) that a plan needs in order to be accurate.
        """
        argv = self.build(args)
        if self.echo:
            self.echo(" ".join(shlex.quote(a) for a in argv))
        if self.dry_run and not force:
            result = AzResult(argv, 0, "", "")
            self._log.append(result)
            return result

        self.ensure_available()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            result = AzResult(argv, 124, _text(exc.stdout), f"timed out after {timeout}s")
            self._log.append(result)
            if check:
                raise AzError(result) from exc
            return result
        except OSError as exc:
            # az vanished or lost its execute bit mid-run. Report it like any
            # other failed command so the executor records the step and the
            # phase's progress is saved, rather than escaping as a traceback.
            result = AzResult(argv, 127, "", f"could not start az: {exc}")
            self._log.append(result)
            if check:
                raise AzError(result) from exc
            return result

        result = AzResult(argv, proc.returncode, proc.stdout, proc.stderr)
        self._log.append(result)
        if check and not result.ok:
            raise AzError(result)
        return result

    # -- convenience --------------------------------------------------------

    def query(self, args: Sequence[str], *, force: bool = True) -> str:
        """Run a read-only command and return trimmed stdout."""
        return self.run(args, check=False, force=force).text

    def current_subscription(self) -> str | None:
        result = self.run(
            ["account", "show", "--query", "id", "--output", "tsv"],
            check=False,
            force=True,
        )
        return result.text or None

    def signed_in_user(self) -> str | None:
        result = self.run(
            ["account", "show", "--query", "user.name", "--output", "tsv"],
            check=False,
            force=True,
        )
        return result.text or None

    def principal_object_id(self) -> str | None:
        """Object id of the signed-in principal, from its ARM token's ``oid`` claim.

        The same for users, service principals and managed identities, and
        needs no Microsoft Graph permission, which a managed identity rarely
        holds. This is also how the azurerm provider learns its object id.
        Asked for the configured subscription, so a guest user gets the object
        id of the tenant that owns it, not of their default account's tenant.
        """
        if self._principal_oid:
            return self._principal_oid
        result = self.run(
            ["account", "get-access-token", "--query", "accessToken", "--output", "tsv",
             *(["--subscription", self.subscription] if self.subscription else [])],
            check=False,
            force=True,
        )
        if self._log and self._log[-1] is result:
            # A bearer token is a credential; keep it out of the command log.
            self._log[-1] = AzResult(result.args, result.returncode, "", result.stderr)
        self._principal_oid = token_object_id(result.text) if result.ok else None
        return self._principal_oid
