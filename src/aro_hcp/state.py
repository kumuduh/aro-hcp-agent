"""Run state: what has been done, and the IDs discovered along the way.

Persisting this is what makes `apply` resumable after a failure part-way
through 60-odd steps. It is also the easiest thing in this tool to get subtly
wrong, so the loader is strict: a state file for a different cluster, a
different subscription, or a materially different config is refused rather
than adopted, because its captured resource IDs would silently point the run
at the wrong resources.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATE_VERSION = 1

PENDING = "pending"
DONE = "done"
SKIPPED = "skipped"  # already existed
FAILED = "failed"


class StateError(ValueError):
    """The state file is unreadable, or describes a different target."""


class StateLocked(StateError):
    """Another run holds the lock for this state file."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


#: Values that look like credentials are masked before they reach disk. Step
#: details hold raw az stderr, which is usually harmless but occasionally
#: echoes a connection string or SAS token back.
_SECRET_PATTERNS = (
    re.compile(r"(?i)((?:password|secret|accountkey|sharedaccesssignature|sig|token)\s*[=:]\s*)[^\s;&\"']+"),
    re.compile(r"(?i)(\"(?:password|secret|value|key|token|connectionString)\"\s*:\s*\")[^\"]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    # A bare JWT: three base64url segments, the first starting with "eyJ".
    re.compile(r"()eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
)


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\1<redacted>", text)
    return text


@dataclass
class RunState:
    path: Path
    cluster_name: str = ""
    subscription_id: str = ""
    #: Config values a completed step depends on. A resume against different
    #: values would skip steps whose resources no longer match the config.
    fingerprint: dict[str, str] = field(default_factory=dict)
    context: dict[str, str] = field(default_factory=dict)
    steps: dict[str, dict] = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)

    # -- persistence --------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "RunState":
        path = Path(path)
        if not path.exists():
            return cls(path=path)
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise StateError(
                f"{path}: state file is unreadable ({exc}). It was left untouched; "
                "move it aside to start fresh, or restore it from a backup"
            ) from exc
        if not isinstance(data, dict):
            raise StateError(f"{path}: state file is not a JSON object")
        version = data.get("version")
        if version != STATE_VERSION:
            raise StateError(
                f"{path}: state file version {version!r} is not supported by this "
                f"release (expected {STATE_VERSION}); move it aside to start fresh"
            )
        expected = {"context": dict, "steps": dict, "history": list, "fingerprint": dict}
        for key, kind in expected.items():
            if key in data and not isinstance(data[key], kind):
                raise StateError(
                    f"{path}: '{key}' should be a {kind.__name__}, found "
                    f"{type(data[key]).__name__}; the file is corrupt"
                )
        return cls(
            path=path,
            cluster_name=data.get("cluster_name", ""),
            subscription_id=data.get("subscription_id", ""),
            fingerprint=data.get("fingerprint", {}),
            context=data.get("context", {}),
            steps=data.get("steps", {}),
            history=data.get("history", []),
        )

    def bind(self, cluster_name: str, subscription_id: str, fingerprint: dict[str, str]) -> None:
        """Attach this state to a target, refusing one recorded for another.

        Before this check the executor overwrote the labels and kept the
        captured IDs, so a ``--state`` file from another cluster ran
        commands against that cluster's VNet.
        """
        if self.cluster_name and self.cluster_name != cluster_name:
            raise StateError(
                f"{self.path} records cluster {self.cluster_name!r}, not "
                f"{cluster_name!r}; refusing to reuse another cluster's state"
            )
        if self.subscription_id and subscription_id and self.subscription_id != subscription_id:
            raise StateError(
                f"{self.path} records subscription {self.subscription_id}, not "
                f"{subscription_id}; its captured resource IDs belong to the other "
                "subscription"
            )
        if self.steps:
            changed = [
                f"{key}: {self.fingerprint[key]!r} -> {value!r}"
                for key, value in fingerprint.items()
                if key in self.fingerprint and self.fingerprint[key] != value
            ]
            if changed:
                raise StateError(
                    f"{self.path} was recorded with different settings:\n"
                    + "\n".join(f"  - {c}" for c in changed)
                    + "\nCompleted steps would be skipped although their resources no "
                    "longer match the config. Tear the cluster down first, or use a "
                    "different cluster_name"
                )
        self.cluster_name = cluster_name
        self.subscription_id = subscription_id or self.subscription_id
        self.fingerprint = {**self.fingerprint, **fingerprint}

    def save(self) -> None:
        payload = {
            "version": STATE_VERSION,
            "cluster_name": self.cluster_name,
            "subscription_id": self.subscription_id,
            "updated_at": _now(),
            "fingerprint": self.fingerprint,
            "context": self.context,
            "steps": self.steps,
            "history": self.history[-500:],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Atomic write: a crash mid-save must not leave a truncated state file.
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            # mkstemp already creates 0600; keep it that way across replace.
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)

    @contextmanager
    def lock(self):
        """Hold an exclusive lock for the duration of a mutating run.

        Atomic replace keeps one writer's file intact, but two concurrent
        applies would still each create resources and overwrite each other's
        records. The lock makes the second run fail fast instead.
        """
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = self.path.with_name(self.path.name + ".lock")
        # The lock file is left in place: unlinking it on release would let a
        # third run lock a fresh inode while a second still waits on the old.
        handle = open(lock_path, "w")
        try:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise StateLocked(
                    f"another aro-hcp run is using {self.path}; wait for it to finish"
                ) from exc
            # Another run may have finished between our load and our lock;
            # pick up its records rather than overwrite them with a stale copy.
            if self.path.exists():
                fresh = RunState.load(self.path)
                self.steps = {**fresh.steps, **{k: v for k, v in self.steps.items()
                                               if k not in fresh.steps}}
                self.context = {**fresh.context, **self.context}
                self.history = fresh.history + [h for h in self.history if h not in fresh.history]
            yield self
        finally:
            handle.close()

    # -- queries ------------------------------------------------------------

    def status(self, step_id: str) -> str:
        return self.steps.get(step_id, {}).get("status", PENDING)

    def is_complete(self, step_id: str) -> bool:
        return self.status(step_id) in (DONE, SKIPPED)

    def get(self, name: str) -> str:
        return self.context.get(name, "")

    # -- mutation -----------------------------------------------------------

    def set_context(self, name: str, value: str) -> None:
        if value:
            self.context[name] = value

    def record(
        self,
        step_id: str,
        status: str,
        *,
        command: str = "",
        detail: str = "",
    ) -> None:
        entry = {"status": status, "at": _now(), "command": command}
        if detail:
            entry["detail"] = redact(detail)[:4000]
        self.steps[step_id] = entry
        self.history.append({"step": step_id, **entry})

    def note(self, event: str, detail: str = "") -> None:
        """Record a run-level event, such as an operator override."""
        self.history.append({"event": event, "at": _now(), "detail": detail})

    def reset(self, step_id: str) -> None:
        self.steps.pop(step_id, None)

    def summary(self) -> dict[str, int]:
        counts = {PENDING: 0, DONE: 0, SKIPPED: 0, FAILED: 0}
        for entry in self.steps.values():
            status = entry.get("status", PENDING)
            counts[status] = counts.get(status, 0) + 1
        return counts


def default_state_path(
    cluster_name: str,
    directory: str | Path | None = None,
    *,
    suffix: str | None = None,
) -> Path:
    base = Path(directory) if directory else Path.cwd() / ".aro-hcp"
    stem = f"{cluster_name}.{suffix}" if suffix else cluster_name
    return base / f"{stem}.state.json"


def destroy_state_path(build_state: Path) -> Path:
    """The teardown state that pairs with a build state, custom paths included.

    Build and teardown must never share a file: teardown's "done" marks would
    otherwise satisfy the next apply.
    """
    name = build_state.name
    if name.endswith(".state.json"):
        stem = name[: -len(".state.json")]
        return build_state.with_name(f"{stem}.destroy.state.json")
    return build_state.with_name(name + ".destroy")
