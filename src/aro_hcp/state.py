"""Run state: what has been done, and the IDs discovered along the way.

Persisting this is what makes `apply` resumable after a failure part-way
through 60-odd steps.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATE_VERSION = 1

PENDING = "pending"
DONE = "done"
SKIPPED = "skipped"  # already existed
FAILED = "failed"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class RunState:
    path: Path
    cluster_name: str = ""
    subscription_id: str = ""
    context: dict[str, str] = field(default_factory=dict)
    steps: dict[str, dict] = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)

    # -- persistence --------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "RunState":
        path = Path(path)
        if not path.exists():
            return cls(path=path)
        data = json.loads(path.read_text())
        version = data.get("version")
        if version != STATE_VERSION:
            raise ValueError(
                f"{path}: state file version {version!r} is not supported by this "
                f"release (expected {STATE_VERSION}); delete it to start fresh"
            )
        return cls(
            path=path,
            cluster_name=data.get("cluster_name", ""),
            subscription_id=data.get("subscription_id", ""),
            context=data.get("context", {}),
            steps=data.get("steps", {}),
            history=data.get("history", []),
        )

    def save(self) -> None:
        payload = {
            "version": STATE_VERSION,
            "cluster_name": self.cluster_name,
            "subscription_id": self.subscription_id,
            "updated_at": _now(),
            "context": self.context,
            "steps": self.steps,
            "history": self.history[-500:],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: a crash mid-save must not leave a truncated state file.
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

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
            entry["detail"] = detail[:4000]
        self.steps[step_id] = entry
        self.history.append({"step": step_id, **entry})

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
