"""Give the cluster a Red Hat pull secret (``pull_secret_path``).

ARO HCP is created with only the service's own registry credentials, so Red
Hat images and OperatorHub content fail to pull. Neither ``az aro hcp cluster
create`` nor the hcpOpenShiftClusters API takes a pull secret. HyperShift
instead merges a ``kube-system/additional-pull-secret`` Secret in the hosted
cluster into every node's kubelet credentials (the global-pull-secret-syncer
DaemonSet). Both backends apply that Secret as their last step; the terraform
backend also stores the file in Key Vault through the module's own
``pull_secret_path`` variable.

The secret's content never reaches argv, logs, state or a step's output: it
goes to `oc`/`kubectl` on stdin, the admin kubeconfig lives in a private
temporary directory for the duration of the step, and state keeps only a
SHA-256 so a changed file is applied again.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .azure import AzResult
from .plan import Step

NAMESPACE = "kube-system"
SECRET_NAME = "additional-pull-secret"
STEP_ID = "pull-secret"
PHASE = "pull-secret"
#: State context key: SHA-256 of the file last applied.
DIGEST_KEY = "PULL_SECRET_SHA256"

#: A dockerconfigjson is a few KB; refuse anything far larger before reading it.
MAX_BYTES = 1024 * 1024
KUBE_TIMEOUT = 120

#: Errors worth retrying: a credential minted moments ago, or an API server
#: still settling just after the cluster reports Succeeded. About a minute in
#: all, so a credential that is simply wrong is reported promptly.
_RETRY_DELAYS = (10, 20, 30)
_TRANSIENT = (
    "unauthorized",
    "connection refused",
    "i/o timeout",
    "no such host",
    "tls handshake timeout",
    "the server is currently unable",
    "service unavailable",
    "context deadline exceeded",
)


class PullSecretError(ValueError):
    """The file is unusable. Messages never quote its content."""


def read(path: str) -> bytes:
    """Return the file's bytes after checking it is a dockerconfigjson."""
    file = Path(path)
    try:
        size = file.stat().st_size
        if size > MAX_BYTES:
            raise PullSecretError(f"pull_secret_path {path}: {size} bytes is too large "
                                  "for a pull secret")
        content = file.read_bytes()
    except OSError as exc:
        raise PullSecretError(f"pull_secret_path {path}: cannot read it: "
                              f"{exc.strerror or exc}") from exc
    try:
        data = json.loads(content)
    except ValueError:
        raise PullSecretError(f"pull_secret_path {path}: not valid JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("auths"), dict) \
            or not data["auths"]:
        raise PullSecretError(
            f"pull_secret_path {path}: expected a dockerconfigjson with a non-empty "
            '"auths" object, as downloaded from console.redhat.com/openshift/install/pull-secret'
        )
    return content


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def encode(content: bytes) -> str:
    return base64.b64encode(content).decode("ascii")


def manifest(encoded: str) -> str:
    return json.dumps({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": SECRET_NAME, "namespace": NAMESPACE},
        "type": "kubernetes.io/dockerconfigjson",
        "data": {".dockerconfigjson": encoded},
    })


def kube_client() -> str | None:
    return shutil.which("oc") or shutil.which("kubectl")


def build_step(config, *, after: tuple[str, ...]) -> Step:
    return Step(
        id=STEP_ID,
        phase=PHASE,
        description=f"Add the Red Hat pull secret to the cluster ({NAMESPACE}/{SECRET_NAME})",
        # Display only: the action reads the file itself.
        args=["apply-pull-secret", f"{NAMESPACE}/{SECRET_NAME}", config.pull_secret_path],
        action="apply-pull-secret",
        timeout=KUBE_TIMEOUT,
        tags=("pull-secret",),
        after=after,
    )


def invalidate_if_changed(config, run_state) -> None:
    """Re-open the step when the file differs from the one last applied.

    The step has no Azure resource to probe, so a completed run would
    otherwise never pick up a rotated secret.
    """
    if not config.pull_secret_path or not run_state.is_complete(STEP_ID):
        return
    try:
        current = digest(read(config.pull_secret_path))
    except PullSecretError:
        return  # validation reports it
    if run_state.get(DIGEST_KEY) != current:
        run_state.reset(STEP_ID)


def _redact(text: str, *secrets: str) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def action_apply_pull_secret(executor, step: Step) -> AzResult:
    config = executor.config
    argv = step.render(executor.context)
    try:
        content = read(config.pull_secret_path)
    except PullSecretError as exc:
        return AzResult(argv, 1, "", str(exc))
    client = kube_client()
    if client is None:
        return AzResult(argv, 1, "", "neither `oc` nor `kubectl` is on PATH; one is needed "
                                     "to add the pull secret to the cluster")

    encoded = encode(content)
    body = manifest(encoded)
    secrets = (encoded, content.decode("utf-8", "replace"))
    workdir = Path(tempfile.mkdtemp(prefix="aro-hcp-"))  # 0700
    try:
        kubeconfig = workdir / "kubeconfig"
        # A 24-hour admin credential, written straight to the private file.
        cred = executor.az.run(
            ["aro", "hcp", "cluster", "request-credential", "--admin",
             "--name", config.cluster_name, "--resource-group", config.resource_group,
             "--file", str(kubeconfig), "--output", "none"],
            check=False, timeout=600,
        )
        if not cred.ok or not kubeconfig.is_file():
            detail = cred.stderr.strip() or "no kubeconfig was written"
            return AzResult(argv, 1, "", f"could not get an admin credential: {detail}")

        command = [client, "--kubeconfig", str(kubeconfig), "apply", "-f", "-"]
        delays = (0, *_RETRY_DELAYS)
        for attempt, delay in enumerate(delays):
            if delay:
                executor.on_event(f"wait  {step.id}: the cluster API refused or did not "
                                  f"answer; retrying in {delay}s")
                executor.sleep(delay)
            try:
                proc = subprocess.run(command, input=body, capture_output=True, text=True,
                                      timeout=KUBE_TIMEOUT, check=False,
                                      env={**os.environ, "KUBECONFIG": str(kubeconfig)})
            except subprocess.TimeoutExpired:
                out, err, rc = "", f"`{Path(client).name} apply` timed out", 124
            else:
                out, err, rc = proc.stdout, proc.stderr, proc.returncode
            out, err = _redact(out, *secrets), _redact(err, *secrets)
            if rc == 0:
                break
            if attempt == len(delays) - 1 or not any(m in err.lower() for m in _TRANSIENT):
                return AzResult(argv, rc or 1, out, err)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    sha = digest(content)
    executor.state.set_context(DIGEST_KEY, sha)
    return AzResult(argv, 0, f"{out.strip()} (sha256 {sha[:12]})", "")


ACTIONS = {"apply-pull-secret": action_apply_pull_secret}
