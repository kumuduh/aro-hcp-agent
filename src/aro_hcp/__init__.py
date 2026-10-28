"""Provision Azure Red Hat OpenShift clusters with hosted control planes."""

from __future__ import annotations

import sys

from .config import BACKENDS, ClusterConfig, ConfigError
from .destroy import DESTROY_PHASES, build_destroy_plan
from .plan import PHASES, Step, build_plan
from .preflight import PreflightReport, run_preflight
from .runner import Runner, TerraformCli
from .terraform import (
    TERRAFORM_DESTROY_PHASES,
    TERRAFORM_PHASES,
    build_terraform_destroy_plan,
    build_terraform_plan,
    render_tfvars,
)

__all__ = [
    "BACKENDS",
    "ClusterConfig",
    "ConfigError",
    "PHASES",
    "PreflightReport",
    "Runner",
    "Step",
    "TERRAFORM_DESTROY_PHASES",
    "TERRAFORM_PHASES",
    "TerraformCli",
    "build_plan",
    "build_destroy_plan",
    "build_terraform_plan",
    "build_terraform_destroy_plan",
    "render_tfvars",
    "DESTROY_PHASES",
    "run_preflight",
    "main",
]

__version__ = "0.1.0"


def main() -> None:
    """Console script entry point."""
    from .cli import main as cli_main

    sys.exit(cli_main())
