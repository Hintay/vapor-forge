#!/usr/bin/env python3
"""Enforce the workspace's crate layering.

Rules name packages by their real Cargo names. Both the rule subject and the
named dependency are validated against the workspace, so a renamed or misspelled
crate fails loudly instead of silently disabling its rule.
"""
import json
import subprocess
import sys


metadata = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        text=True,
    )
)
packages = {
    package["name"]: {dependency["name"] for dependency in package["dependencies"]}
    for package in metadata["packages"]
}
failures: list[str] = []


def workspace_package(package: str) -> set[str]:
    try:
        return packages[package]
    except KeyError:
        failures.append(f"rule names a package that is not in the workspace: {package}")
        return set()


def rule(package: str, dependency: str) -> tuple[set[str], bool]:
    """Resolve a rule's operands, reporting either name if it does not exist."""
    dependencies = workspace_package(package)
    # Only workspace crates are subject to layering rules; third-party names
    # would silently never match, so reject them here.
    if dependency.startswith("vapor-forge-") and dependency not in packages:
        failures.append(
            f"rule names a dependency that is not in the workspace: {dependency}"
        )
        return dependencies, False
    return dependencies, True


def forbid_dependency(package: str, dependency: str) -> None:
    dependencies, valid = rule(package, dependency)
    if valid and dependency in dependencies:
        failures.append(f"{package} must not depend on {dependency}")


def require_dependency(package: str, dependency: str) -> None:
    dependencies, valid = rule(package, dependency)
    if valid and dependency not in dependencies:
        failures.append(f"{package} must depend on {dependency}")


# `features` holds Steam-facing policy. It must stay below the cloud transport,
# durable storage and native-ABI layers so those can depend on it, not the
# reverse.
for forbidden in (
    "vapor-forge-steam-native-abi",
    "vapor-forge-cloud-cumulus",
    "vapor-forge-cloud-local",
    "vapor-forge-cloud-rpc",
    "vapor-forge-sync-journal",
    "vapor-forge-hooks",
):
    forbid_dependency("vapor-forge-features", forbidden)

# Wire types stay free of native layout knowledge.
forbid_dependency("vapor-forge-steam-protocol", "vapor-forge-steam-native-abi")

# `cloud-core` defines the backend port; concrete backends and the RPC
# translation layer implement it.
forbid_dependency("vapor-forge-cloud-core", "vapor-forge-cloud-cumulus")
forbid_dependency("vapor-forge-cloud-core", "vapor-forge-cloud-local")
forbid_dependency("vapor-forge-cloud-core", "vapor-forge-cloud-rpc")
forbid_dependency("vapor-forge-cloud-core", "vapor-forge-sync-journal")
require_dependency("vapor-forge-cloud-cumulus", "vapor-forge-cloud-core")
require_dependency("vapor-forge-cloud-local", "vapor-forge-cloud-core")

# The durable journal is storage only: it knows the cloud value types and
# nothing about how they are transported.
forbid_dependency("vapor-forge-sync-journal", "vapor-forge-cloud-cumulus")
forbid_dependency("vapor-forge-sync-journal", "vapor-forge-cloud-rpc")

engine_dependencies = workspace_package("vapor-forge-hook-engine")
workspace_engine_dependencies = sorted(
    dependency
    for dependency in engine_dependencies
    if dependency.startswith("vapor-forge-")
)
if workspace_engine_dependencies:
    failures.append(
        "vapor-forge-hook-engine must not depend on target-specific workspace crates: "
        + ", ".join(workspace_engine_dependencies)
    )

if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)

print("architecture dependency boundaries: ok")
