#!/usr/bin/env python3

import hashlib
import json
import subprocess
import sys
from pathlib import Path


LICENSE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE")
OVERRIDES_PATH = Path(__file__).with_name("third-party-license-overrides.json")


def is_notice(root: Path, path: Path) -> bool:
    name = path.name.upper()
    if any(
        name == prefix
        or name.startswith(prefix + "-")
        or name.startswith(prefix + ".")
        for prefix in LICENSE_NAMES
    ):
        return True

    relative = path.relative_to(root)
    return (
        len(relative.parts) == 2
        and relative.parts[0].upper() in {"LICENSES", "LICENCES"}
        and path.suffix.lower() in {"", ".md", ".txt"}
    )


def load_overrides() -> dict[str, dict]:
    data = json.loads(OVERRIDES_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(
        isinstance(key, str) and isinstance(value, dict)
        for key, value in data.items()
    ):
        raise ValueError("license override manifest must be an object")
    return data


def read_override(package: dict, override: dict) -> list[tuple[str, str, str]]:
    key = f"{package['name']} {package['version']}"
    expected_fields = {
        "declared_license",
        "package_source",
        "selected_license",
        "notices",
    }
    if set(override) != expected_fields:
        raise ValueError(f"{key}: license override fields do not match the schema")
    if override["declared_license"] != package.get("license"):
        raise ValueError(f"{key}: declared license changed")
    if override["package_source"] != package.get("source"):
        raise ValueError(f"{key}: package source changed")
    if not isinstance(override["selected_license"], str) or not override["selected_license"]:
        raise ValueError(f"{key}: selected license is missing")
    if override["selected_license"] not in override["declared_license"]:
        raise ValueError(f"{key}: selected license is not declared by the crate")
    if not isinstance(override["notices"], list) or not override["notices"]:
        raise ValueError(f"{key}: license override has no notices")

    base = OVERRIDES_PATH.parent.resolve()
    notices = []
    for notice in override["notices"]:
        if not isinstance(notice, dict) or set(notice) != {"path", "sha256", "source"}:
            raise ValueError(f"{key}: license notice fields do not match the schema")
        if not isinstance(notice["source"], str) or not notice["source"].startswith("https://"):
            raise ValueError(f"{key}: license notice source must use HTTPS")
        path = (OVERRIDES_PATH.parent / notice["path"]).resolve()
        try:
            display_path = path.relative_to(base)
        except ValueError as error:
            raise ValueError(f"{key}: license notice escapes the scripts directory") from error
        body = path.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        if digest != notice["sha256"]:
            raise ValueError(f"{key}: license notice checksum mismatch: {display_path}")
        notices.append(
            (str(display_path), body.decode("utf-8"), notice["source"])
        )
    return notices


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: generate-third-party-licenses.py OUTPUT", file=sys.stderr)
        return 2

    try:
        overrides = load_overrides()
        metadata = json.loads(
            subprocess.run(
                ["cargo", "metadata", "--format-version", "1", "--locked"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"third-party license generation failed: {error}", file=sys.stderr)
        return 1
    workspace = set(metadata["workspace_members"])
    packages = sorted(
        (package for package in metadata["packages"] if package["id"] not in workspace),
        key=lambda package: (package["name"].lower(), package["version"]),
    )

    output = [
        "# Third-Party Licenses\n",
        "This file is generated from the dependency sources locked by Cargo.lock.\n",
    ]
    errors = []
    used_overrides = set()
    for package in packages:
        key = f"{package['name']} {package['version']}"
        root = Path(package["manifest_path"]).parent
        notices = sorted(
            path
            for path in root.rglob("*")
            if path.is_file()
            and len(path.relative_to(root).parts) <= 2
            and is_notice(root, path)
        )
        output.append(f"\n## {package['name']} {package['version']}\n")
        output.append(f"Declared license: {package.get('license') or 'not specified'}\n")
        if package.get("repository"):
            output.append(f"Upstream: {package['repository']}\n")

        if notices:
            if key in overrides:
                errors.append(f"{key}: override is no longer needed")
            for notice in notices:
                output.append(f"\n### {notice.relative_to(root)}\n\n```text\n")
                output.append(notice.read_text(encoding="utf-8", errors="strict"))
                if not output[-1].endswith("\n"):
                    output.append("\n")
                output.append("```\n")
            continue

        override = overrides.get(key)
        if override is None:
            errors.append(f"{key}: published crate contains no license or notice file")
            continue
        used_overrides.add(key)
        try:
            override_notices = read_override(package, override)
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(str(error))
            continue
        output.append(f"Selected license: {override['selected_license']}\n")
        if package.get("authors"):
            output.append(f"Published crate authors: {', '.join(package['authors'])}\n")
        output.append(
            "License source: pinned override for a crate without a published notice.\n"
        )
        for display_path, body, source in override_notices:
            output.append(f"Source: {source}\n")
            output.append(f"\n### {display_path}\n\n```text\n")
            output.append(body)
            if not output[-1].endswith("\n"):
                output.append("\n")
            output.append("```\n")

    for key in sorted(set(overrides) - used_overrides):
        if key not in {f"{package['name']} {package['version']}" for package in packages}:
            errors.append(f"{key}: override does not match a locked dependency")

    if errors:
        print("third-party license generation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    destination = Path(sys.argv[1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("".join(output), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
