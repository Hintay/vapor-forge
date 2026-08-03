#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path


LICENSE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE")


def is_notice(path: Path) -> bool:
    name = path.name.upper()
    return any(name == prefix or name.startswith(prefix + "-") or name.startswith(prefix + ".") for prefix in LICENSE_NAMES)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: generate-third-party-licenses.py OUTPUT", file=sys.stderr)
        return 2

    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    workspace = set(metadata["workspace_members"])
    packages = sorted(
        (package for package in metadata["packages"] if package["id"] not in workspace),
        key=lambda package: (package["name"].lower(), package["version"]),
    )

    output = [
        "# Third-Party Licenses\n",
        "This file is generated from the dependency sources locked by Cargo.lock.\n",
    ]
    missing = []
    for package in packages:
        root = Path(package["manifest_path"]).parent
        notices = sorted(
            path
            for path in root.rglob("*")
            if path.is_file() and len(path.relative_to(root).parts) <= 2 and is_notice(path)
        )
        if not notices:
            missing.append(f"{package['name']} {package['version']}")
        output.append(f"\n## {package['name']} {package['version']}\n")
        output.append(f"Declared license: {package.get('license') or 'not specified'}\n")
        if package.get("repository"):
            output.append(f"Upstream: {package['repository']}\n")
        if not notices:
            output.append("\nThe published crate contains no standalone license or notice file.\n")
        for notice in notices:
            output.append(f"\n### {notice.relative_to(root)}\n\n```text\n")
            output.append(notice.read_text(encoding="utf-8", errors="replace"))
            if not output[-1].endswith("\n"):
                output.append("\n")
            output.append("```\n")

    if missing:
        print("dependencies without standalone license files: " + ", ".join(missing))

    destination = Path(sys.argv[1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("".join(output), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
