#!/usr/bin/env python3

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: check-glibc-baseline.py MAX_VERSION ELF...", file=sys.stderr)
        return 2

    maximum = version(sys.argv[1])
    failed = False
    for raw_path in sys.argv[2:]:
        path = Path(raw_path)
        result = subprocess.run(
            ["readelf", "--version-info", "--wide", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        required = {
            version(match)
            for match in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", result.stdout)
        }
        newest = max(required, default=(0,))
        print(f"{path}: GLIBC_{'.'.join(map(str, newest))}")
        if newest > maximum:
            failed = True

    if failed:
        print(
            f"required glibc exceeds {'.'.join(map(str, maximum))}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
