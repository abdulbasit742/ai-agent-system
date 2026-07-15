from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def run(command: list[str], cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Clone integrations at reviewed, pinned commits.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--update", action="store_true", help="Fetch an existing checkout before resetting to the pinned commit.")
    args = parser.parse_args()
    root = args.root.resolve()
    lock = json.loads((root / "integrations.lock.json").read_text(encoding="utf-8"))
    for item in lock["integrations"]:
        destination = root / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if not (destination / ".git").exists():
                raise RuntimeError(f"refusing to replace non-git path: {destination}")
            if args.update:
                run(["git", "fetch", "--all", "--tags", "--prune"], cwd=destination)
        else:
            run(["git", "clone", "--filter=blob:none", "--no-checkout", item["url"], str(destination)])
        run(["git", "checkout", "--detach", item["commit"]], cwd=destination)
        print(f"PINNED {item['name']} {item['commit'][:12]} -> {destination.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
