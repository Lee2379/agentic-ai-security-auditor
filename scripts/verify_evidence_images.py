#!/usr/bin/env python3
"""Verify reviewed public evidence-image derivatives against the committed manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "assets" / "evidence" / "manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures: list[str] = []
    for item in manifest["artifacts"]:
        path = ROOT / item["path"]
        if not path.is_file():
            failures.append(f"missing: {item['path']}")
            continue
        if path.stat().st_size != item["bytes"]:
            failures.append(f"size mismatch: {item['path']}")
        if sha256(path) != item["sha256"]:
            failures.append(f"hash mismatch: {item['path']}")
    if failures:
        print("evidence image verification failed")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"evidence image verification passed: {len(manifest['artifacts'])} reviewed files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
