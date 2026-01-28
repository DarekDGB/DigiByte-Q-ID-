from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_manifest() -> dict:
    manifest_path = _repo_root() / "contracts" / "manifest_v0_1.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def test_contract_manifest_v0_1_is_enforced() -> None:
    manifest = _load_manifest()

    assert manifest["version"] == "v0.1"
    assert manifest["frozen_at_tag"] == "v0.1.2-ci-locked"

    files = manifest["files"]
    assert isinstance(files, list)
    assert files, "manifest must not be empty"

    seen_paths: set[str] = set()
    root = _repo_root()

    for entry in files:
        assert set(entry.keys()) == {"path", "sha256"}

        rel_path = entry["path"]
        expected_hash = entry["sha256"]

        assert rel_path not in seen_paths, f"duplicate manifest entry: {rel_path}"
        seen_paths.add(rel_path)

        file_path = root / rel_path
        assert file_path.exists(), f"manifest file missing: {rel_path}"

        actual_hash = _sha256_bytes(file_path.read_bytes())
        assert actual_hash == expected_hash, (
            f"hash mismatch for {rel_path}: {actual_hash} != {expected_hash}"
        )


def test_contract_manifest_v0_1_covers_minimum_core_contracts() -> None:
    manifest = _load_manifest()
    covered = {entry["path"] for entry in manifest["files"]}

    assert "contracts/api_surface_v0_1.json" in covered
    assert "docs/CONTRACTS/INDEX.md" in covered
