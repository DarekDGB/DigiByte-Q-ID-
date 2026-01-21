"""
MIT License
Copyright (c) 2025 DarekDGB
"""

from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path

import pytest


def _load_contract() -> dict:
    p = Path(__file__).resolve().parents[1] / "contracts" / "api_surface_v0_1.json"
    raw = p.read_text(encoding="utf-8")
    return json.loads(raw)


def _import_object(spec: str):
    """
    spec format: "module.path:attr_name"
    """
    if ":" not in spec:
        raise ValueError(f"Invalid import spec (missing ':'): {spec!r}")
    mod_name, attr = spec.split(":", 1)
    mod = importlib.import_module(mod_name)
    if not hasattr(mod, attr):
        raise AttributeError(f"Missing {attr!r} in module {mod_name!r}")
    return getattr(mod, attr)


def test_api_surface_contract_v0_1_is_enforced() -> None:
    c = _load_contract()
    assert c["version"] == "v0.1"
    assert isinstance(c["public_functions"], list)
    assert len(c["public_functions"]) >= 10  # sanity: should not be empty

    for entry in c["public_functions"]:
        spec = entry["import"]
        expected_args = entry.get("args", [])
        expected_kwonly = entry.get("kwonly", [])

        obj = _import_object(spec)
        assert callable(obj), f"{spec} must be callable"

        sig = inspect.signature(obj)
        params = list(sig.parameters.values())

        # We only lock simple function signatures: positional-or-keyword args + kwonly.
        pos = [p.name for p in params if p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD]
        kwonly = [p.name for p in params if p.kind == inspect.Parameter.KEYWORD_ONLY]

        assert pos == expected_args, f"{spec} args changed: {pos} != {expected_args}"
        assert kwonly == expected_kwonly, f"{spec} kwonly changed: {kwonly} != {expected_kwonly}"
