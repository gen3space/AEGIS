from __future__ import annotations

import importlib.util
from pathlib import Path


def test_repository_zero_leak_privacy_hygiene() -> None:
    root = Path(__file__).resolve().parent.parent
    script_path = root / "scripts" / "verify_clean_repo.py"
    spec = importlib.util.spec_from_file_location("verify_clean_repo", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    issues = mod.scan_repository(root)
    assert issues == [], f"Privacy / secret hygiene issues detected: {issues}"
