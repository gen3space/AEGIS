from __future__ import annotations

import time
from pathlib import Path

from aegis.config import AegisConfig
from aegis.core import NGFWTelemetryCore


def test_zero_config_auto_mode_selects_tier1_system_shield(tmp_path: Path) -> None:
    cfg = AegisConfig(
        mode="auto",
        router_explicitly_configured=False,
        auto_update_feeds=False,
        data_dir=tmp_path / "data",
    )
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    core = NGFWTelemetryCore(cfg)
    try:
        core.startup()
        assert core.config.mode == "system"
        time.sleep(0.35)
        snap = core.tick_1s_snapshot()
        assert snap["status"]["mode"] == "system"
        assert snap["status"]["tier"] == 1
        assert snap["status"]["error"] == ""
        assert 0 <= snap["kpis"]["shield_score"] <= 100
    finally:
        core.shutdown()
