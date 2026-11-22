# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Cross-Platform Standalone Binary Spec for Aegis (Windows / Linux / macOS).
Produces a single portable executable bundling FastAPI, Uvicorn, WebSockets, and `aegis/static/*`.
"""

import platform
import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
STATIC_SRC = str(ROOT / "aegis" / "static")

os_tag = {
    "win32": "windows",
    "darwin": "macos",
}.get(sys.platform, "linux")

arch_raw = platform.machine().lower()
arch_tag = "arm64" if arch_raw in ("arm64", "aarch64") else "x64"
binary_name = f"aegis-{os_tag}-{arch_tag}"

a = Analysis(
    [str(ROOT / "aegis" / "__main__.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(STATIC_SRC, "aegis/static")],
    hiddenimports=[
        "aegis",
        "aegis.cli",
        "aegis.config",
        "aegis.core",
        "aegis.dpi_engine",
        "aegis.enricher",
        "aegis.host_correlator",
        "aegis.server",
        "aegis.shield_control",
        "aegis.threat_intel",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.protocols.websockets.wsproto_impl",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "dns.resolver",
        "dns.rdtypes.ANY.TXT",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "torch",
        "torchaudio",
        "torchvision",
        "tensorflow",
        "transformers",
        "scipy",
        "numpy",
        "pandas",
        "matplotlib",
        "PIL",
        "cv2",
        "sklearn",
        "tkinter",
        "pytest",
        "IPython",
        "notebook",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=binary_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
