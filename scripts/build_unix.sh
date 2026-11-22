#!/usr/bin/env bash
# ==============================================================================
# Build Standalone Linux / macOS Executable (`dist/aegis-<os>-<arch>`)
# Usage: bash scripts/build_unix.sh
# ==============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[Aegis] Installing package and PyInstaller..."
python3 -m pip install --upgrade pip
python3 -m pip install -e . pyinstaller

echo "[Aegis] Building standalone binary..."
python3 -m PyInstaller scripts/aegis.spec --clean --noconfirm

chmod +x dist/aegis-*
if command -v sha256sum >/dev/null 2>&1; then
    (cd dist && sha256sum aegis-* > SHA256SUMS.txt)
elif command -v shasum >/dev/null 2>&1; then
    (cd dist && shasum -a 256 aegis-* > SHA256SUMS.txt)
fi

echo "[Aegis] Build complete! Artifacts in ./dist:"
ls -lh dist/
