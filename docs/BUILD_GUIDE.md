# 📦 Cross-Platform Build & Installation Guide (Windows, Linux, macOS)

Aegis runs natively on **Windows 10/11**, **Linux** (Ubuntu, Debian, Fedora, Arch), and **macOS** (Apple Silicon & Intel). You can run it directly from Python, via Docker, or compile it into a **single portable standalone binary** (`0` Python installation required on target machines).

---

## 1. Download Pre-Built Standalone Binaries (Zero Dependencies)

Grab the latest native binary for your OS from [**GitHub Releases**](https://github.com/gen3space/AEGIS/releases):

| Platform | Binary Artifact | Quick Run |
| :--- | :--- | :--- |
| **Windows (x64)** | `aegis-windows-x64.exe` | Double-click `aegis-windows-x64.exe` (opens `http://127.0.0.1:8765` in Tier 1 System Shield) or run `.\aegis-windows-x64.exe --router 192.168.1.1` |
| **Linux (x64)** | `aegis-linux-x64` | `chmod +x aegis-linux-x64 && ./aegis-linux-x64 --open-browser` |
| **macOS (Apple Silicon)** | `aegis-macos-arm64` | `chmod +x aegis-macos-arm64 && ./aegis-macos-arm64 --open-browser` |

> [!NOTE]
> **Privilege Tip for Tier 1 (`System Shield`):** Aegis works as a standard non-admin user out-of-the-box. Running as Administrator (Windows) or `sudo` (Linux/macOS) allows the OS kernel to expose PIDs and executable paths for elevated system services in addition to user-space apps.
> For **Tier 2 (`Router Shield`)**, ensure your OS has the standard `ssh` client installed (built-in by default on Windows 10/11, Linux, and macOS).

---

## 2. Install from Source (`pip` / `pipx` / `uv`)

Requires **Python 3.10+**:

```bash
git clone https://github.com/gen3space/AEGIS.git
cd aegis
pip install -e .

# Launch immediately (auto-starts Tier 1 System Shield if no router is configured):
aegis --open-browser
```

Or isolated via `pipx`:
```bash
pipx install git+https://github.com/gen3space/AEGIS.git
aegis --open-browser
```

---

## 3. Build Standalone Native Binaries Yourself (`PyInstaller`)

Aegis includes a cross-platform PyInstaller specification ([`scripts/aegis.spec`](../scripts/aegis.spec)) that bundles the Python interpreter, FastAPI, Uvicorn, WebSockets, DNS resolver, and the entire static Web Console into **one portable file**.

### 🪟 Build on Windows (`PowerShell`)

```powershell
git clone https://github.com/gen3space/AEGIS.git
cd aegis
powershell -ExecutionPolicy Bypass -File scripts/build_windows.ps1
```
Output:
- `dist\aegis-windows-x64.exe`
- `dist\SHA256SUMS-windows.txt`

### 🐧 Build on Linux (`Ubuntu / Debian / Fedora / Arch`)

```bash
git clone https://github.com/gen3space/AEGIS.git
cd aegis
python3 -m venv .venv
source .venv/bin/activate
bash scripts/build_unix.sh
```
Output:
- `dist/aegis-linux-x64` (or `aegis-linux-arm64` on ARM hosts)
- `dist/SHA256SUMS.txt`

### 🍎 Build on macOS (`Apple Silicon M1–M4 / Intel`)

```bash
git clone https://github.com/gen3space/AEGIS.git
cd aegis
python3 -m venv .venv
source .venv/bin/activate
bash scripts/build_unix.sh
```
Output:
- `dist/aegis-macos-arm64` (or `aegis-macos-x64`)
- `dist/SHA256SUMS.txt`

*(If macOS Gatekeeper flags an unsigned local build downloaded from a browser, clear quarantine with `xattr -d com.apple.quarantine ./aegis-macos-arm64`.)*

---

## 4. Run via Docker / Docker Compose

```bash
docker compose -f examples/docker-compose.yml up --build -d
```
Then open **http://127.0.0.1:8765**.

---

## 5. Automated GitHub Actions Multi-OS Releases

Every tag matching `v*` (e.g., `git tag v1.0.0 && git push origin v1.0.0`) triggers [`.github/workflows/release.yml`](../.github/workflows/release.yml), which builds standalone binaries cleanly on official GitHub runners (`ubuntu-latest`, `windows-latest`, `macos-latest`), smoke-tests each executable, computes `SHA256SUMS.txt`, and publishes them to GitHub Releases.
