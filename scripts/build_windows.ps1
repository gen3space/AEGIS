# ==============================================================================
# Build Standalone Windows Executable (`dist/aegis-windows-x64.exe`)
# Usage: powershell -ExecutionPolicy Bypass -File scripts/build_windows.ps1
# ==============================================================================
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host "[Aegis] Installing build requirements..." -ForegroundColor Cyan
python -m pip install -e . pyinstaller --quiet

Write-Host "[Aegis] Building standalone Windows executable via PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller scripts/aegis.spec --clean --noconfirm

$exe = Get-ChildItem -Path "dist" -Filter "aegis-windows-*.exe" | Select-Object -First 1
if (-not $exe) {
    throw "Expected standalone binary was not found in dist/"
}

$hash = (Get-FileHash -Path $exe.FullName -Algorithm SHA256).Hash.ToLower()
"$hash  $($exe.Name)" | Out-File -FilePath "dist/SHA256SUMS-windows.txt" -Encoding ascii

Write-Host "[Aegis] Build complete!" -ForegroundColor Green
Write-Host "  Binary : $($exe.FullName) ($([math]::Round($exe.Length / 1MB, 2)) MB)"
Write-Host "  SHA256 : $hash"
