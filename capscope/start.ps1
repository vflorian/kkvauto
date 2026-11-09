<#
.SYNOPSIS
  CapScope indítása Windows 11-en (PowerShell 5.1 vagy 7).
.EXAMPLE
  .\start.ps1
  .\start.ps1 -Port 8770 -Data D:\capscope-data
  .\start.ps1 -Check
  .\start.ps1 -TShark "D:\Wireshark\tshark.exe"
#>
param(
  [int]$Port = 8765,
  [string]$Data = "",
  [string]$TShark = "",
  [switch]$NoBrowser,
  [switch]$Check
)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# 1) Python 3.10+ keresése (py launcher, majd python)
$py = $null
$candidates = @(@{ exe = "py"; pre = @("-3") }, @{ exe = "python"; pre = @() })
foreach ($c in $candidates) {
  if (Get-Command $c.exe -ErrorAction SilentlyContinue) {
    $pre = $c.pre
    $ver = & $c.exe @pre -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    if ($ver -and [version]$ver -ge [version]"3.10") { $py = $c; break }
  }
}
if (-not $py) {
  Write-Host "HIBA: Python 3.10+ szükséges. Telepítés: https://www.python.org/downloads/windows/ (vagy: winget install Python.Python.3.12)" -ForegroundColor Red
  exit 1
}

# 2) Virtuális környezet + függőségek (csak első indításkor / requirements változásakor tölt le)
if (-not (Test-Path ".venv\Scripts\python.exe")) {
  Write-Host "Virtuális környezet létrehozása (.venv)..."
  $pre = $py.pre
  & $py.exe @pre -m venv .venv
}
$vpy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$stamp = ".venv\.requirements.sha256"
$hash = (Get-FileHash requirements.txt -Algorithm SHA256).Hash
if (-not (Test-Path $stamp) -or (Get-Content $stamp) -ne $hash) {
  Write-Host "Függőségek telepítése (fastapi, uvicorn)..."
  & $vpy -m pip install --disable-pip-version-check -q -r requirements.txt
  if ($LASTEXITCODE -ne 0) { Write-Host "HIBA: pip install sikertelen." -ForegroundColor Red; exit 1 }
  Set-Content -Path $stamp -Value $hash
}

# 3) TShark: paraméter > CAPSCOPE_TSHARK > PATH > Program Files (a program maga is keresi)
if ($TShark) { $env:CAPSCOPE_TSHARK = $TShark }
elseif (-not $env:CAPSCOPE_TSHARK -and -not (Get-Command tshark -ErrorAction SilentlyContinue)) {
  $default = Join-Path $env:ProgramFiles "Wireshark\tshark.exe"
  if (Test-Path $default) { $env:CAPSCOPE_TSHARK = $default }
  else {
    Write-Host "HIBA: TShark nem található. Telepítsd a Wiresharkot (TShark komponenssel), vagy add meg: .\start.ps1 -TShark 'C:\...\tshark.exe'" -ForegroundColor Red
    exit 2
  }
}

# 4) Indítás (csak 127.0.0.1-en figyel)
$argsList = @("-m", "capscope", "--port", "$Port")
if ($Data) { $argsList += @("--data", $Data) }
if ($NoBrowser) { $argsList += "--no-browser" }
if ($Check) { $argsList += "--check" }
& $vpy @argsList
exit $LASTEXITCODE
