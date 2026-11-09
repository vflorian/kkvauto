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

# Natív parancs futtatása úgy, hogy a stderr / hibakód ne dobjon kivételt (PowerShell 5.1 + Stop miatt).
function Invoke-Quiet([string]$Exe, [string[]]$ArgList) {
  $old = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $out = & $Exe @ArgList 2>$null
    return @{ ok = ($LASTEXITCODE -eq 0); out = $out }
  } catch {
    return @{ ok = $false; out = $null }
  } finally {
    $ErrorActionPreference = $old
  }
}
$verCode = "import sys; print('%d.%d' % sys.version_info[:2])"

# 1) Python 3.10+ keresése (py launcher, majd python) – csak ténylegesen futó interpretert fogad el
$py = $null
$candidates = @(@{ exe = "py"; pre = @("-3") }, @{ exe = "python"; pre = @() })
foreach ($c in $candidates) {
  if (Get-Command $c.exe -ErrorAction SilentlyContinue) {
    $r = Invoke-Quiet $c.exe ($c.pre + @("-c", $verCode))
    $ver = "$($r.out)".Trim()
    if ($r.ok -and $ver -match '^\d+\.\d+$' -and [version]$ver -ge [version]"3.10") { $py = $c; break }
  }
}
if (-not $py) {
  Write-Host "HIBA: nem található működő Python 3.10+. Telepítés: winget install Python.Python.3.12 (vagy https://www.python.org/downloads/windows/)." -ForegroundColor Red
  Write-Host "Ellenőrzés: py -0p  (a telepített Pythonok listája)"
  exit 1
}
$pyExe = (Invoke-Quiet $py.exe ($py.pre + @("-c", "import sys; print(sys.executable)"))).out
Write-Host "Python: $pyExe"

# 2) Virtuális környezet: ha hiányzik vagy elromlott (pl. az alap-Python közben eltűnt/frissült), újraépítjük
$vpy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$venvOk = (Test-Path $vpy) -and (Invoke-Quiet $vpy @("-c", "import sys")).ok
if (-not $venvOk) {
  if (Test-Path ".venv") {
    if (-not (Test-Path ".venv\pyvenv.cfg")) {
      Write-Host "HIBA: a .venv mappa nem virtuális környezet; nevezd át vagy töröld kézzel." -ForegroundColor Red
      exit 1
    }
    $cfgHome = (Select-String -Path ".venv\pyvenv.cfg" -Pattern '^home\s*=\s*(.*)$' | Select-Object -First 1).Matches.Groups[1].Value
    Write-Host "A meglévő .venv nem működik (alap-Python: $cfgHome). Újralétrehozás..." -ForegroundColor Yellow
    Remove-Item -LiteralPath (Join-Path $PSScriptRoot ".venv") -Recurse -Force
  } else {
    Write-Host "Virtuális környezet létrehozása (.venv)..."
  }
  $r = Invoke-Quiet $py.exe ($py.pre + @("-m", "venv", ".venv"))
  if (-not $r.ok -or -not (Invoke-Quiet $vpy @("-c", "import sys")).ok) {
    Write-Host "HIBA: a virtuális környezet létrehozása sikertelen ($pyExe -m venv .venv)." -ForegroundColor Red
    exit 1
  }
}
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
