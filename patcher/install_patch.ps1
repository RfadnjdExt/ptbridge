# install_patch.ps1 - Packet Tracer 9.0.1 installer wrapper: silent Cisco setup (optional) + unified binary patch (login skip + canvas rev4).
# Usage:
#   .\install_patch.ps1                          # patch existing 9.0.1 install (auto-locate)
#   .\install_patch.ps1 -SetupPath PT901.exe     # silent-install Cisco setup first, then patch
#   .\install_patch.ps1 -ExePath "D:\...\PacketTracer.exe"   # explicit target
# Self-elevates (Program Files write needs admin). Requires pt-patch.exe (std-only Rust patcher) next to this script or in ..\target\release.
param(
    [string]$SetupPath,
    [string]$ExePath
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Find-PtPatch {
    $cands = @(
        (Join-Path $here "pt-patch.exe"),
        (Join-Path $here "..\target\release\pt-patch.exe")
    )
    foreach ($c in $cands) { if (Test-Path $c) { return (Resolve-Path $c).Path } }
    throw "pt-patch.exe tidak ditemukan. cargo build --release -p pt-patch, lalu copy ke folder ini."
}

function Find-PTExe {
    if ($ExePath) { return $ExePath }
    $candidates = @(
        (Join-Path $env:ProgramFiles "Cisco Packet Tracer 9.0.1\bin\PacketTracer.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Cisco Packet Tracer 9.0.1\bin\PacketTracer.exe")
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    $found = Get-ChildItem -Path $env:ProgramFiles -Directory -Filter "Cisco Packet Tracer*" -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName "bin\PacketTracer.exe" } |
        Where-Object { Test-Path $_ } | Sort-Object -Descending | Select-Object -First 1
    if ($found) { return $found }
    throw "PacketTracer.exe 9.0.1 tidak ditemukan. Pakai -ExePath atau instal dulu (-SetupPath)."
}

# self-elevate
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($SetupPath)  { $argList += @("-SetupPath", "`"$SetupPath`"") }
    if ($ExePath)    { $argList += @("-ExePath",   "`"$ExePath`"") }
    Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    exit $LASTEXITCODE
}

if ($SetupPath) {
    if (-not (Test-Path $SetupPath)) { throw "installer tidak ada: $SetupPath" }
    Write-Host "[setup] silent install: $SetupPath"
    $p = Start-Process -FilePath $SetupPath -ArgumentList "/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART","/SP-" -Wait -PassThru
    Write-Host "[setup] exit=$($p.ExitCode)"
    if ($p.ExitCode -ne 0) { throw "installer exit $($p.ExitCode)" }
    Start-Sleep -Seconds 3
}

$exe = Find-PTExe
$patcher = Find-PtPatch
Write-Host "[target] $exe"
Write-Host "[patch] $patcher --exe $exe"
& $patcher --exe $exe
if ($LASTEXITCODE -ne 0) { throw "patcher gagal (exit $LASTEXITCODE)" }
Write-Host "[done] login-skip + canvas-rev4 aktif di $exe"
