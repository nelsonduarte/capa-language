# Capa one-line installer for Windows (PowerShell).
#
# Downloads the latest pre-built capa.exe, drops it into
# %LOCALAPPDATA%\capa\capa.exe, and adds that directory to the
# *user* PATH (no admin rights required). The binary bundles
# Python and the Capa runtime via PyInstaller; no Python install
# is required.
#
# Usage:
#   irm https://raw.githubusercontent.com/nelsonduarte/capa/main/deploy/install.ps1 | iex
#   $env:CAPA_INSTALL_DIR = "C:\Tools\capa"; irm https://raw.githubusercontent.com/nelsonduarte/capa/main/deploy/install.ps1 | iex
#
# Or run it as a regular script after cloning the repo:
#   powershell -ExecutionPolicy Bypass -File deploy\install.ps1
#
# The installer is idempotent: re-running it overwrites the
# existing capa.exe with the latest release.

$ErrorActionPreference = "Stop"

$Repo = "nelsonduarte/capa"
$InstallDir = if ($env:CAPA_INSTALL_DIR) { $env:CAPA_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "capa" }
$Asset = "capa-windows-x86_64.exe"
$Url = "https://github.com/$Repo/releases/latest/download/$Asset"
$Dest = Join-Path $InstallDir "capa.exe"

Write-Host "capa-install: target  $Dest"
Write-Host "capa-install: source  $Url"

# Ensure the install directory exists.
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Download. Disable the progress bar (Invoke-WebRequest is much
# slower on Windows PowerShell with progress on).
$prev = $ProgressPreference
$ProgressPreference = "SilentlyContinue"
try {
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
} finally {
    $ProgressPreference = $prev
}

# Verify.
try {
    $version = & $Dest --version 2>&1
    Write-Host "capa-install: installed $version"
} catch {
    Write-Warning "capa-install: the binary did not respond to --version"
}

# Add to user PATH if not already there.
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $UserPath) { $UserPath = "" }
$Already = $UserPath.Split(";") | Where-Object { $_ -eq $InstallDir }
if ($Already) {
    Write-Host "capa-install: $InstallDir is already on your user PATH"
} else {
    $NewPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "capa-install: added $InstallDir to your user PATH"
    Write-Host "capa-install: open a new terminal for the PATH update to take effect"
}

# Update the current process PATH too so the caller can use
# 'capa' immediately without reopening their shell.
if (-not ($env:Path.Split(";") -contains $InstallDir)) {
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host ""
Write-Host "capa-install: done. Try:"
Write-Host "    capa init my-project"
Write-Host "    cd my-project"
Write-Host "    capa --run main.capa"
