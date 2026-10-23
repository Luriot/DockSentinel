#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$DataDir = '',
    [switch]$NoShortcut,
    [switch]$NoStart,
    [switch]$UseSystemNode
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$NodeVersion = '24.12.0'
$NodeZipName = "node-v$NodeVersion-win-x64.zip"
$NodeBaseUrl = "https://nodejs.org/dist/v$NodeVersion"
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    $DataDir = Join-Path $env:LOCALAPPDATA 'DockSentinel'
}
$DataDir = [IO.Path]::GetFullPath($DataDir)
$RuntimeDir = Join-Path $DataDir 'runtime'
$NodeDir = Join-Path $RuntimeDir "node-v$NodeVersion-win-x64"
$NodeExe = Join-Path $NodeDir 'node.exe'
$NpmCmd = Join-Path $NodeDir 'npm.cmd'
$Launcher = Join-Path $DataDir 'Start DockSentinel.cmd'

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-NodeRuntime([string]$Exe) {
    if (-not (Test-Path $Exe)) { return $false }
    try {
        $raw = (& $Exe --version 2>$null | Select-Object -First 1).Trim()
    } catch {
        return $false
    }
    if ($raw -notmatch '^v(\d+)\.(\d+)\.(\d+)') { return $false }
    $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
    return ($major -gt 24) -or ($major -eq 24 -and ($minor -gt 12 -or ($minor -eq 12 -and $patch -ge 0)))
}

function Install-PortableNode {
    if (Test-NodeRuntime $NodeExe) {
        Write-Host "Using existing portable Node.js at $NodeExe"
        return
    }
    Write-Step "Installing a private Node.js $NodeVersion runtime (no system Node.js required)"
    New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
    $zipPath = Join-Path $RuntimeDir $NodeZipName
    $checksumPath = Join-Path $RuntimeDir 'SHASUMS256.txt'
    Invoke-WebRequest -Uri "$NodeBaseUrl/$NodeZipName" -OutFile $zipPath -UseBasicParsing
    Invoke-WebRequest -Uri "$NodeBaseUrl/SHASUMS256.txt" -OutFile $checksumPath -UseBasicParsing
    $line = Get-Content $checksumPath | Where-Object { $_ -match "\s$([Regex]::Escape($NodeZipName))$" } | Select-Object -First 1
    if (-not $line) { throw "The official Node.js checksum file did not contain $NodeZipName." }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Remove-Item -Force $zipPath, $checksumPath -ErrorAction SilentlyContinue
        throw "Node.js checksum verification failed. Nothing was installed."
    }
    if (Test-Path $NodeDir) { Remove-Item -Recurse -Force $NodeDir }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $RuntimeDir -Force
    Remove-Item -Force $zipPath, $checksumPath -ErrorAction SilentlyContinue
    if (-not (Test-NodeRuntime $NodeExe)) { throw "The Node.js runtime did not install correctly." }
    Write-Host "Verified Node.js runtime: $(& $NodeExe --version)"
}

try {
    Write-Host ""
    Write-Host "  DockSentinel installer" -ForegroundColor Green
    Write-Host "  Docker image vulnerability monitoring for normal people." -ForegroundColor DarkGray
    Write-Host ""

    if (-not (Test-Path (Join-Path $ProjectRoot 'package.json'))) {
        throw "This installer must stay inside the DockSentinel folder (package.json was not found)."
    }

    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

    if ($UseSystemNode) {
        $systemNode = (Get-Command node.exe -ErrorAction SilentlyContinue)
        if (-not $systemNode -or -not (Test-NodeRuntime $systemNode.Source)) {
            throw "No supported Node.js was found. Run the installer without -UseSystemNode to install a private runtime."
        }
        $NodeExe = $systemNode.Source
        $NpmCmd = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
        if (-not $NpmCmd) { throw "npm.cmd was not found next to the system Node.js." }
    } else {
        Install-PortableNode
    }

    $env:PATH = "$(Split-Path -Parent $NodeExe);$env:PATH"
    $env:DATA_DIR = $DataDir

    Write-Step "Installing application dependencies"
    Push-Location $ProjectRoot
    try {
        & $NpmCmd ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed with exit code $LASTEXITCODE." }

        Write-Step "Building the interface and installing verified Trivy"
        & $NpmCmd run native:setup
        if ($LASTEXITCODE -ne 0) { throw "DockSentinel setup failed with exit code $LASTEXITCODE." }
    } finally {
        Pop-Location
    }

    Write-Step "Creating the DockSentinel launcher"
    $launcherText = @"
@echo off
setlocal
set "DATA_DIR=$DataDir"
cd /d "$ProjectRoot"
"$NodeExe" "scripts\native.ts" --open
if errorlevel 1 pause
"@
    Set-Content -LiteralPath $Launcher -Value $launcherText -Encoding ASCII

    if (-not $NoShortcut) {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $desktop = [Environment]::GetFolderPath('Desktop')
            $startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'DockSentinel'
            New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
            foreach ($shortcutPath in @((Join-Path $desktop 'DockSentinel.lnk'), (Join-Path $startMenu 'DockSentinel.lnk'))) {
                $shortcut = $shell.CreateShortcut($shortcutPath)
                $shortcut.TargetPath = $Launcher
                $shortcut.WorkingDirectory = $ProjectRoot
                $shortcut.IconLocation = "$NodeExe,0"
                $shortcut.Description = 'DockSentinel - Docker vulnerability monitoring'
                $shortcut.Save()
            }
            Write-Host "Desktop and Start Menu shortcuts created."
        } catch {
            Write-Warning "Shortcuts could not be created: $($_.Exception.Message)"
        }
    }

    Write-Host ""
    Write-Host "DockSentinel is installed." -ForegroundColor Green
    Write-Host "Data folder: $DataDir"
    Write-Host "Start it from the DockSentinel shortcut, or run:"
    Write-Host "  $Launcher"
    Write-Host ""
    if (-not $NoStart) {
        Write-Step "Starting DockSentinel"
        Start-Process -FilePath $Launcher
        Write-Host "The browser will open when the server is ready. The first-run setup code is shown in the DockSentinel window."
    } else {
        Write-Host "Start it with the shortcut when you are ready."
    }
    exit 0
} catch {
    Write-Host ""
    Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "If the download was blocked, check your internet/proxy and run the installer again." -ForegroundColor Yellow
    exit 1
}
