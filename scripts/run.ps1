param(
    [ValidateSet("setup", "api", "detector", "frontend", "all", "test-rules", "health")]
    [string]$Action = "all",
    [switch]$DebugHttp
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendRoot = Join-Path $RepoRoot "backend"
$FrontendRoot = Join-Path $RepoRoot "frontend\threat-analytics-ui"

function Get-PythonExe {
    $candidates = @(
        (Join-Path $RepoRoot ".venv\Scripts\python.exe"),
        (Join-Path $BackendRoot ".venv\Scripts\python.exe"),
        (Join-Path $BackendRoot "venv\Scripts\python.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return $python.Source
    }

    throw "Python executable not found. Create a virtual environment first."
}

function Get-NpmCmd {
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($npm) {
        return $npm.Source
    }

    $fallback = "C:\Program Files\nodejs\npm.cmd"
    if (Test-Path $fallback) {
        return $fallback
    }

    throw "npm.cmd not found. Install Node.js or add it to PATH."
}

function Start-PowerShellWindow {
    param(
        [string]$Title,
        [string]$WorkingDirectory,
        [string]$Command
    )

    $script = @"
Set-Location '$WorkingDirectory'
`$Host.UI.RawUI.WindowTitle = '$Title'
$Command
"@

    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-ExecutionPolicy", "Bypass",
        "-Command", $script
    ) | Out-Null
}

function Invoke-Setup {
    $pythonExe = Get-PythonExe
    $npmCmd = Get-NpmCmd

    Write-Host "Installing backend dependencies..."
    & $pythonExe -m pip install -r (Join-Path $BackendRoot "requirements.txt")

    Write-Host "Installing frontend dependencies..."
    & $npmCmd install
}

function Invoke-Api {
    $pythonExe = Get-PythonExe
    Set-Location $BackendRoot
    & $pythonExe (Join-Path $BackendRoot "api\server.py")
}

function Invoke-Detector {
    $pythonExe = Get-PythonExe
    Set-Location $BackendRoot

    if ($DebugHttp) {
        $env:DEBUG_HTTP_PAYLOADS = "1"
        Write-Host "DEBUG_HTTP_PAYLOADS enabled."
    }

    & $pythonExe (Join-Path $BackendRoot "detectors\detector.py")
}

function Invoke-Frontend {
    $npmCmd = Get-NpmCmd
    Set-Location $FrontendRoot
    & $npmCmd start
}

function Invoke-All {
    $debugFlag = if ($DebugHttp) { " -DebugHttp" } else { "" }

    Start-PowerShellWindow -Title "Threat API" -WorkingDirectory $BackendRoot -Command "& '$PSScriptRoot\run.ps1' api"
    Start-PowerShellWindow -Title "Threat Detector" -WorkingDirectory $BackendRoot -Command "& '$PSScriptRoot\run.ps1' detector$debugFlag"
    Start-PowerShellWindow -Title "Threat Frontend" -WorkingDirectory $FrontendRoot -Command "& '$PSScriptRoot\run.ps1' frontend"
}

function Invoke-TestRules {
    $pythonExe = Get-PythonExe
    Set-Location $RepoRoot
    & $pythonExe (Join-Path $BackendRoot "detectors\test_rules.py")
}

function Invoke-Health {
    try {
        Invoke-RestMethod "http://localhost:5000/api/health" | ConvertTo-Json -Depth 5
    } catch {
        Write-Error "Health check failed. Make sure the backend API is running."
    }
}

switch ($Action) {
    "setup" { Invoke-Setup }
    "api" { Invoke-Api }
    "detector" { Invoke-Detector }
    "frontend" { Invoke-Frontend }
    "all" { Invoke-All }
    "test-rules" { Invoke-TestRules }
    "health" { Invoke-Health }
}
