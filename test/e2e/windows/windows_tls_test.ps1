#Requires -Version 5.1
<#
.SYNOPSIS
    Windows end-to-end test for the ecapture TLS/Schannel module.

.PREREQUISITES
    - Administrator privileges (ETW sessions require elevation).
    - ecapture.exe built for Windows.
    - Network connectivity to an HTTPS endpoint (https://api.github.com is used
      by default; override with -TestUrl).

.NOTES
    Phase-1 Schannel ETW captures handshake/lifecycle metadata, not HTTP bodies.
    This test requires real Schannel event lines after the HTTPS request.
    Initialization-only success is NOT accepted.
#>
[CmdletBinding()]
param(
    [string]$EcaptureBinary = "",
    [string]$TestUrl = "https://api.github.com",
    [string]$TmpDir = ""
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common_windows.ps1"

if ([string]::IsNullOrWhiteSpace($TmpDir)) {
    $TmpDir = Join-Path $env:TEMP ("ecapture_tls_e2e_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$script:TestName = "Windows TLS E2E Test"
$script:Binary = Get-EcaptureBinary -Path $EcaptureBinary
$script:LogFile = Join-Path $TmpDir "ecapture_tls.log"

function Test-TextMode {
    Write-Info "=== Testing Schannel text mode (metadata capture required) ==="
    $proc = Start-Ecapture -Binary $script:Binary -Arguments "tls --schannel --debug -m text" -LogFile $script:LogFile
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        Sync-EcaptureOutput
        Write-Error2 "eCapture exited during initialization (exit code: $($proc.ExitCode))"
        if (Test-Path $script:LogFile) {
            Write-Info "--- eCapture output (text mode) ---"
            Get-Content $script:LogFile | ForEach-Object { Write-Info $_ }
            Write-Info "--- end of output ---"
        }
        return $false
    }

    try {
        Write-Info "Making HTTPS request to $TestUrl"
        Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Warn "HTTPS request failed: $_"
    }

    Start-Sleep -Seconds 3
    Stop-Ecapture
    Start-Sleep -Seconds 1
    Sync-EcaptureOutput

    if (-not (Test-Path $script:LogFile)) {
        Write-Error2 "eCapture log was not created"
        return $false
    }

    Write-Info "Log size: $((Get-Item $script:LogFile).Length) bytes"

    # Require evidence of real Schannel ETW (or SSPI) events — not just start-up logs.
    $capturePatterns = @(
        "DeleteSecurityContext",
        "AcquireCredentialHandle",
        "AcceptSecurityContext",
        "FreeCredentialHandle",
        "SSPIAppData",
        "Target:.*github",
        "Target:api\.github\.com",
        "Microsoft-Windows-Schannel-Events"
    )
    if (Test-OutputContains -LogFile $script:LogFile -Patterns $capturePatterns -Description "Schannel capture evidence") {
        Write-Info "Text mode test PASSED (captured Schannel events)"
        return $true
    }

    Write-Error2 "Text mode test FAILED: no Schannel capture evidence after HTTPS request"
    Write-Info "--- eCapture output (text mode) ---"
    Get-Content $script:LogFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Info $_ }
    Write-Info "--- end of output ---"
    return $false
}

function Test-KeylogMode {
    Write-Info "=== Testing keylog mode (must warn that ETW cannot export secrets) ==="
    $keylogFile = Join-Path $TmpDir "tls_keys.log"
    $logFile = Join-Path $TmpDir "ecapture_keylog.log"
    $proc = Start-Ecapture -Binary $script:Binary -Arguments "tls --schannel --debug -m keylog -k `"$keylogFile`"" -LogFile $logFile
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        Sync-EcaptureOutput
        Write-Error2 "eCapture exited during keylog initialization (exit code: $($proc.ExitCode))"
        if (Test-Path $logFile) {
            Write-Info "--- eCapture output (keylog mode) ---"
            Get-Content $logFile | ForEach-Object { Write-Info $_ }
            Write-Info "--- end of output ---"
        }
        return $false
    }

    try {
        Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Warn "HTTPS request failed: $_"
    }

    Start-Sleep -Seconds 2
    Stop-Ecapture
    Sync-EcaptureOutput

    # Phase 1: must clearly warn that keylog is unavailable via Schannel ETW.
    $warnPatterns = @(
        "cannot export TLS secrets",
        "keylog will stay empty",
        "awaiting SSPI/LSASS"
    )
    if (-not (Test-OutputContains -LogFile $logFile -Patterns $warnPatterns -Description "keylog limitation warning")) {
        Write-Error2 "Keylog mode test FAILED: missing explicit Schannel keylog limitation warning"
        return $false
    }

    # Must NOT claim success just because the handler was registered.
    if ((Test-Path $keylogFile) -and (Get-Item $keylogFile).Length -gt 0) {
        if (Test-OutputContains -LogFile $keylogFile -Patterns @("CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET") -Description "unexpected keylog secrets") {
            Write-Info "Keylog file unexpectedly contains secrets (Phase 3 may have landed) — treating as PASS"
            return $true
        }
    }

    Write-Info "Keylog mode test PASSED (documented ETW limitation; no false CLIENT_RANDOM success)"
    return $true
}

function Main {
    Write-Info "=== $script:TestName ==="
    if (-not (Test-Admin)) {
        Write-Error2 "Administrator privileges are required for ETW-based TLS capture"
        exit 1
    }
    if (-not (Test-Path $script:Binary)) {
        Write-Error2 "ecapture binary not found at $($script:Binary)"
        exit 1
    }
    Write-Info "Using ecapture binary: $($script:Binary)"

    $results = @()
    $results += Test-TextMode
    $results += Test-KeylogMode

    Write-Info "=== Test Summary ==="
    $passed = ($results | Where-Object { $_ -eq $true }).Count
    $failed = ($results | Where-Object { $_ -eq $false }).Count
    Write-Info "Passed: $passed / $($results.Count)"

    if ($failed -eq 0) {
        Write-Info "=== $script:TestName PASSED ==="
        exit 0
    } else {
        Write-Error2 "=== $script:TestName FAILED ==="
        exit 1
    }
}

try {
    Main
} finally {
    Stop-Ecapture
    if ($script:TestFailed -ne 0 -and (Test-Path $script:LogFile)) {
        Write-Info "--- eCapture final log (tail) ---"
        Get-Content $script:LogFile -Tail 80 | ForEach-Object { Write-Info $_ }
    }
}
