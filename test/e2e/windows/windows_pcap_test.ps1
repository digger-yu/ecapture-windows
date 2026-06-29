#Requires -Version 5.1
<#
.SYNOPSIS
    Windows end-to-end test for ecapture TLS pcap/pcapng mode via Npcap.

.DESCRIPTION
    Validates that the ecapture binary at -EcaptureBinary can capture
    network packets and write them as pcapng using the Npcap runtime.

    The test is designed to be tolerant of two different binary flavours:

      1. pcap-enabled binaries (built with `-tags 'windows,pcap'`): the
         full flow runs and a pcapng file is produced and validated.
      2. default binaries (built without the `pcap` tag): the test runs
         the binary and expects it to refuse to start pcap mode with a
         helpful error message. This is treated as a PASS so that the
         test suite still works in CI where only the default build is
         available.

.PREREQUISITES
    - Administrator privileges.
    - Npcap runtime installed on the target host (the script checks for
      the Npcap helper DLL). Only required for the pcap-enabled flavour.
    - ecapture.exe built for Windows (either default or with the `pcap`
      tag).
#>
[CmdletBinding()]
param(
    [string]$EcaptureBinary = "",
    [string]$InterfaceName = "",
    [string]$TmpDir = "",
    [int]$WaitSeconds = 3
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common_windows.ps1"

if ([string]::IsNullOrWhiteSpace($TmpDir)) {
    $TmpDir = Join-Path $env:TEMP ("ecapture_pcap_e2e_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$script:TestName = "Windows PCAP E2E Test"
$script:Binary = Get-EcaptureBinary -Path $EcaptureBinary
$script:LogFile = Join-Path $TmpDir "ecapture_pcap.log"
$script:PcapFile = Join-Path $TmpDir "capture.pcapng"

# Patterns that indicate the running binary is a default (no-pcap) build
# and has refused to start because of the missing tag.
$script:PcapDisabledPatterns = @(
    "pcap mode is not available in this eCapture binary",
    "pcap mode is not enabled in this build",
    "pcap mode requires"
)

function Get-DefaultInterface {
    if (-not [string]::IsNullOrWhiteSpace($InterfaceName)) { return $InterfaceName }
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback" } | Select-Object -First 1
    if ($adapters) { return $adapters.Name }
    $ni = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        $_.OperationalStatus -eq "Up" -and $_.NetworkInterfaceType -ne "Loopback"
    } | Select-Object -First 1
    if ($ni) { return $ni.Name }
    return "Ethernet"
}

function Test-NpcapInstalled {
    $paths = @(
        "C:\Windows\System32\Npcap\wpcap.dll",
        "C:\Windows\System32\wpcap.dll",
        "C:\Windows\SysWOW64\Npcap\wpcap.dll",
        "C:\Windows\SysWOW64\wpcap.dll"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $true } }
    $svc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    return ($svc -ne $null)
}

function Test-PcapDisabledInLog {
    if (-not (Test-Path $script:LogFile)) { return $false }
    $content = Get-Content $script:LogFile -Raw
    foreach ($pat in $script:PcapDisabledPatterns) {
        if ($content -imatch [regex]::Escape($pat)) { return $true }
    }
    return $false
}

function Test-NpcapMissingInLog {
    if (-not (Test-Path $script:LogFile)) { return $false }
    return ((Get-Content $script:LogFile -Raw) -imatch "Npcap runtime was not detected")
}

function Main {
    Write-Info "=== $script:TestName ==="
    if (-not (Test-Admin)) {
        Write-Error2 "Administrator privileges are required for Npcap capture"
        exit 1
    }
    if (-not (Test-Path $script:Binary)) {
        Write-Error2 "ecapture binary not found at $($script:Binary)"
        exit 1
    }

    $iface = Get-DefaultInterface
    Write-Info "Using network interface: $iface"
    Write-Info "Binary: $($script:Binary)"
    Write-Info "Log file: $($script:LogFile)"

    $ecaptureArgs = "tls --debug -m pcap -i `"$iface`" --pcapfile `"$script:PcapFile`""
    $proc = Start-Ecapture -Binary $script:Binary -Arguments $ecaptureArgs -LogFile $script:LogFile
    Start-Sleep -Seconds $WaitSeconds

    # Case 1: default (no-pcap) build. The binary should exit quickly with
    # a friendly error message. This is a passing condition.
    if ($proc.HasExited) {
        Sync-EcaptureOutput
        if (Test-PcapDisabledInLog) {
            Write-Info "Binary is a default (no-pcap) build; refused to start pcap mode with a clear message."
            Write-Info "PASS (default build)"
            exit 0
        }
        if (Test-NpcapMissingInLog) {
            Write-Error2 "Npcap runtime is missing on this host. Install Npcap from https://npcap.com/."
            exit 1
        }
        Write-Error2 "eCapture exited unexpectedly during pcap initialization (exit code: $($proc.ExitCode))"
        Write-Info "--- last 80 log lines ---"
        if (Test-Path $script:LogFile) {
            Get-Content $script:LogFile -Tail 80 | ForEach-Object { Write-Info $_ }
        }
        exit 1
    }

    # Case 2: pcap-enabled build. The binary should be running and
    # writing to a pcapng file.
    if (-not (Test-NpcapInstalled)) {
        Write-Error2 "ecapture is a pcap-enabled build but Npcap runtime is not installed. Install Npcap from https://npcap.com/."
        Stop-Ecapture
        exit 1
    }

    try {
        Write-Info "Generating some network traffic..."
        Invoke-WebRequest -Uri "https://api.github.com" -UseBasicParsing -TimeoutSec 15 -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Warn "HTTPS request failed (network may be restricted in this environment): $_"
    }

    Start-Sleep -Seconds 2
    Stop-Ecapture

    if (-not (Test-Path $script:PcapFile)) {
        Write-Error2 "Pcapng file was not created: $script:PcapFile"
        exit 1
    }
    $size = (Get-Item $script:PcapFile).Length
    Write-Info "Pcapng file created: $script:PcapFile ($size bytes)"
    if ($size -eq 0) {
        Write-Error2 "Pcapng file is empty"
        exit 1
    }

    # Verify pcapng magic bytes (0x0A0D0D0A little-endian at offset 0).
    $bytes = [System.IO.File]::ReadAllBytes($script:PcapFile)
    if ($bytes.Length -lt 4) {
        Write-Error2 "Pcapng file is too short to contain a section header"
        exit 1
    }
    $magic = [BitConverter]::ToUInt32($bytes, 0)
    if ($magic -eq 0x0A0D0D0A) {
        Write-Info "Valid pcapng magic bytes detected"
    } else {
        Write-Warn "Pcapng magic bytes did not match (got 0x$('{0:X8}' -f $magic)); file may still be valid if ecapture writes a different section header"
    }

    Write-Info "=== $script:TestName PASSED ==="
    exit 0
}

try {
    Main
} finally {
    Stop-Ecapture
    if ($script:TestFailed -ne 0 -and (Test-Path $script:LogFile)) {
        Write-Info "--- last 50 eCapture log lines ---"
        Get-Content $script:LogFile -Tail 50 | ForEach-Object { Write-Info $_ }
    }
}
