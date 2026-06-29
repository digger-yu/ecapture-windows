# Common helpers for Windows e2e tests.
# This file is intended to be dot-sourced by the individual test scripts.

$script:TestFailed = 0
$script:EcaptureProcess = $null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] [$Level] $Message"
}

function Write-Info  { param([string]$Message) Write-Log -Message $Message -Level "INFO" }
function Write-Warn  { param([string]$Message) Write-Log -Message $Message -Level "WARN" }
function Write-Error2 { param([string]$Message) Write-Log -Message $Message -Level "ERROR"; $script:TestFailed = 1 }

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-EcaptureBinary {
    param([string]$Path)
    if ($Path -and (Test-Path $Path)) { return $Path }
    $candidates = @(
        "$PSScriptRoot\..\..\..\bin\ecapture.exe",
        "$PSScriptRoot\..\..\bin\ecapture.exe",
        "$PSScriptRoot\..\ecapture.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    return "ecapture.exe"
}

function Start-Ecapture {
    param(
        [Parameter(Mandatory)] [string]$Binary,
        [Parameter(Mandatory)] [string]$Arguments,
        [Parameter(Mandatory)] [string]$LogFile
    )
    $dir = Split-Path -Parent $LogFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Binary
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    # CREATE_NEW_PROCESS_GROUP = 0x00000200. Placing eCapture in its own
    # process group lets us send CTRL+BREAK_EVENT to it without also
    # signaling the test runner that shares the same console.
    # CreateNewProcessGroup is a CLR property introduced in .NET Core 3.0
    # (it is NOT available on .NET Framework / Windows PowerShell 5.1).
    # We test for it via reflection so the script works on either runtime.
    $newPg = $psi.GetType().GetProperty("CreateNewProcessGroup")
    if ($newPg -and $newPg.CanWrite) {
        [void]$newPg.SetValue($psi, $true)
    } else {
        Write-Warn "CreateNewProcessGroup not available; CTRL+BREAK may also signal the test runner."
    }
    $proc = [System.Diagnostics.Process]::Start($psi)
    $script:EcaptureProcess = $proc
    $script:EcaptureOutTask = $proc.StandardOutput.ReadToEndAsync()
    $script:EcaptureErrTask = $proc.StandardError.ReadToEndAsync()
    $script:EcaptureLogFile = $LogFile
    return $proc
}

# Flush captured stdout/stderr to the log file. Safe to call multiple times.
function Sync-EcaptureOutput {
    $logFile = $script:EcaptureLogFile
    if (-not $logFile) { return }
    try {
        $o = ""
        $e = ""
        if ($script:EcaptureOutTask -and $script:EcaptureOutTask.IsCompleted) {
            $o = $script:EcaptureOutTask.Result
        }
        if ($script:EcaptureErrTask -and $script:EcaptureErrTask.IsCompleted) {
            $e = $script:EcaptureErrTask.Result
        }
        if ($o -or $e) {
            "$o`n$e" | Out-File -FilePath $logFile -Encoding utf8 -Force
        }
    } catch {
        Write-Warn "Sync-EcaptureOutput failed: $_"
    }
}

# Send CTRL+BREAK_EVENT to a console process. CTRL+BREAK is the Windows
# equivalent of SIGINT for console applications, and eCapture's signal
# handler (os.Interrupt / syscall.SIGTERM) responds to it for graceful
# shutdown. CloseMainWindow() does not work for console apps.
if (-not $script:EcaptureCtrlBreak) {
    $signature = @"
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool AttachConsole(uint dwProcessId);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FreeConsole();
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetConsoleCtrlHandler(Delegate handlerRoutine, bool add);
"@
    try {
        $native = Add-Type -MemberDefinition $signature -Name "EcaptureWin32" -Namespace "Ecapture" -PassThru -ErrorAction Stop
        $script:EcaptureCtrlBreak = $native
    } catch {
        Write-Warn "Failed to register native console APIs: $_"
    }
}

function Stop-Ecapture {
    param([int]$TimeoutSec = 5)
    $proc = $script:EcaptureProcess
    if (-not $proc -or $proc.HasExited) {
        Sync-EcaptureOutput
        return
    }
    Write-Info "Stopping eCapture (PID $($proc.Id))..."

    # Try to send CTRL+BREAK_EVENT first for graceful shutdown.
    # eCapture registers signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
    # so a CTRL+BREAK will trigger its clean Stop() path.
    $stoppedGracefully = $false
    if ($script:EcaptureCtrlBreak) {
        try {
            # CTRL_BREAK_EVENT = 1
            $sent = $script:EcaptureCtrlBreak::GenerateConsoleCtrlEvent(1, [uint32]$proc.Id)
            if ($sent) {
                $stoppedGracefully = $proc.WaitForExit($TimeoutSec * 1000)
            }
        } catch {
            Write-Warn "GenerateConsoleCtrlEvent failed: $_"
        }
    }
    if (-not $stoppedGracefully) {
        Write-Warn "eCapture did not exit gracefully; killing process."
        $proc.Kill()
        $proc.WaitForExit(2000) | Out-Null
    }
    Sync-EcaptureOutput
    $script:EcaptureProcess = $null
}

function Test-OutputContains {
    param(
        [string]$LogFile,
        [string[]]$Patterns,
        [string]$Description
    )
    if (-not (Test-Path $LogFile)) { return $false }
    $content = Get-Content $LogFile -Raw
    foreach ($pat in $Patterns) {
        if ($content -imatch $pat) {
            Write-Info "$Description`: matched pattern '$pat'"
            return $true
        }
    }
    Write-Warn "$Description`: no pattern matched in $LogFile"
    return $false
}
