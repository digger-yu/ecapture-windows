<!-- MarkdownTOC autolink="true" -->

- [Capturing TLS/SSL on Windows with the Schannel module](#capturing-tlsssl-on-windows-with-the-schannel-module)
- [Capability boundary (read this first)](#capability-boundary-read-this-first)
- [Background](#background)
- [Prerequisites](#prerequisites)
- [Step 1: Build or download ecapture.exe](#step-1-build-or-download-ecaptureexe)
- [Step 2: Launch ecapture in Schannel mode](#step-2-launch-ecapture-in-schannel-mode)
  - [Text mode (ETW metadata)](#text-mode-etw-metadata)
  - [Keylog mode (not available via ETW)](#keylog-mode-not-available-via-etw)
  - [Plaintext via SSPI hook DLL](#plaintext-via-sspi-hook-dll)
  - [Pcap mode (requires Npcap)](#pcap-mode-requires-npcap)
- [Step 3: Trigger an HTTPS request with a Schannel-backed client](#step-3-trigger-an-https-request-with-a-schannel-backed-client)
- [Step 4: Read the captured output](#step-4-read-the-captured-output)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Roadmap](#roadmap)

<!-- /MarkdownTOC -->
----

# Capturing TLS/SSL on Windows with the Schannel module

This guide shows how to use eCapture on Windows against processes that use the
built-in Schannel SSP (`schannel.dll` / `secur32.dll`). Capture is based on the
`Microsoft-Windows-Schannel-Events` ETW provider. It does **not** require a CA
certificate.

# Capability boundary (read this first)

| Mode | What you get today |
|------|--------------------|
| `--schannel -m text` | **Handshake / lifecycle metadata** (event name, PID/TID, TargetName when present). **Not** HTTP plaintext. |
| `--schannel -m keylog` | **No secrets from ETW.** eCapture warns at start-up. Keylog needs Phase 3 (LSASS/ncrypt). |
| `--schannel -m text --pid N` + `schannel_hook.dll` | **Plaintext** from `EncryptMessage` / `DecryptMessage` via DLL injection (Phase 2). |
| `-m pcap` | Wire packets via Npcap (encrypted on the wire unless you have keys). |

**Phase 2 (SSPI plaintext) vs Phase 3 (LSASS keylog)** are different mechanisms —
see the comparison table in [`windows-roadmap.md`](./windows-roadmap.md#phase-2-vs-phase-3-comparison).
In short: bodies in eCapture → Phase 2; Wireshark decrypt of a pcap → Phase 3.

# Background

Schannel is the default TLS provider for many Microsoft / .NET / PowerShell
clients. ETW provider:

| Name | GUID |
|------|------|
| `Microsoft-Windows-Schannel-Events` | `{91CC1150-71AA-47E2-AE18-C96E61736B6F}` |

eCapture subscribes to that provider and prints metadata events. Plaintext is
**not** exposed by this provider; use the optional SSPI hook DLL for AppData.

# Prerequisites

| Requirement | Notes |
|-------------|-------|
| Windows 10 1809 (build 17763) or later | Older builds have limited Schannel tracing. |
| Administrator PowerShell | ETW sessions and DLL injection need elevation. |
| `ecapture.exe` | Cross-build with `make windows` / `make windows-arm64`, or `go build`. |
| Schannel client | PowerShell `Invoke-WebRequest`, Windows `curl.exe` (Schannel), .NET `HttpClient`. |
| Optional: `schannel_hook.dll` | Built from `contrib/schannel_hook/` for plaintext. |

> Chromium-based browsers (Edge/Chrome) use **BoringSSL**, not Schannel.
> Firefox uses **NSS**. Those are out of scope for `--schannel`.

# Step 1: Build or download ecapture.exe

```powershell
# On Linux host (recommended)
make windows-arm64   # or: make windows
```

Or on Windows:

```powershell
$env:CGO_ENABLED = "0"
go build -tags windows -o .\bin\ecapture.exe .
```

# Step 2: Launch ecapture in Schannel mode

Open an **elevated** PowerShell.

## Text mode (ETW metadata)

```powershell
PS C:\Tools> .\ecapture.exe tls --schannel -m text
```

| Flag | Meaning |
|------|---------|
| `tls` | Windows TLS subcommand (Schannel ETW + optional hooks). |
| `--schannel` | Enable Schannel ETW (default `true`). |
| `-m text` | Print metadata events (default). |
| `-l save_schannel.log` | Redirect **process logs** only (`--logaddr`). Captured events go to stdout / `--eventaddr`. |

## Keylog mode (not available via ETW)

```powershell
PS C:\Tools> .\ecapture.exe tls --schannel -m keylog -k save_schannel.keylog
```

Expect a start-up warning. The keylog file stays empty until Phase 3 key
extraction lands. Do not treat an empty file as a successful capture.

## Plaintext via SSPI hook DLL

```powershell
# Build DLL (see contrib/schannel_hook/README.md), place next to ecapture.exe
PS C:\Tools> .\ecapture.exe tls --schannel -m text --pid 1234
```

You should see `SSPIAppData` lines with `send` / `recv` plaintext when the
target process uses Schannel SSPI.

## Pcap mode (requires Npcap)

```powershell
PS C:\Tools> .\ecapture.exe tls --schannel -m pcap -i "Ethernet" -w save_schannel.pcapng
```

Packets remain encrypted unless you separately supply TLS keys.

# Step 3: Trigger an HTTPS request with a Schannel-backed client

In a **second** window:

```powershell
Invoke-WebRequest -Uri https://api.github.com -UseBasicParsing
# or
curl.exe -sSL https://api.github.com | Select-Object -First 5
```

Confirm `curl.exe --version` shows `Schannel`.

# Step 4: Read the captured output

### ETW metadata sample

```text
PID:1234 TID:5678 AcquireCredentialHandleStart(257) Proto: Cipher: Target:
PID:1234 TID:5678 DeleteSecurityContext(1793) Proto: Cipher: Target:api.github.com
```

### SSPI plaintext sample (with hook DLL + `--pid`)

```text
PID:1234 TID:5678 SSPIAppData send len=23 data="GET / HTTP/1.1\r\nHost: "
PID:1234 TID:5678 SSPIAppData recv len=45 data="HTTP/1.1 200 OK\r\nServer: GitHub.com"
```

# Troubleshooting

- **"ETW session start failed" / Access denied** — Re-run elevated.
- **Probe started but no events** — Confirm the client uses Schannel; confirm provider GUID `{91CC1150-71AA-47E2-AE18-C96E61736B6F}` via `logman query providers`.
- **Only metadata, no HTTP body** — Expected for ETW-only. Build/inject `schannel_hook.dll` and pass `--pid`.
- **OpenProcess / inject failed** — `--pid` must be a **live** target PID (`$PID` in that window). Dead PIDs return "parameter is incorrect".
- **Target crashes with 0xC0000005 after inject** — Replace `schannel_hook.dll` with a rebuild from current sources. Old trampolines used `mov rax; jmp rax`, which clobbers the `/GS` stack cookie in `EncryptMessage`. See `contrib/schannel_hook/README.md`.
- **Empty keylog** — Expected for Schannel ETW. See roadmap Phase 3.
- **`-l` file has only JSON logs** — That file is `--logaddr`, not the event stream. Watch the console or set `--eventaddr`.

# Limitations

- Schannel ETW does **not** expose master secrets or AppData plaintext.
- OpenSSL / BoringSSL / NSS traffic needs other probes (not yet on Windows).
- SSPI DLL injection cannot target PPL / protected processes.
- pcap mode needs Npcap and does not auto-decrypt without keys.

# Roadmap

See [`windows-roadmap.md`](./windows-roadmap.md) for Phase 1–3, including the
[Phase 2 vs Phase 3 comparison](./windows-roadmap.md#phase-2-vs-phase-3-comparison)
(SSPI plaintext vs LSASS/ncrypt keylog).
