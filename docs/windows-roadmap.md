# Windows TLS capture roadmap

This document defines the phased capability boundary for eCapture on Windows.

## Phase 2 vs Phase 3 (comparison)

Item 4 of the Windows plan was phrased as *either* cross-process Schannel
hooking *or* LSASS/ncrypt key extraction. Both paths matter; they solve
different problems.

| | Phase 2: SSPI hook (implemented) | Phase 3: LSASS / ncrypt (planned) |
|--|----------------------------------|-----------------------------------|
| **Goal** | Application **plaintext** (HTTP bodies, etc.) | NSS **keylog** secrets for Wireshark |
| **Where** | Target process (`secur32!EncryptMessage` / `DecryptMessage`) | **LSASS** / `ncrypt` session key material |
| **How** | Inject `schannel_hook.dll`; stream buffers to `\\.\pipe\ecapture-schannel` | Privileged LSASS access or hook `Ssl*` APIs; correlate `ClientRandom` / TLS 1.3 secrets |
| **CLI today** | `tls --schannel -m text --pid <pid>` (+ DLL beside exe) | `-m keylog` accepted but **empty** (start-up warning) |
| **Privilege / risk** | Admin + injectable process; fails on PPL | Higher: PPL, Credential Guard, EDR-sensitive; bad impl can destabilize the host |
| **With Wireshark** | Read plaintext directly in eCapture output | Pair keylog with a pcap (`-m pcap` / external capture) to decrypt on the wire |
| **Status** | In tree (`contrib/schannel_hook`, `InjectDLL`, pipe server) | Documented only; not implemented |

**Rule of thumb**: need to *see* request/response bodies → Phase 2. Need
*offline* decrypt of a packet capture → Phase 3 (when it lands).

## Phase 1 (current): Schannel ETW metadata

**Provider**: `Microsoft-Windows-Schannel-Events`
**GUID**: `{91CC1150-71AA-47E2-AE18-C96E61736B6F}`

| Captures | Does NOT capture |
|----------|------------------|
| Handshake / credential lifecycle events | HTTP/TLS application plaintext |
| TargetName (when present, e.g. on DeleteSecurityContext) | NSS keylog / master secrets |
| Process / thread IDs | Decrypted pcap application data |

Run:

```powershell
ecapture.exe tls --schannel -m text
```

`-m keylog` is accepted for API compatibility but **will not produce secrets**
from ETW alone. eCapture logs an explicit warning at start-up.

## Phase 2 (in tree): SSPI plaintext via companion DLL

**Mechanism**: inject `contrib/schannel_hook/schannel_hook.dll` into a target
process; hook `secur32!EncryptMessage` / `DecryptMessage`; stream plaintext to
`\\.\pipe\ecapture-schannel`.

| Status | Detail |
|--------|--------|
| Pipe server in eCapture | Implemented (`pkg/util/hook/sspi_pipe_windows.go`) |
| `InjectDLL(pid, path)` | Implemented (`pkg/util/hook/inject_windows.go`) |
| Companion DLL source | `contrib/schannel_hook/schannel_hook.c` |
| Same-process trampoline API | Enabled (`Hook.Install`) for tests / future use |

Usage once the DLL is built and placed beside `ecapture.exe`:

```powershell
ecapture.exe tls --schannel -m text --pid <target_pid>
```

## Phase 3 (planned): LSASS / ncrypt key extraction + pcap decrypt

Schannel keeps TLS secrets in LSASS / `ncrypt`. Exporting them for Wireshark
NSS keylog requires:

1. Privileged access to LSASS (or a supported Microsoft key-export API if one
   appears in a future Windows release).
2. Correlating `ClientRandom` (or TLS 1.3 traffic secrets) with sessions.
3. Writing NSS keylog lines and optionally decrypting a Npcap capture.

This path is intentionally separate from ETW metadata and from SSPI plaintext
hooks. Tracking issue: keep this file updated as the implementation lands.

## Explicit non-goals for Schannel ETW

- Do **not** claim ETW emits `AppData` HTTP bodies.
- Do **not** claim Edge/Chrome use Schannel (Chromium uses BoringSSL).
- Do **not** treat “probe started” as a successful capture in E2E tests.
