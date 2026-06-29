# schannel_hook.dll

Companion DLL for eCapture Windows **SSPI plaintext** capture (Plan B).

## What it does

When injected into a target process (PowerShell, a .NET app, `curl.exe` using
Schannel, etc.), the DLL inline-hooks `secur32!EncryptMessage` /
`DecryptMessage`, copies `SECBUFFER_DATA` plaintext, and streams framed
messages over **localhost TCP**. eCapture publishes the port in
`%TEMP%\ecapture_schannel_port.txt`.

(Older builds used a named pipe `\\.\pipe\ecapture-schannel`; that path was
unreliable across integrity levels / `CreateNamedPipe` flag quirks and has
been replaced.)

## Build

```sh
# from repo root (Linux cross-compile)
make windows
# or DLL only:
make bin/schannel_hook.dll
```

Copy `bin/schannel_hook.dll` next to `ecapture.exe` (overwrite any older DLL).

## Usage (correct order)

```powershell
# Terminal A — target process (note its PID)
$PID   # e.g. 10484

# Terminal B — Admin
.\ecapture.exe tls --schannel -m text --pid 10484 --debug
# wait until you see: Injected schannel_hook.dll ...

# Terminal A — only AFTER injection succeeds
Invoke-WebRequest https://api.github.com -UseBasicParsing
```

You should see `SSPIAppData` lines with HTTP plaintext in Terminal B.
Schannel ETW metadata may still show `PID:8` (System); that is normal.

## Why older DLLs crashed

`EncryptMessage` prologue on current Windows:

```text
push … ; sub rsp,58h
mov rax, [rip+cookie]   ; load /GS cookie into RAX
xor rax, rsp            ; needs RAX intact
```

An early trampoline used `mov rax, imm64; jmp rax` to return to the original
function. That **clobbered RAX**, so the stack-cookie check faulted with
`AccessViolationException` / `0xC0000005` (often on the 2nd HTTPS call).

Current code:
- jumps with `jmp qword ptr [rip+0]; dq abs` (preserves GPRs)
- relocates RIP-relative loads
- allocates the trampoline **within ±~1.5GB of `EncryptMessage`**
  (a plain `VirtualAlloc(NULL)` often lands too far away, overflowing the
  signed 32-bit RIP displacement and still crashing with 0xC0000005)

## Limitations

- Requires Administrator / `SeDebugPrivilege` for injection.
- PPL / protected processes cannot be injected.
- **amd64 only** — ARM64 builds do not install hooks.
- Do not reuse a DLL built before this fix; delete old `schannel_hook.dll` first.
- TLS secrets / NSS keylog still need a separate LSASS/ncrypt path
  (see `docs/windows-roadmap.md`).
