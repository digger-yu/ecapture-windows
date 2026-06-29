<!-- MarkdownTOC autolink="true" -->

- [How eCapture works](#how-ecapture-works)
- [eCapture Architecture](#ecapture-architecture)
- [Compilation instructions](#compilation-instructions)
  - [Compiling from source on Linux](#compiling-from-source-on-linux)
  - [compile without BTF](#compile-without-btf)
  - [cross-compilation](#cross-compilation)
  - [Compiling for Windows](#compiling-for-windows)
    - [Windows Runtime Limitations](#windows-runtime-limitations)
- [What's eBPF](#whats-ebpf)

<!-- /MarkdownTOC -->
----

# How eCapture works

![](./images/how-ecapture-works.png)

# Architecture

![](./images/ecapture-architecture.png)

# Compilation instructions

## Compiling from source on Linux

### Linux prerequisites

Linux kernel 4.18 or later. x86_64/aarch64 architecture.

**prerequisites**

* golang 1.21 or newer
* clang 9.0 or newer
* cmake 3.18.4 or newer
* clang backend: llvm 9.0 or newer

#### ubuntu

If you are using Ubuntu 20.04 or later versions, you can use a single command to complete the initialization of the
compilation environment.

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
```

#### other Linux

In addition to the software listed in the 'Toolchain Version' section above, the following software is also required for
the compilation environment. Please install it yourself.

* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**Clone the repository code and compile it**

Caution: The following `make` command will install libpcap into the system
directory if `libpcap.a` does not exist under `/usr/local/lib`. If you have
installed libpcap in system without `libpcap.a`, it maybe break your libpcap's
headers.

```shell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
make
bin/ecapture
```

## compile without BTF

eCapture support BTF disabled with command `make nocore` to compile at 2022/04/17. It can work normally even on Linux
systems that do not support BTF.

```shell
make nocore
bin/ecapture --help
```

## cross-compilation

### Kernel header files

To cross-compile the eCapture tool, you need to install the kernel header files for the target architecture. you need to
install the `linux-source` package.

```shell
sudo apt-get install -y linux-source
cd /usr/src
source_file=$(find . -maxdepth 1 -name "*linux-source*.tar.bz2")
source_dir=$(echo "$source_file" | sed 's/\.tar\.bz2//g')  
sudo tar -xf $source_file
cd $source_dir
test -f .config || yes "" | sudo make oldconfig
```

### ToolChains

To cross-compile binary files for the aarch64 architecture on an amd64 architecture system, you need to install the
gcc-aarch64-linux-gnu toolchain. Similarly, to cross-compile binary files for the amd64 architecture on an aarch64
system, you need to install the gcc-x86-64-linux-gnu toolchain.

* amd64 arch: gcc-aarch64-linux-gnu
* arm64 arch: gcc-x86-64-linux-gnu

### Build Commands

To build an `arm64` artifact on an ubuntu `amd64` system, you can set the `CROSS_ARCH` environment variable to achieve
cross-compilation.

```shell
CROSS_ARCH=arm64 make
```

# Testing

eCapture includes comprehensive end-to-end (e2e) tests for the TLS, GnuTLS, and GoTLS modules. These tests verify that eCapture can successfully capture plaintext SSL/TLS traffic on Linux systems.

## Running E2E Tests

Run all e2e tests:
```bash
sudo make e2e
```

Run individual module tests:
```bash
sudo make e2e-tls      # Test OpenSSL/BoringSSL capture
sudo make e2e-gnutls   # Test GnuTLS capture
sudo make e2e-gotls    # Test Go TLS capture
```

**Prerequisites**: Linux kernel >= 4.18 (x86_64) or >= 5.5 (aarch64), root access, and required tools (see [e2e-tests.md](./e2e-tests.md)).

For detailed information about the test suite, troubleshooting, and CI integration, see [e2e-tests.md](./e2e-tests.md).

## Compiling for Windows

eCapture supports Windows (x86_64 and arm64) using ETW (Event Tracing for Windows)
instead of eBPF. On Windows, **Phase 1** captures Schannel **handshake metadata**
via `Microsoft-Windows-Schannel-Events`. Optional **Phase 2** plaintext uses the
companion `schannel_hook.dll` (see [`windows-roadmap.md`](./windows-roadmap.md)).

* **Administrator privileges** required at runtime (ETW sessions need elevation)
* **Npcap runtime** (optional, for pcap mode at runtime): install from [npcap.com](https://npcap.com/) with "WinPcap API-compatible mode" enabled

### Cross-compiling from Linux

Windows builds work on any Linux host with:

* **Go 1.21** or newer

If you need pcap mode, you also need:

* **MinGW-w64** cross-compiler
  - On Ubuntu: `sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-aarch64-linux-gnu`
* **Npcap SDK**: download from [npcap.com](https://npcap.com/) and set the `NPCAP_SDK` environment variable
  - Example layout: `/opt/npcap-sdk/Include/`, `/opt/npcap-sdk/Lib/x64/`, `/opt/npcap-sdk/Lib/ARM64/`

Build commands:

```shell
# Windows amd64
make windows                 # → bin/ecapture.exe + bin/schannel_hook.dll

# Windows arm64
make windows-arm64
```

`make windows` automatically detects the `NPCAP_SDK` environment variable: if set, pcap support is enabled (CGO_ENABLED=1); if unset, an ETW-only build is produced (CGO_ENABLED=0).

To enable pcap mode, install MinGW-w64 and the Npcap SDK, then set `NPCAP_SDK`:

```shell
# 1. Install MinGW-w64
sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-aarch64-linux-gnu

# 2. Download Npcap SDK and extract it
wget https://npcap.com/dist/npcap-sdk-1.13.zip
unzip npcap-sdk-1.13.zip -d /opt/
export NPCAP_SDK=/opt/npcap-sdk

# 3. Build (pcap enabled automatically when NPCAP_SDK is set)
make windows                 # Windows amd64
```

**Note on Windows arm64**: `make windows-arm64` always builds ETW-only (pcap mode is not supported on Windows ARM64 due to gopacket/pcap compatibility issues). The `NPCAP_SDK` environment variable is ignored for arm64 builds.

### Building natively on Windows

> **Note**: eCapture's Makefile relies on Linux-specific tools (`uname`, `bpftool`, `clang`, etc.), so **`make` is not supported on Windows**. For native Windows builds, use `go build` directly.

Prerequisites:

* **Go 1.21** or newer
* **MSYS2** (only for pcap mode): install [MSYS2](https://www.msys2.org/) and add `mingw-w64` to PATH
* **Npcap SDK** (optional, for pcap mode): download from [npcap.com](https://npcap.com/)

Build commands:

```powershell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
# Default: no pcap mode (no CGO required)
$env:CGO_ENABLED = "0"
go build -tags windows -o bin/ecapture.exe main.go

# With pcap mode: set CGO_CFLAGS/LDFLAGS to your Npcap SDK install
$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS = "-I`"C:\Program Files\Npcap\Include`""
$env:CGO_LDFLAGS = "-L`"C:\Program Files\Npcap\Lib\x64`" -lwpcap -lPacket"
go build -tags "windows,pcap" -o bin/ecapture.exe main.go
```

### Windows Features

| Feature | Description | Without pcap | With pcap (NPCAP_SDK set) |
|---------|-------------|---------------|----------------|
| TLS/Schannel ETW | Handshake / lifecycle **metadata** via `Microsoft-Windows-Schannel-Events` `{91CC1150-71AA-47E2-AE18-C96E61736B6F}` | Yes (metadata) | Yes (metadata) |
| SSPI plaintext (`schannel_hook.dll` + `--pid`) | Inject companion DLL; hook `EncryptMessage`/`DecryptMessage` | Optional | Optional |
| OpenSSL hooking (DLL) | Same-process trampoline only; no cross-process OpenSSL capture yet | Limited | Limited |
| pcap mode | Network packet capture via Npcap (encrypted on wire) | No | Yes (requires Npcap runtime) |
| keylog mode | NSS keylog from Schannel ETW | **No** (warns; needs Phase 3 LSASS/ncrypt) | **No** |

> **OpenSSL / SSPI hooks**: same-process `Hook.Install` is available for tests.
> Cross-process Schannel plaintext requires building `contrib/schannel_hook` and
> passing `--pid`. See [Windows Runtime Limitations](#windows-runtime-limitations).

### Common Windows Build Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `undefined: pcapTPtr` / `undefined: pcapBpfProgram` / `undefined: pcapIf` | Npcap SDK headers not found during cross-compilation | Install Npcap SDK and set `NPCAP_SDK`, or unset `NPCAP_SDK` for ETW-only build |
| `cannot find x86_64-w64-mingw32-gcc` | MinGW-w64 not installed | `apt-get install gcc-mingw-w64-x86-64` |
| `undefined: _Cfunc__cgo_runtime_cmalloc` | `CGO_ENABLED=1` but the build context cannot use CGO (e.g. pure-cross without toolchain) | Use `CGO_ENABLED=0` build (`make windows` / `make windows-arm64`) |
| `windows-arm64: relocation error` | Old MinGW without arm64 support | `apt-get install gcc-mingw-w64-aarch64-linux-gnu` |

### Windows Runtime Limitations

Windows support is phased. Schannel ETW metadata works today; plaintext and
keylog require additional components. See [`windows-roadmap.md`](./windows-roadmap.md).

| Capability | Status | Notes |
|------------|--------|-------|
| Schannel ETW (`--schannel`, default `true`) | Working (metadata) | Provider `{91CC1150-71AA-47E2-AE18-C96E61736B6F}`. Handshake / credential events only — **not** HTTP AppData. |
| SSPI plaintext (`schannel_hook.dll` + `--pid`) | Optional | Build DLL from `contrib/schannel_hook/`; inject into target PID. |
| OpenSSL inline hook (`--libssl=<path>`) | Same-process only | Does not capture third-party OpenSSL processes. |
| `-m keylog` via Schannel ETW | Not available | Start-up warning; Phase 3 = LSASS/ncrypt extraction. |
| GnuTLS / NSS / GoTLS hooking | Not implemented | No Windows variant yet. |
| pcap mode (`-m pcap`) | Working (when `NPCAP_SDK` + Npcap runtime) | Packets stay encrypted without keys. |

**Recommended Schannel workflow today**:

1. Target a Schannel client (PowerShell / `curl.exe` with Schannel / .NET HttpClient).
2. Metadata:
   ```powershell
   ecapture.exe tls --schannel --debug -m text
   ```
3. Plaintext (after building `schannel_hook.dll`):
   ```powershell
   ecapture.exe tls --schannel -m text --pid <target_pid>
   ```

**Workarounds for OpenSSL-only hosts**:

* Capture in pcap mode and decrypt with an application-provided keylog (if any).
* Prefer Linux eCapture against the OpenSSL process when possible.

### Windows E2E Tests

PowerShell-based end-to-end tests are located in `test/e2e/windows/`. Run as Administrator:

```powershell
cd test\e2e\windows
.\windows_tls_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_pcap_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
```

# What's eBPF

[eBPF](https://ebpf.io)

