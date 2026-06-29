<!-- MarkdownTOC autolink="true" -->

- [Windows 上使用 Schannel 模块捕获 TLS/SSL](#windows-上使用-schannel-模块捕获-tlsssl)
- [能力边界（请先读）](#能力边界请先读)
- [背景](#背景)
- [前置条件](#前置条件)
- [步骤 1：构建或下载 ecapture.exe](#步骤-1构建或下载-ecaptureexe)
- [步骤 2：以 Schannel 模式启动 eCapture](#步骤-2以-schannel-模式启动-ecapture)
  - [text 模式（ETW 元数据）](#text-模式etw-元数据)
  - [keylog 模式（ETW 无法导出密钥）](#keylog-模式etw-无法导出密钥)
  - [通过 SSPI hook DLL 捕获明文](#通过-sspi-hook-dll-捕获明文)
  - [pcap 模式（需要 Npcap）](#pcap-模式需要-npcap)
- [步骤 3：使用基于 Schannel 的客户端发起 HTTPS 请求](#步骤-3使用基于-schannel-的客户端发起-https-请求)
- [步骤 4：查看捕获结果](#步骤-4查看捕获结果)
- [常见问题排查](#常见问题排查)
- [限制说明](#限制说明)
- [路线图](#路线图)

<!-- /MarkdownTOC -->
----

# Windows 上使用 Schannel 模块捕获 TLS/SSL

本指南说明如何在 Windows 上对使用内置 Schannel SSP（`schannel.dll` /
`secur32.dll`）的进程使用 eCapture。捕获基于
`Microsoft-Windows-Schannel-Events` ETW Provider，**无需** CA 证书。

# 能力边界（请先读）

| 模式 | 当前实际能力 |
|------|--------------|
| `--schannel -m text` | **握手 / 生命周期元数据**（事件名、PID/TID、可能有的 TargetName）。**不是** HTTP 明文。 |
| `--schannel -m keylog` | **ETW 无法导出密钥。** 启动时会告警。Keylog 依赖 Phase 3（LSASS/ncrypt）。 |
| `--schannel -m text --pid N` + `schannel_hook.dll` | 通过 DLL 注入捕获 `EncryptMessage` / `DecryptMessage` **明文**（Phase 2）。 |
| `-m pcap` | 通过 Npcap 抓线包（线上仍是密文，除非另有密钥）。 |

**Phase 2（SSPI 明文）与 Phase 3（LSASS keylog）是两条不同路线**——对照表见
[`windows-roadmap.md`](./windows-roadmap.md#phase-2-vs-phase-3-comparison)。
简记：要在 eCapture 里直接看正文 → Phase 2；要用 Wireshark 离线解密 pcap → Phase 3。

# 背景

Schannel 是多数 Microsoft / .NET / PowerShell 客户端的默认 TLS 实现。ETW：

| 名称 | GUID |
|------|------|
| `Microsoft-Windows-Schannel-Events` | `{91CC1150-71AA-47E2-AE18-C96E61736B6F}` |

eCapture 订阅该 Provider 并输出元数据。该 Provider **不**暴露明文；明文需可选的 SSPI hook DLL。

# 前置条件

| 需求 | 说明 |
|------|------|
| Windows 10 1809 (build 17763) 或更新 | 更老版本 Schannel 追踪能力有限。 |
| 管理员 PowerShell | ETW 会话与 DLL 注入需要提权。 |
| `ecapture.exe` | 用 `make windows` / `make windows-arm64` 交叉编译，或本地 `go build`。 |
| Schannel 客户端 | PowerShell `Invoke-WebRequest`、系统自带 `curl.exe`（Schannel）、.NET `HttpClient`。 |
| 可选：`schannel_hook.dll` | 从 `contrib/schannel_hook/` 构建，用于明文捕获。 |

> 基于 Chromium 的浏览器（Edge/Chrome）使用 **BoringSSL**，不是 Schannel。
> Firefox 使用 **NSS**。它们不在 `--schannel` 范围内。

# 步骤 1：构建或下载 ecapture.exe

```powershell
# 推荐在 Linux 主机交叉编译
make windows-arm64   # 或: make windows
```

或在 Windows 本地：

```powershell
$env:CGO_ENABLED = "0"
go build -tags windows -o .\bin\ecapture.exe .
```

# 步骤 2：以 Schannel 模式启动 eCapture

打开**提升权限**的 PowerShell。

## text 模式（ETW 元数据）

```powershell
PS C:\Tools> .\ecapture.exe tls --schannel -m text
```

| 参数 | 含义 |
|------|------|
| `tls` | Windows TLS 子命令（Schannel ETW + 可选 hook）。 |
| `--schannel` | 启用 Schannel ETW（默认 `true`）。 |
| `-m text` | 打印元数据事件（默认）。 |
| `-l save_schannel.log` | 仅重定向**进程日志**（`--logaddr`）。捕获事件走 stdout / `--eventaddr`。 |

## keylog 模式（ETW 无法导出密钥）

```powershell
PS C:\Tools> .\ecapture.exe tls --schannel -m keylog -k save_schannel.keylog
```

启动时会有告警。在 Phase 3 落地前 keylog 文件会保持为空。不要把空文件当成捕获成功。

## 通过 SSPI hook DLL 捕获明文

```powershell
# 先构建 DLL（见 contrib/schannel_hook/README.md），放到 ecapture.exe 同目录
PS C:\Tools> .\ecapture.exe tls --schannel -m text --pid 1234
```

目标进程使用 Schannel SSPI 时，应能看到带 `send` / `recv` 明文的 `SSPIAppData` 行。

## pcap 模式（需要 Npcap）

```powershell
PS C:\Tools> .\ecapture.exe tls --schannel -m pcap -i "Ethernet" -w save_schannel.pcapng
```

没有密钥时数据包仍是密文。

# 步骤 3：使用基于 Schannel 的客户端发起 HTTPS 请求

在**另一个**窗口：

```powershell
Invoke-WebRequest -Uri https://api.github.com -UseBasicParsing
# 或
curl.exe -sSL https://api.github.com | Select-Object -First 5
```

确认 `curl.exe --version` 显示 `Schannel`。

# 步骤 4：查看捕获结果

### ETW 元数据示例

```text
PID:1234 TID:5678 AcquireCredentialHandleStart(257) Proto: Cipher: Target:
PID:1234 TID:5678 DeleteSecurityContext(1793) Proto: Cipher: Target:api.github.com
```

### SSPI 明文示例（hook DLL + `--pid`）

```text
PID:1234 TID:5678 SSPIAppData send len=23 data="GET / HTTP/1.1\r\nHost: "
PID:1234 TID:5678 SSPIAppData recv len=45 data="HTTP/1.1 200 OK\r\nServer: GitHub.com"
```

# 常见问题排查

- **ETW session 启动失败 / Access denied** — 以管理员重新运行。
- **探针已启动但无事件** — 确认客户端走 Schannel；用 `logman query providers` 确认 GUID `{91CC1150-71AA-47E2-AE18-C96E61736B6F}`。
- **只有元数据、没有 HTTP 正文** — 纯 ETW 时这是预期行为。构建并注入 `schannel_hook.dll`，并传 `--pid`。
- **注入失败 / OpenProcess 参数错误** — `--pid` 必须是**仍在运行**的目标进程 PID（在目标窗口执行 `$PID`，不要用已退出窗口的旧值）。
- **PowerShell 注入后崩溃（0xC0000005 / AccessViolation）** — 请用当前仓库重新交叉编译的 `schannel_hook.dll` 覆盖旧文件。旧 trampoline 会破坏栈 cookie（`mov rax; jmp rax`）。详见 `contrib/schannel_hook/README.md`。
- **keylog 为空** — Schannel ETW 下这是预期行为。见路线图 Phase 3。
- **`-l` 文件只有 JSON 日志** — 该文件是 `--logaddr`，不是事件流。请看控制台或设置 `--eventaddr`。

# 限制说明

- Schannel ETW **不**暴露 master secret 或 AppData 明文。
- OpenSSL / BoringSSL / NSS 流量需要其它探针（Windows 上尚未实现）。
- SSPI DLL 注入无法覆盖 PPL / 受保护进程。
- pcap 模式需要 Npcap，且无密钥时不会自动解密。

# 路线图

见 [`windows-roadmap.md`](./windows-roadmap.md) 的 Phase 1–3，以及
[Phase 2 vs Phase 3 对照表](./windows-roadmap.md#phase-2-vs-phase-3-comparison)
（SSPI 明文 vs LSASS/ncrypt keylog）。
