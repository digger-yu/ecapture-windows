<!-- MarkdownTOC autolink="true" -->

- [eCapture 工作原理](#ecapture-工作原理)
- [eCapture 系统架构](#ecapture-系统架构)
- [编译方法](#编译方法)
    - [编译环境](#编译环境)
    - [未开启BTF的编译](#未开启btf的编译)
    - [交叉编译](#交叉编译)
    - [Windows 编译](#windows-编译)
        - [Windows 当前限制](#windows-当前限制)
- [原理](#原理)
    - [eBPF技术](#ebpf技术)
    - [eBPF学习资料](#ebpf学习资料)
<!-- /MarkdownTOC -->
----

# eCapture 系统架构

![](./images/ecapture-architecture.png)

# eCapture 工作原理

![](./images/how-ecapture-works.png)

## 自行编译

自行编译对编译环境有要求，参考**原理**章节的介绍。

# 编译方法

针对个别程序使用的openssl类库是静态编译，也可以自行修改源码实现。若函数名不在符号表里，也可以自行反编译找到函数的offset偏移地址，填写到
`Uaddress`
属性上，进行编译。
笔者环境`ubuntu 21.04`， Linux Kernel 4.18以上通用。
**推荐使用`UBUNTU 20.04` 及以上版本的Linux测试。**

> **Note**
>
> Android版本编译方法见 [eCapture旁观者：Android HTTPS明文抓包](https://mp.weixin.qq.com/s/KWm5d0uuzOzReRtr9PmuWQ)

## 工具链版本

* golang 1.21 以上
* clang 9.0 以上
* cmake 3.18.4 以上
* clang backend: llvm 9.0 以上
* kernel config:CONFIG_DEBUG_INFO_BTF=y (可选，2022-04-17增加)

## 编译环境

### ubuntu

如果你使用的是ubuntu 20.04以及更新版本，可以使用一条命令即可完成编译环境的初始化。

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
```

### 其他Linux

编译环境除了上面`工具链版本`列出的软件外，还需要以下软件，请自行安装。

* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**克隆仓库代码，并进行编译**

注意：如果系统里没有 `/usr/local/lib/libpcap.a`，则下面 `make` 命令会将 libpcap
编译并安装到 `/usr/local/lib` 目录下。如果系统里已经安装了 libpcap 但没有
`/usr/local/lib/libpcap.a`，则 `make` 命令会破坏系统里的 libpcap 头文件。

```shell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
make
bin/ecapture
```

如果你在中国，可以在`make`编译之前，设定GOPROXY来加速eCapture依赖的go package的安装。

```shell
export GOPROXY=https://goproxy.cn
```

## 未开启BTF的编译

2022/04/17起，eCapture支持了未开启BTF的系统编译，编译指令为：`make nocore`，即在不支持BTF的Linux上也可以正常工作。

```shell
git clone git@github.com:gojue/ecapture.git
cd ecapture
make nocore
bin/ecapture
```

## 交叉编译

### 内核头文件

要交叉编译eCapture工具，您需要安装目标体系结构的内核头文件。需要安装`linux-source`软件包。

```shell
kernel_ver=`uname -r | cut -d'-' -f 1`
sudo apt-get install -y linux-source-$kernel_ver
cd /usr/src
source_file=$(find . -maxdepth 1 -name "*linux-source*.tar.bz2")
source_dir=$(echo "$source_file" | sed 's/\.tar\.bz2//g')  
sudo tar -xf $source_file
cd $source_dir
test -f .config || yes "" | sudo make oldconfig
```

### ToolChains

在amd64架构下，交叉编译aarch64架构的二进制文件，需要安装gcc-aarch64-linux-gnu工具链。同样，在aarch64架构下，交叉编译amd64架构的二进制文件，需要安装gcc-x86-64-linux-gnu工具链。

* amd64 arch: gcc-aarch64-linux-gnu
* arm64 arch: gcc-x86-64-linux-gnu

### 编译命令

要在ubuntu `amd64` 系统上构建 `arm64`的产物，您可以设置 `CROSS_ARCH`环境变量来实现交叉编译。

```shell
CROSS_ARCH=arm64 make
```

## Windows 编译

eCapture 支持 Windows 平台（x86_64 和 arm64），使用 ETW（Event Tracing for Windows）
替代 eBPF。**Phase 1** 通过 `Microsoft-Windows-Schannel-Events` 捕获 Schannel
**握手元数据**；可选 **Phase 2** 明文依赖配套 `schannel_hook.dll`
（见 [`windows-roadmap.md`](./windows-roadmap.md)）。

* **管理员权限**：运行时需要管理员权限（ETW 会话需要提升权限）
* **Npcap 运行时**（可选，pcap 模式运行时需要）：从 [npcap.com](https://npcap.com/) 安装，需启用 "WinPcap API-compatible mode"

### 从 Linux 交叉编译

Windows 构建只需要以下依赖即可在任何 Linux 主机上编译：

* **Go 1.21** 及以上

如果需要 pcap 模式，还需要：

* **MinGW-w64** 交叉编译器
  - Ubuntu 下安装：`sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-aarch64-linux-gnu`
* **Npcap SDK**：从 [npcap.com](https://npcap.com/) 下载 SDK，并设置环境变量 `NPCAP_SDK` 指向 SDK 根目录
  - 目录结构示例：`/opt/npcap-sdk/Include/`、`/opt/npcap-sdk/Lib/x64/`、`/opt/npcap-sdk/Lib/ARM64/`

编译命令：

```shell
# Windows amd64 版本
make windows

# Windows arm64 版本
make windows-arm64
```

`make windows` 会自动检测 `NPCAP_SDK` 环境变量：如果已设置，则自动启用 pcap 支持（CGO_ENABLED=1）；如果未设置，则构建仅含 ETW 的版本（CGO_ENABLED=0）。

如需 pcap 模式，只需安装 MinGW-w64 和 Npcap SDK，然后设置 `NPCAP_SDK`：

```shell
# 1. 安装 MinGW-w64
sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-aarch64-linux-gnu

# 2. 下载 Npcap SDK 并解压
wget https://npcap.com/dist/npcap-sdk-1.13.zip
unzip npcap-sdk-1.13.zip -d /opt/
export NPCAP_SDK=/opt/npcap-sdk

# 3. 编译（自动检测 NPCAP_SDK，启用 pcap）
make windows                 # Windows amd64
```

**关于 Windows arm64 的说明**：`make windows-arm64` 始终构建仅含 ETW 的版本（由于 gopacket/pcap 兼容性问题，pcap 模式不支持 Windows ARM64）。arm64 构建会忽略 `NPCAP_SDK` 环境变量。

### 在 Windows 上本地编译

> **注意**：eCapture 的 Makefile 使用 Linux 专属工具（`uname`、`bpftool`、`clang` 等），因此 **`make` 命令不支持在 Windows 上直接使用**。Windows 本地编译请直接使用 `go build`。

依赖要求：

* **Go 1.21** 及以上
* **MSYS2**（仅当需要 pcap 模式时）：安装 [MSYS2](https://www.msys2.org/) 并将 `mingw-w64` 添加到 PATH
* **Npcap SDK**（可选，pcap 模式时需要）：从 [npcap.com](https://npcap.com/) 下载 SDK

编译命令：

```powershell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
# 默认：不带 pcap 模式（无需 CGO）
$env:CGO_ENABLED = "0"
go build -tags windows -o bin/ecapture.exe main.go

# 启用 pcap 模式：把 CGO_CFLAGS/LDFLAGS 指向你的 Npcap SDK 安装路径
$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS = "-I`"C:\Program Files\Npcap\Include`""
$env:CGO_LDFLAGS = "-L`"C:\Program Files\Npcap\Lib\x64`" -lwpcap -lPacket"
go build -tags "windows,pcap" -o bin/ecapture.exe main.go
```

如果你在中国，可以在编译之前设置 GOPROXY 来加速依赖包下载：

```powershell
$env:GOPROXY = "https://goproxy.cn,direct"
```

### Windows 功能列表

| 功能 | 说明 | 不含 pcap | 含 pcap（需设置 NPCAP_SDK） |
|------|------|----------|------------------|
| TLS/Schannel ETW | 通过 `Microsoft-Windows-Schannel-Events` `{91CC1150-71AA-47E2-AE18-C96E61736B6F}` 捕获握手/**生命周期元数据** | 支持（元数据） | 支持（元数据） |
| SSPI 明文（`schannel_hook.dll` + `--pid`） | 注入配套 DLL，hook `EncryptMessage`/`DecryptMessage` | 可选 | 可选 |
| OpenSSL DLL 钩子 | 仅同进程 trampoline；尚无跨进程 OpenSSL 捕获 | 有限 | 有限 |
| pcap 模式 | 通过 Npcap 抓线包（线上仍为密文） | 不支持 | 支持（需安装 Npcap） |
| keylog 模式 | 从 Schannel ETW 导出 NSS keylog | **不支持**（告警；需 Phase 3 LSASS/ncrypt） | **不支持** |

> **OpenSSL / SSPI 钩子**：同进程 `Hook.Install` 可用于测试。跨进程 Schannel 明文需构建
> `contrib/schannel_hook` 并传入 `--pid`。详见 [Windows 当前限制](#windows-当前限制)。

### Windows 常见编译错误

| 错误 | 原因 | 修复 |
|------|------|------|
| `undefined: pcapTPtr` / `undefined: pcapBpfProgram` / `undefined: pcapIf` | 交叉编译时找不到 Npcap SDK 头文件 | 安装 Npcap SDK 并设置 `NPCAP_SDK` 环境变量，或取消设置 `NPCAP_SDK` 构建仅 ETW 版本 |
| `cannot find x86_64-w64-mingw32-gcc` | 未安装 MinGW-w64 | `apt-get install gcc-mingw-w64-x86-64` |
| `undefined: _Cfunc__cgo_runtime_cmalloc` | `CGO_ENABLED=1` 但构建环境无法使用 CGO（例如纯交叉编译未带工具链） | 使用 `CGO_ENABLED=0` 构建（`make windows` / `make windows-arm64`） |
| `windows-arm64: relocation error` | 旧版 MinGW 不支持 arm64 | `apt-get install gcc-mingw-w64-aarch64-linux-gnu` |

### Windows 当前限制

Windows 支持按阶段交付。Schannel ETW 元数据现已可用；明文与 keylog 需要额外组件。
详见 [`windows-roadmap.md`](./windows-roadmap.md)。

| 能力 | 状态 | 备注 |
|------|------|------|
| Schannel ETW（`--schannel`，默认 `true`） | 可用（元数据） | Provider `{91CC1150-71AA-47E2-AE18-C96E61736B6F}`。仅握手/凭证事件——**不是** HTTP AppData。 |
| SSPI 明文（`schannel_hook.dll` + `--pid`） | 可选 | 从 `contrib/schannel_hook/` 构建 DLL，注入目标 PID。 |
| OpenSSL inline hook（`--libssl=<路径>`） | 仅同进程 | 无法捕获第三方 OpenSSL 进程。 |
| 经 Schannel ETW 的 `-m keylog` | 不可用 | 启动告警；Phase 3 = LSASS/ncrypt 提取。 |
| GnuTLS / NSS / GoTLS 钩子 | 未实现 | 尚无 Windows 版本。 |
| pcap 模式（`-m pcap`） | 可用（需 `NPCAP_SDK` + Npcap 运行时） | 无密钥时数据包保持加密。 |

**当前推荐的 Schannel 用法**：

1. 使用 Schannel 客户端（PowerShell / 带 Schannel 的 `curl.exe` / .NET HttpClient）。
2. 元数据：
   ```powershell
   ecapture.exe tls --schannel --debug -m text
   ```
3. 明文（构建 `schannel_hook.dll` 后）：
   ```powershell
   ecapture.exe tls --schannel -m text --pid <target_pid>
   ```

**面向仅使用 OpenSSL 主机的变通方案**：

* 使用 pcap 模式，再配合应用自身导出的 keylog（若有）解密。
* 尽量在 Linux 上对 OpenSSL 进程使用 eCapture。

### Windows E2E 测试

PowerShell 端到端测试脚本位于 `test/e2e/windows/` 目录，需要以管理员身份运行：

```powershell
cd test\e2e\windows
.\windows_tls_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_pcap_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
```

# 原理

## eBPF技术

参考[ebpf](https://ebpf.io)官网的介绍

## eBPF学习资料

* [eBPF PDF资料精选](https://github.com/gojue/ebpf-slide)
* [CFC4N的博客](https://www.cnxct.com)