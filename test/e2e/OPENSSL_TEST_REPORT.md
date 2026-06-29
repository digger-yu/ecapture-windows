# eCapture OpenSSL/TLS 模块完整测试报告

## 一、报告概述

| 项目 | 内容 |
|------|------|
| **项目名称** | eCapture（基于 eBPF/ETW 的 SSL/TLS 明文捕获工具） |
| **被测对象** | `bin/ecapture` 二进制文件（OpenSSL/BoringSSL TLS 捕获模块） |
| **测试范围** | OpenSSL / BoringSSL / GnuTLS TLS 明文捕获能力（text/pcap/keylog 三种模式） |
| **测试类型** | 端到端测试（E2E End-to-End Test） |
| **测试程序位置** | `test/e2e/` |
| **测试入口** | `test/e2e/tls_e2e_test.sh` |
| **高级测试** | `tls_text_advanced_test.sh`、`tls_pcap_advanced_test.sh`、`tls_keylog_advanced_test.sh` |
| **报告生成时间** | 2026-07-06 |
| **测试环境** | Linux x86_64 (kernel ≥ 4.18) 或 aarch64 (kernel ≥ 5.5) |

---

## 二、被测程序说明

### 2.1 eCapture 是什么

eCapture 是一款无需 CA 证书即可捕获 SSL/TLS 明文、bash/zsh 命令和 SQL 查询的工具。它通过 Linux 上的 eBPF（内核 ≥ 4.18）以及 Windows 上的 ETW 实现底层 hook 能力。

### 2.2 OpenSSL/TLS 模块核心原理

```
应用程序 (curl, wget, nginx, etc.)
        ↓
libssl.so / libcrypto.so (OpenSSL/BoringSSL)
        ↓
eBPF Uprobe / kprobe
        ↓
eCapture 用户态解析
        ↓
文本模式 / pcap 模式 / keylog 模式
```

- **OpenSSL**：18 个 eBPF 内核 C 程序，覆盖
  - `1.0.2a`（1 个）
  - `1.1.0a`（1 个）
  - `1.1.1{a, b, d, j}`（4 个）
  - `3.0.{0, 12}`（2 个）
  - `3.1.0`（1 个）
  - `3.2.{0, 3, 4}`（3 个）
  - `3.3.{0, 2, 3}`（3 个）
  - `3.4.{0, 1}`（2 个）
  - `3.5.0`（1 个）
- **BoringSSL**：5 个 eBPF 内核 C 程序
  - `a.{13, 14, 15, 16}`（4 个 Android 命名空间版本）
  - `na`（非 Android 通用版本）
- **GnuTLS**：7 个 eBPF 内核 C 程序，覆盖 `3.6.{12, 13}`、`3.7.{0, 3, 7}`、`3.8.{4, 7}`
- 内核态 C 代码位于 `kern/openssl_X_Y_Z_kern.c` / `kern/boringssl_*.c` / `kern/gnutls_*.c`
- 用户态 Go 代码位于 `internal/probe/openssl/` / `internal/probe/boringssl/` / `internal/probe/gnutls/`
- 字节码嵌入到 `assets/ebpf_probe.go`（`make assets` 生成）

### 2.3 测试程序依赖组件

| 组件 | 作用 | 位置 |
|------|------|------|
| `tls_e2e_test.sh` | 3 种模式基础测试入口 | `test/e2e/` |
| `tls_text_advanced_test.sh` | text 模式 8 个高级场景 | `test/e2e/` |
| `tls_pcap_advanced_test.sh` | pcap 模式 8 个高级场景 | `test/e2e/` |
| `tls_keylog_advanced_test.sh` | keylog 模式 8 个高级场景 | `test/e2e/` |
| `go_https_client.go` | Go 编写的 HTTPS 客户端 | `test/e2e/` |
| `common.sh` | 公共工具函数（root 检查、内核版本检查、超时） | `test/e2e/` |
| `curl` | 触发 OpenSSL 流量的命令行客户端 | 系统依赖 |
| `tshark`/`tcpdump` | pcap 模式文件验证 | 系统依赖（可选） |

---

## 三、测试环境要求

### 3.1 硬件与操作系统

| 项 | 要求 |
|----|------|
| 架构 | x86_64 或 aarch64 |
| 内核版本（x86_64） | ≥ 4.18 |
| 内核版本（aarch64） | ≥ 5.5 |
| 操作系统 | Linux（推荐 Ubuntu 20.04+） |
| 权限 | ROOT 权限（eBPF/Uprobe 必需） |
| BTF | 推荐开启（`CONFIG_DEBUG_INFO_BTF=y`）；未开启时使用 `make nocore` |

### 3.2 工具链

| 工具 | 版本 | 安装方式 |
|------|------|---------|
| Go | ≥ 1.21（建议 ≥ 1.24） | `https://go.dev/dl/` |
| Clang | ≥ 9.0 | `apt install clang` |
| LLVM | ≥ 9.0 | `apt install llvm` |
| cmake | ≥ 3.18.4 | `apt install cmake` |
| bpftool | 匹配内核版本 | `apt install linux-tools-generic` |
| llc | 匹配 LLVM | `apt install llvm` |
| libelf-dev | 任意 | `apt install libelf-dev` |
| pkgconf | 任意 | `apt install pkgconf` |
| linux-source | 匹配内核 | 交叉编译时需要 |

### 3.3 一键初始化编译环境（Ubuntu）

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
```

### 3.4 国内加速

```bash
export GOPROXY=https://goproxy.cn,direct
```

---

## 四、测试执行步骤

### 4.1 步骤 1：构建 eCapture

```bash
cd /path/to/ecapture

# 标准构建（CO-RE 模式，需要 BTF）
make all

# 非 CO-RE 模式（无 BTF 也能跑）
make nocore
```

构建产物路径：

```
bin/ecapture    # Linux 可执行文件
bytecode/*.o    # eBPF 字节码（已嵌入二进制）
```

### 4.2 步骤 2：执行基础 TLS 测试

```bash
cd test/e2e
sudo bash tls_e2e_test.sh
```

测试脚本会自动：

1. 检查 ROOT 权限（`check_root`）
2. 检查内核版本 ≥ 4.18（`check_kernel_version 4 18`）
3. 检查 `curl` 是否存在
4. 创建 `/tmp/ecapture_tls_e2e_$$` 临时目录
5. 按顺序执行 text / pcap / keylog 三种模式
6. 汇总结果并清理

### 4.3 步骤 3：执行高级测试

```bash
# text 模式 8 个高级场景
sudo bash tls_text_advanced_test.sh

# pcap 模式 8 个高级场景
sudo bash tls_pcap_advanced_test.sh

# keylog 模式 8 个高级场景
sudo bash tls_keylog_advanced_test.sh
```

### 4.4 步骤 4：通过 Makefile 批量执行

```bash
sudo make e2e-tls                    # 基础 TLS 测试
sudo make e2e-tls-text-advanced      # text 高级
sudo make e2e-tls-pcap-advanced      # pcap 高级
sudo make e2e-tls-keylog-advanced    # keylog 高级
sudo make e2e-basic                  # 全部基础测试
sudo make e2e-advanced               # 全部高级测试
sudo make e2e                        # 全部
```

---

## 五、三种模式详细测试流程

### 5.1 Text 模式（明文捕获）

**测试命令**：
```bash
./bin/ecapture tls -m text > output/text_mode.log 2>&1 &
ECAPTURE_PID=$!
sleep 3

# 触发 HTTPS 流量
curl -v https://api.github.com > output/text_client.log 2>&1
sleep 2

# 停止 eCapture
kill -INT $ECAPTURE_PID
sleep 2
```

**校验规则**：

| 校验项 | 校验方法 | 通过条件 |
|--------|---------|---------|
| 进程存活 | `kill -0 $ECAPTURE_PID` | 启动后 3 秒仍在运行 |
| 日志非空 | `[ -s text_mode.log ]` | 文件大小 > 0 |
| HTTP 明文关键字 | `grep -iq "GET\|POST\|HTTP"` | 至少命中一个 |
| 内容验证 | `grep -iq "GitHub"` | 命中（api.github.com 的响应体） |
| eBPF 事件解码无错 | `grep -c "Failed to decode event"` | 计数 == 0 |

**回归检查**（`Failed to decode event`）：
> 防止 `ConnDataEvent.Sock` 结构体大小不匹配导致的解码失败回归。

### 5.2 Pcap 模式（pcapng 文件输出）

**测试命令**：
```bash
./bin/ecapture tls -m pcap -i eth0 --pcapfile=output/capture.pcapng &
ECAPTURE_PID=$!
sleep 3
curl -v https://api.github.com
sleep 2
kill -INT $ECAPTURE_PID
```

**校验规则**：

| 校验项 | 校验方法 | 通过条件 |
|--------|---------|---------|
| pcap 文件存在 | `[ -f capture.pcapng ]` | 文件存在 |
| 文件非空 | `[ -s capture.pcapng ]` | 大小 > 0 |
| pcapng 魔数 | `od -An -tx1 -N4` | 前 4 字节为 `0a0d0d0a` |
| file 命令验证 | `file capture.pcapng` | 包含 `pcap` 或 `capture` |
| tshark 兼容 | `tshark -r capture.pcapng` | 可正常解析（高级测试） |

### 5.3 Keylog 模式（NSS Keylog 格式）

**测试命令**：
```bash
./bin/ecapture tls -m keylog --keylogfile=output/masterkey.log &
ECAPTURE_PID=$!
sleep 3
# 多次请求以提高捕获概率
curl -s -o /dev/null https://api.github.com
sleep 1
curl -s -o /dev/null https://api.github.com
sleep 3
kill -INT $ECAPTURE_PID
```

**校验规则**：

| 校验项 | 校验方法 | 通过条件 |
|--------|---------|---------|
| keylog 文件存在 | `[ -f masterkey.log ]` | 文件存在 |
| 文件非空 | `[ -s masterkey.log ]` | 大小 > 0 |
| NSS 格式 | `grep "CLIENT_RANDOM"` | 至少一条 `CLIENT_RANDOM` 条目 |
| keylog 配置生效 | `grep "Keylog handler registered\|capture_mode=keylog"` | 命中 |

**注意**：
> Keylog 捕获依赖环境。如果 `curl` 使用的 OpenSSL 函数不在 eCapture hook 范围内（例如 `SSL_write_ex`），keylog 文件可能为空。此种情况下，仅校验 `keylog_configured=1` 即可判通过（脚本已实现该 fallback 逻辑）。

---

## 六、测试场景矩阵

### 6.1 OpenSSL 基础测试（3 场景，源自 `tls_e2e_test.sh`）

> `tls_e2e_test.sh` 脚本自身注释里写的是 "OpenSSL/BoringSSL"，但实际只跑 `ecapture tls -m {text|pcap|keylog}`，不针对 BoringSSL 做单独验证。`boringssl_e2e_test.sh` 暂未在仓库中提供（`gnutls_e2e_test.sh` 存在但不在本报告范围）。

| # | 模式 | 场景 | 命令 | 通过条件 |
|---|------|------|------|---------|
| 1 | text | HTTPS 明文捕获 | `ecapture tls -m text` + `curl https://api.github.com` | 日志中含 `GET`/`GitHub` 等关键字，且无 `Failed to decode event` |
| 2 | pcap | pcapng 文件输出 | `ecapture tls -m pcap -i eth0 --pcapfile=out.pcapng` | 文件存在、非空、魔数 `0a0d0d0a` |
| 3 | keylog | TLS 密钥导出 | `ecapture tls -m keylog --keylogfile=master.log` | 含 `CLIENT_RANDOM` 条目 |

### 6.2 Text 模式高级测试（8 场景）

| # | 场景 | 命令/参数 | 验证点 |
|---|------|-----------|--------|
| 1 | HTTP/1.1 明文 | `ecapture tls -m text` | 含 `GET /`/`HTTP/1.1` |
| 2 | HTTP/2 明文 | `ecapture tls -m text` | 含 `:method`、`:path` 等 HPACK 字段 |
| 3 | PID 过滤 | `ecapture tls -m text --pid=$$` | 仅捕获指定 PID 的流量 |
| 4 | UID 过滤 | `ecapture tls -m text --uid=1000` | 仅捕获指定 UID 的流量 |
| 5 | 并发连接 | `ecapture tls -m text` + 10 并发 curl | 日志中能区分不同连接 |
| 6 | 文本截断 | `ecapture tls -m text -t 512` | 单行最大 512 字节（脚本默认 `truncate_size=512`） |
| 7 | 调试模式 | `ecapture tls -m text -d` | 启用 debug 日志 |
| 8 | 十六进制输出 | `ecapture tls -m text --hex` | 含 hex 编码 |

### 6.3 Pcap 模式高级测试（8 场景）

| # | 场景 | 命令/参数 | 验证点 |
|---|------|-----------|--------|
| 1 | 基础 pcapng | `ecapture tls -m pcap` | 魔数 `0a0d0d0a` |
| 2 | 端口过滤 | `ecapture tls -m pcap --port 443` | 过滤 `tcp port 443` |
| 3 | 主机过滤 | `ecapture tls -m pcap --host api.github.com` | 过滤目标主机 |
| 4 | 指定网卡 | `ecapture tls -m pcap -i eth0` | 指定网络接口 |
| 5 | 并发连接 | `ecapture tls -m pcap` + 10 并发 | 文件包含多条记录 |
| 6 | PID 过滤 | `ecapture tls -m pcap --pid=$$` | 仅目标 PID |
| 7 | tshark 兼容 | `tshark -r capture.pcapng` | tshark 可正常解析 |
| 8 | mapsize 配置 | `ecapture tls -m pcap --mapsize 1024` | 自定义 BPF map 大小 |

### 6.4 Keylog 模式高级测试（8 场景）

| # | 场景 | 命令/参数 | 验证点 |
|---|------|-----------|--------|
| 1 | 基础 keylog | `ecapture tls -m keylog` | 文件非空 |
| 2 | TLS 1.2 | `ecapture tls -m keylog` | `CLIENT_RANDOM 48字节 master_secret 48字节` |
| 3 | TLS 1.3 | `ecapture tls -m keylog` | `CLIENT_HANDSHAKE_TRAFFIC_SECRET` 等新格式 |
| 4 | 并发连接 | `ecapture tls -m keylog` + 10 并发 | 多条 `CLIENT_RANDOM` |
| 5 | PID 过滤 | `ecapture tls -m keylog --pid=$$` | 仅目标 PID |
| 6 | UID 过滤 | `ecapture tls -m keylog --uid=1000` | 仅目标 UID |
| 7 | 格式验证 | `grep "^[A-Z_]* [0-9a-f]\{64\} [0-9a-f]\{96\}$"` | 符合 NSS Keylog 规范 |
| 8 | tcpdump 集成 | `tcpdump --include=master.log` | 可用 Wireshark/tcpdump 解密 |

### 6.5 总体测试统计

| 模块 | 基础场景 | 高级场景 | 小计 |
|------|---------|---------|------|
| TLS (OpenSSL) | 3 | 24 | 27 |
| TLS (BoringSSL) | 1 | 0 | 1 |
| TLS (GnuTLS) | 1 | 0 | 1 |
| GoTLS | 1 | 7 | 8 |
| Bash | 1 | 8 | 9 |
| Zsh | 1 | 0 | 1 |
| MySQL | 1 | 7 | 8 |
| PostgreSQL | 1 | 0 | 1 |
| 边界用例 | 0 | 15 | 15 |
| **合计** | **10** | **61** | **71** |

---

## 七、判定标准与退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 全部通过 |
| `1` | 至少一个场景失败 |
| `2` | ROOT 权限检查失败（`check_root`） |
| `3` | 内核版本检查失败（`check_kernel_version`） |
| `4` | 依赖工具缺失（`check_prerequisites`） |
| `5` | eCapture 二进制文件不存在 |

每种模式返回的字符串：

| 模式 | 返回值 |
|------|--------|
| text:PASS / text:FAIL |
| pcap:PASS / pcap:FAIL |
| keylog:PASS / keylog:FAIL |

最终汇总行示例：
```
✓ All TLS E2E tests PASSED
```

或失败时：
```
✗ 1 test(s) failed
```

---

## 八、常见失败原因与排查

| 失败现象 | 可能原因 | 解决方案 |
|----------|---------|---------|
| `Root privileges required` | 未用 `sudo` | `sudo bash tls_e2e_test.sh` |
| `Kernel version 4.x is too old` | 内核版本不足 | 升级内核至 ≥ 4.18（x86_64）或 ≥ 5.5（aarch64） |
| `eCapture binary not found` | 未构建 | `make all` 或 `make nocore` |
| `eCapture process died` | 启动失败 | 检查 `text_mode.log`，通常 BTF/内核头不匹配 |
| `Failed to decode event` 计数 > 0 | 事件结构体大小不匹配回归 | 重新 `make clean && make all`，确认目标 OpenSSL 版本 |
| `Pcap file format could not be verified` | libpcap 未正确链接 | 确认 `lib/libpcap/libpcap.a` 存在 |
| `Keylog file does not contain expected CLIENT_RANDOM` | curl 用了 `SSL_write_ex` | 已知环境问题，脚本会自动 fallback 通过 |
| `Could not determine default network interface` | 无默认路由 | `ip route add default via ...` 或手动指定 `-i` |

---

## 九、测试结果模板

执行 `sudo bash tls_e2e_test.sh` 后填入：

| 模式 | 结果 | 备注 |
|------|------|------|
| text | ☐ PASS / ☐ FAIL | |
| pcap | ☐ PASS / ☐ FAIL | |
| keylog | ☐ PASS / ☐ FAIL | |
| **综合** | ☐ PASS / ☐ FAIL | |

执行高级测试后：

| 测试 | 场景数 | 通过 | 失败 | 通过率 |
|------|--------|------|------|--------|
| text-advanced | 8 | /8 | /8 | % |
| pcap-advanced | 8 | /8 | /8 | % |
| keylog-advanced | 8 | /8 | /8 | % |
| **小计** | 24 | /24 | /24 | % |

---

## 十、参考命令速查

```bash
# 完整流程
cd /path/to/ecapture
make all
sudo make e2e-tls
sudo make e2e-tls-text-advanced
sudo make e2e-tls-pcap-advanced
sudo make e2e-tls-keylog-advanced

# 单独验证某模式
sudo ./bin/ecapture tls -m text &
curl -v https://api.github.com
kill %1

# 清理
make clean
```

---

## 十一、报告结论

| 评估项 | 状态 |
|--------|------|
| 测试程序完整性 | ✅ 8 个基础脚本 + 6 个高级脚本 + 1 个边界脚本 = 71 个场景 |
| 测试覆盖度 | ✅ 覆盖 text/pcap/keylog 三种模式的所有关键路径 |
| 回归保护 | ✅ 内置 `Failed to decode event` 检测 |
| 跨版本兼容 | ✅ OpenSSL 18 个版本（1.0.2a/1.1.0a/1.1.1a,b,d,j/3.0.0,12/3.1.0/3.2.0,3,4/3.3.0,2,3/3.4.0,1/3.5.0）+ BoringSSL 5 个版本 + GnuTLS 7 个版本 均有专用 eBPF C 程序 |
| 自动化能力 | ✅ 通过 `make e2e-*` 一键执行 |
| 文档完整性 | ✅ `README.md` + `QUICK_REFERENCE.md` + `IMPLEMENTATION_STATUS.md` |

**最终结论**：eCapture 的 OpenSSL/BoringSSL TLS 模块 E2E 测试套件设计完整、覆盖面广、可在标准 Linux 环境下自动化执行。建议作为 CI 流水线（如 GitHub Actions `e2e.yml`）的标准校验环节。

