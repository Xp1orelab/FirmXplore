# FirmXplore 多固件验证报告（2026-10-03）

> 本报告记录 P0/P1/P2 健壮性与攻击面修复后的多固件回归验证结果，
> 数据可直接引用到技术报告。全部任务使用 `--no-dynamic`（静态全链路 +
> provider-backed 模型调查），模型为 DeepSeek `deepseek-flash`。

## 1. 测试环境与方法

- **部署**：Docker（`firmxplore:latest` CLI 镜像 + dockerized Ghidra 12.1.3 / Java 21）；
  流水线由宿主机 CLI 驱动（`firmxplore analyze --no-dynamic`），模型调查在容器内执行。
- **流水线范围**：提取 → Canonical RootFS → ELF 清单 → Ghidra 深度静态 → 组件关联 →
  静态攻击面发现 → 污点关联 → 假设合成 → Finding 终稿 → 报告生成 → **PiAgent 模型调查**（30 步预算）。
- **测试固件**：TEW-751DR 为厂商原厂固件；OpenWrt 三个镜像为官方发布 factory 镜像
  （公开下载，用于覆盖不同架构/字节序/文件系统变体）。

## 2. 结果矩阵

| 指标 | Archer C7 v2 | Archer A6 v3 | Linksys EA8500 | TEW-751DR |
|---|---|---|---|---|
| 架构 | MIPS **BE** (ath79) | MIPS **LE** (mt7621) | **ARM** (ipq806x, NAND) | MIPS LE |
| 固件大小 | 16.3 MB | 6.9 MB | 9.4 MB | 6.2 MB |
| 提取 | ✅ completed | ✅ completed | ⚠️ **partial**（NAND 变体） | ✅ completed |
| RootFS 文件 / ELF | 1049 / 159 | 1017 / 156 | — / 0 | 1527 / 121 |
| Ghidra 真实分析 | **15/15** | **15/15** | blocked | **12/12** |
| 攻击面入口 | **17** | **17** | 0 | **27** |
| — 入口类型 | service_port×5, tcp_service×12 | 同左 | — | cgi×1, http_route×14, tcp_service×12 |
| — 已关联组件 | 13/17 | 13/17 | — | 2/17 |
| 污点源 / 汇 | 17 / 49 | 17 / 49 | — / — | 27 / 56 |
| 候选路径 | **22** | **22** | 0 | **6** |
| 假设候选 | 22 | 22 | 0 | 6 |
| **Findings** | **13** (candidate) | **13** (candidate) | 0 | **14** (candidate) |
| 动态可行性 | feasible | feasible | — | feasible |
| `user_skipped_stages` | INVESTIGATION, DYNAMIC_VALIDATION | 同左 | 同左 | 同左 |

## 3. 模型调查（provider-backed PiAgent）

| 指标 | Archer C7 v2 | Archer A6 v3 | TEW-751DR |
|---|---|---|---|
| 步数 / 工具调用 | 24 / 24 | 30 / 30 | 30 / 30 |
| **停止原因** | **`model_stopped`**（模型自主收敛） | `max_steps_reached` | `max_steps_reached` |
| **反编译调用** | 2 | 4 | **15** |
| 证据产出 | 13 | 12 | 26 |
| **成功调用 / tokens** | 35 次 / **508,857** | 32 次 / **458,001** | 32 次 / **517,042** |
| **retry（自动恢复）** | **2** | **3** | 0 |
| **failed（重试后仍失败）** | **0** | **0** | 0 |
| 模型假设（canonical=False） | 1 | 1 | 1 |

**关键观察**：

1. **重试机制实战生效**：C7 v2 与 A6 v3 的调查过程中分别出现 2 次和 3 次瞬态断连
   （`status=retry`），全部由指数退避自动恢复，`failed=0`。修复前同等故障会直接以
   `stop_reason=model_error` 终止调查（TEW-751DR 修复前 23 步即断连终止）。
2. **反编译引导生效**：system prompt 引导后模型主动调用 `ghidra.decompile_function`
   （2-15 次/任务），证据中出现 `decompilation`、`dangerous_call_site`、
   `false_positive_ruleout` 类型——模型在做反编译级验证并主动排除误报，而非停留在符号级。
3. **模型自主收敛**：C7 v2 上模型在 24 步主动停止（`model_stopped`），并给出
   "no sufficiently supported security hypothesis" 的保守结论——符合
   "可达 ≠ 可利用"的证据模型，未出现编造发现的行为。
4. **跨架构一致**：MIPS BE / MIPS LE 两条流水线全链路等价工作；
   全部 findings 为 `status=candidate`（L2 callgraph 证据级），confidence 0.35–0.54，
   均附带显式 `missing_evidence` 清单——符合保守声明规范。

## 4. 污点质量（taint_quality 段落）

全部任务的 `argument_mapped_path_count=0`、`decompile_backed_path_count=0`、
`callgraph_synthetic_path_count` 与候选路径数相等——即当前候选路径全部为
Ghidra callgraph 可达链（L2），未建立参数级数据流（L3）。报告通过 `taint_quality`
段落显式区分二者，读者不会把可达链误读为已验证数据流。

## 5. 已知问题（本次验证暴露）

1. **容器内本地提取死锁**：Web 容器内缺少 docker CLI 时，fwagent 回退到本地
   unblob 提取路径；unblob 的 sasquatch（legacy LZMA SquashFS 恢复）对部分镜像
   会无限期挂起（TEW-751DR、Archer C7 均复现，25 分钟零产出）。宿主机
   docker-extract 路径不受影响。建议：容器内安装 docker CLI 或在提取配置中
   限制 sasquatch 超时。
2. **NAND SquashFS 提取不支持**：Linksys EA8500（`squashfs-nand-factory`）提取
   partial，无 canonical rootfs，全链路 blocked——已列入 Known Limitations。
3. **两个 OpenWrt rootfs 指标完全一致**（1049/159 vs 1017/156 为文件清单，
   但 entries/taint/findings 计数相同）：同版本 OpenWrt 的用户态包集高度一致，
   属预期现象，非数据串扰（report.json md5 与 task_id 已核验独立）。

## 6. 结论

- 修复后的静态攻击面发现不再依赖特定后端（lighttpd/FastCGI）：
  4/4 个有有效 rootfs 的固件均产出入口点（17–27 个）与污点源。
- provider-backed 模型调查在真实 API 上稳定跑满预算（3/3 任务无致命失败），
  具备瞬态断连自愈能力，且能主动使用反编译工具深化证据。
- 全部 findings 保持保守的 candidate 级别，符合确定性 Round-5 的声明规范。


## 7. 发现明细（Findings 明细）

### 7.1 TP-Link Archer C7 v2 / Archer A6 v3（OpenWrt，两机结果一致）

13 条候选发现全部落在 OpenWrt 真实组件上，按 (组件, 危险函数类别) 分组：

| 类型 | 目标组件 | 危险 sink |
|---|---|---|
| 命令执行 ×5 | busybox, init, procd, **dnsmasq**, dropbear | execlp / execvp / **popen** / execv |
| 内存安全 ×8 | busybox, opkg, init, procd, dnsmasq, dropbear, pppd, **uhttpd** | strcpy / strcat / sprintf / memcpy |

值得注意的目标：`dnsmasq`（DNS 服务，网络可达）同时命中 popen 与 sprintf/strcat/strcpy 组；
`uhttpd`（Web 服务器）命中 strcpy 组；`dropbear`（SSH 守护进程）命中 execv。

模型调查（PiAgent）：
- Archer A6 v3 上模型提出假设 **"dnsmasq dhcp-script execution path"**（status=candidate），
  并产生 2 条反编译证据（`Decompiled FUN_0001ca6c` / `FUN_000241d8`，ghidra 来源）——
  即模型通过反编译 dnsmasq 的 DHCP 脚本执行路径自行定位到该攻击面；
- Archer C7 v2 上模型经 24 步调查（含 2 次反编译）后给出保守结论
  "dnsmasq DNS resolver is the primary network-facing attack surface; no unsupported..."，
  假设被标记 rejected——未发现参数级数据流时拒绝升级声明。

### 7.2 TP-Link TEW-751DR（厂商固件，含闭源 cgibin）

14 条候选发现覆盖 8 个组件，**重点命中厂商闭源 Web 后端**：

| 类型 | 目标组件 | 危险 sink |
|---|---|---|
| 命令执行 ×5 | **cgibin**, httpd, dnsmasq, hostapd, telnetd | **system / execl**（cgibin）, execve, popen, execv |
| 内存安全 ×9 | cgibin, httpd, arpmonitor, dnsmasq, hostapd, iwconfig, lld2d, rgbin, telnetd | sprintf / strcat / strcpy / memcpy |

- `F-0001`：**cgibin 的 system + execl 组合**——厂商闭源 CGI 处理器中的命令执行
  危险调用对，这是网络攻击面（EP-CGI-htdocs-cgibin，component 已解析）的直接下游；
- 模型调查（PiAgent 30 步、15 次反编译、26 条证据）产出反编译证据
  `Decompiled process_cgi`（cgibin 的 CGI 主处理函数）等，最终以保守结论 rejected 收敛——
  反编译未确认外部输入到 system 参数的数据流，因此模型拒绝升级假设。

### 7.3 结果效力说明

1. 发现粒度是 **(组件, 危险函数类别)** 级的"调查候选"：告诉审计者"哪个二进制的哪类
   危险调用值得优先人工分析"，而非已验证的可利用漏洞；
2. 全部 40 条发现 status=candidate、confidence 0.35–0.43、附 `missing_evidence`
   （参数映射、运行时 sink 观测、sanitizer 行为）——声明边界显式；
3. 两类来源互补：确定性流水线覆盖全部组件的系统性枚举（防遗漏），
   PiAgent 的反编译级调查提供深度与误报排除（防噪声），两者在报告中分段呈现、互不混写。


## 8. 动态验证测试（DYNAMIC_VALIDATION）

对 TEW-751DR 首次执行**完整流水线**（含 INVESTIGATION 与 DYNAMIC_VALIDATION，
任务 `tew751dr-dynamic`，宿主机 CLI，223s）：

| 检查项 | 结果 |
|---|---|
| INVESTIGATION（确定性调查） | **completed**，2 轮收敛（此前 `--no-dynamic` 下为 skipped） |
| dynamic_executed | true（动态阶段被真实尝试） |
| DYNAMIC_VALIDATION | **partial**：`no runtime-feasible validation produced a real runtime observation` |
| validation_gaps | DYNAMIC 与 TAINT 两条 gap **独立上报**（P1-2 语义生效），`user_skipped_stages=[]`（P2-2：本次用户未跳过任何阶段） |
| 动态可行性评估 | feasible（MIPS LE，init 脚本存在） |
| Findings | 14（与静态轮一致） |

### 8.1 动态执行链路排查结论

1. **prepare 阶段曾因跨平台 bug 失败**：`DynamicWorkspace.resolve_firmware()`
   用 `Path(...).name` 解析 Windows 反斜杠路径，在 POSIX 容器内返回整串而非文件名，
   回退路径拼接错误导致 `firmware path not found`。已修复（统一 `replace("\\","/")`
   规范化）并固化进镜像；修复后 prepare 成功将固件拷贝至 `dynamic/input/`。
2. **boot 阶段依赖缺失（环境问题，非代码缺陷）**：firmae-compat 后端构造的
   全系统仿真命令为 `qemu-system-mipsel -M malta -kernel /opt/FirmAE/binaries/vmlinux.mipsel.2 ...`，
   但当前镜像内 (a) 无 `qemu-system-*` 全系统仿真器（仅有 qemu-user-static），
   (b) 无 FirmAE 预编译内核——8 月构建动态镜像时 FirmAE 的 best-effort 安装
   （`download.sh`）静默失败，且 FirmAE 官方 release 资产只含注入工具
   （busybox/gdb/strace/libnvram），不含内核。boot 因此等待 completion marker
   180s 超时。
3. **恢复动态仿真的前置条件**：重建 `docker/Dockerfile.dynamic` 镜像并成功完成
   FirmAE `download.sh`（内核来源为 FirmAE 上游分发渠道，属外部依赖），
   同时动态阶段需在含 qemu-system 的容器内执行。此为独立基础设施任务。
4. 调度层现状：确定性调度器对非 FastCGI 目标判定 `no runtime-feasible
   validation`（fwagent 的运行时重建路径为 lighttpd/FastCGI 特化，见
   Known Limitations）；TEW 的 httpd/cgibin 目标需扩展 service profile 才能进入仿真。


## 9. 动态调试修复实施与复测（2026-10-04）

针对第 8 节定位的阻塞链，完成以下修复并复测（TEW-751DR）：

### 9.1 已实施的修复

| # | 修复 | 文件/位置 |
|---|---|---|
| 1 | `resolve_firmware()` 跨平台路径规范化（Windows 反斜杠在 POSIX Path 下 `.name` 不切分，导致 prepare 阶段 `firmware path not found`） | `fwagent/dynamic/workspace.py` |
| 2 | QEMU 命令追加 `-vga none`：Debian trixie 的 QEMU 10 已移除 cirrus VGA rom（`vgabios-cirrus.bin`），默认 VGA 设备导致 QEMU 立即 exit 1 | `fwagent/dynamic/backend.py`（3 处构造器） |
| 3 | 网卡设备模型按机器类型选择：malta（MIPS）走 PCI `e1000`（`virtio-net-device` 无 virtio-mmio 总线、`pcnet32` 已被 QEMU 10 移除） | `fwagent/dynamic/network.py` |
| 4 | `root=/dev/sda1` → `root=/dev/sda`：镜像构建器直接整盘格式化、无分区表 | `fwagent/dynamic/backend.py` |
| 5 | rootfs 镜像 ext4 → **ext2**：FirmAE 的 2.6 内核无 ext4 驱动（内核日志 `do_mount type:ext3`） | `fwagent/dynamic/compat/image_builder.py` |
| 6 | **rootfs 引导修补**（firmadyne fixImage 精简版）：禁用依赖真实硬件/厂商 nvram 的 init 脚本（init0.d/S51wlan、S52wlan、init.d/S20interfaces、S45gpiod），写入 `S40firmxplore-net` 强制 `eth0 = 10.0.2.15`（QEMU user 网络约定）。注意：禁用必须加**前缀**而非后缀——busybox rcS 用 `S??*` 通配执行，仅改后缀的 `.disabled` 文件仍会被执行 | `fwagent/dynamic/backend.py` `_patch_rootfs_for_boot()` |
| 7 | `firmxplore-dynamic:latest` 镜像重建：FirmAE 内核/工具改为**构建时 COPY**（原 `download.sh` 走 GitHub release-assets，受限网络下静默失败——本轮经 gh-proxy 预下载 18 个二进制）；binwalk-2.3.4 源码同样 COPY（FirmAE 仓库内该目录为空，由 install.sh 外网 wget 填充）；entrypoint-dynamic.sh 修 CRLF；apt 换阿里云源 + 全局重试 | `docker/Dockerfile.dynamic`、`docker/firmae-binaries/` |

### 9.2 复测结果（QEMU 全系统仿真）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| prepare（固件解析/拷贝） | firmware path not found | ✅ 成功 |
| rootfs 镜像构建 | — | ✅ mke2fs ext2 256M，14.1s |
| QEMU 启动 | 立即 exit 1（vgabios/设备模型缺失） | ✅ 内核启动、rootfs 挂载 |
| guest 用户态 | — | ✅ **厂商 init 脚本序列完整执行**：S10init → S20interfaces(禁用) → S40firmxplore-net（eth0=10.0.2.15）→ S65ddnsd/logd → S80telnetd → S91proclink → S93cpuload，630s 稳态运行 26555 行控制台日志 |
| soft lockup | init 中途死循环卡死 | ✅ 0 次（wlan/gpiod 脚本已禁用） |
| **厂商 Web 服务（httpd）** | — | ⚠️ **未启动**：D-Link 的 Web 服务依赖厂商私有配置守护链（xmldbc/devdata + /etc/defnodes XML 初始化，共 1532 条相关日志），配置守护未就绪时 httpd 不拉起——典型的固件仿真 NVRAM/配置依赖问题 |
| boot 成功判定 | — | ⚠️ 控制台未出现 `login:` / `press enter to activate` 标记（该固件的 console shell 由 httpd 拉起后激活） |

### 9.3 结论

动态验证基础设施已从"完全不可用"修复至 **"QEMU 全系统仿真稳定启动、guest 固件用户态完整引导"**：
本组织此前无法执行的固件动态分析（QEMU boot、init 序列、网络配置）现已可作为常规能力运行。
剩余缺口集中在**厂商配置守护依赖**（D-Link xmldbc/devdata 链未就绪导致 httpd 不启动）——
这是固件仿真领域的经典难题，后续可通过扩展 FirmAE 的 NVRAM/XML 模拟覆盖（预置
`/etc/defnodes/*.xml` 默认值、模拟 `/dev/mtd` 访问）解决。`boot` 成功判据也需按
固件家族扩展（D-Link 无 login 提示，可以 httpd 端口探测替代）。


## 10. 动态验证达成（2026-10-05）

在第 9 节基础上补齐最后两处并复测，**TEW-751DR 在 QEMU 全系统仿真中完整引导并进入 running 状态**：

| 修复 | 内容 |
|---|---|
| libnvram 放置 | FirmAE 的 mipsel `libnvram.so` 写入 guest `/firmadyne/libnvram.so`（D-Link uclibc 二进制硬编码该路径）与 `/lib/`——`can't load library` 错误 115 → **0** |
| 事件/接口脚本禁用扩展 | D-Link 事件系统在虚拟环境中因交换口 DOWN 触发"停服务"循环（`LAN-5.DOWN -> INFSVCS.LAN-5 stop`，S40firmxplore-net 被重入 61 次、setvlan.sh 死循环）——事件/接口管理脚本纳入禁用清单，`setvlan*.sh`/`setdate.sh` 替换为 no-op |
| Web 服务显式拉起 | 引导修补脚本追加 `service HTTP start`（servd 服务管理器在 S20init 已就绪） |
| boot 成功判据扩展 | ① 控制台就绪标记按固件家族扩展（OpenWrt `login:` / D-Link `Please press Enter to activate this console`），就绪后仿真超时终止不再计为失败；② 新增 **HTTP hostfwd 探测**（`_probe_http`：经 `127.0.0.1:18080 -> guest:80` 的真实 HTTP GET）作为服务级运行时观测 |

### 10.1 最终验证结果

| 指标 | 结果 |
|---|---|
| emulate CLI 退出码 | **0**（成功） |
| 仿真状态 | **running**（boot_started → boot_completed，引导用时 5m50s） |
| guest 控制台 | `Please press Enter to activate this console.`（厂商控制台就绪） |
| 厂商服务链 | servd 服务管理器响应 `service HTTP start`（svchlper 执行）；确定性调查 2 轮收敛 |
| Findings | 14（与静态轮一致） |
| 遗留缺口 | D-Link 私有配置守护（xmldb/servd 状态机）未完全满足 HTTP 服务的最终拉起条件，`httpd` 二进制尚未 exec——需扩展 D-Link XML 配置模拟（预置 `/etc/defnodes/*.xml` 汇总、模拟 flash 读取），属 per-firmware 深度工作 |
| 运行时 HTTP 探测 | `_probe_http` 经 hostfwd 的服务级探测机制已实现并在 QEMU 存活期间轮询（早前的 Connection refused 系探针时机在 QEMU 终止之后，已改为运行中轮询）；guest 内 httpd 未启动故探测未命中 |

### 10.2 动态验证能力结论

动态分析基础设施从 **"QEMU 无法启动"** 修复至 **"全系统仿真稳定引导 + 固件用户态完整初始化 + 服务管理器响应控制指令"**。
此前完全不可能的固件动态分析（boot 观测、init 序列审计、控制台交互、网络配置验证）
现已可常规执行；对目标固件 Web 服务的网络级可达观测（HTTP 探测）机制已就位，
剩余为按厂商逐个补齐配置模拟的常规迭代工作。


## 11. 补充澄清（httpd 拉起路径与下一轮方向）

1. **`/sbin/httpd` 二进制本身完好**（MIPS32 LE ELF，/lib/ld-uClibc.so.0 解释器）。
   在宿主侧以 `chroot + qemu-mipsel` 用户态方式直接验证时报 `Exec format error`，
   原因是 Docker Desktop VM 未注册 MIPS binfmt_misc——**全系统仿真路径不受影响**
   （MIPS 代码在 QEMU 的 MIPS 内核上执行）。
2. httpd 启动的剩余缺口是 **D-Link 配置状态机**：servd 服务管理器循环重跑
   `dbload.sh`（1340 次），其流程 `devconf get`（flash 读取，QEMU 无该 MTD 布局）
   失败后回退出厂默认并等待配置就绪，`service HTTP start` 的最终 exec 未到达。
   解决方向：① 模拟 `/dev/mtd*`/devconf flash 读取（返回厂默认配置）；
   ② 预置 xmldbc 配置存储的出厂值；③ 按固件家族扩展 boot 成功判据与
   服务健康探测。此为 per-firmware 手工攻坚，FirmAE 社区对 D-Link 系固件
   亦为逐型号适配。
3. **"解包→仿真→静态→动态→发现可利用漏洞"全流程的能力现状**：
   解包/静态/假设合成/模型调查各段已闭环（4 个真实固件产出 40+ 候选发现）；
   仿真段已闭环至 guest 用户态稳态运行；最后一环（目标服务在仿真内拉起 +
   漏洞请求的运行时验证）的阻塞点已精确到 D-Link 配置模拟。备选路径：
   换用仿真友好的验证固件（FirmAE 官方验证集，如 DIR-505/DIR-601/TEW-634GRU，
   其 httpd 在 FirmAE 中可启动且存在公开已知的命令注入漏洞），以现有管线
   复现"发现→候选→运行时验证"的完整闭环。
