# 2026-10-22：应用 UID 下独立 `app_process` / `RuntimeInit` 线索

证据源：用户在本地保存的 `CNMB-runtime-logcat-private.txt` 中按临时进程 PID 检索所得的 2026-10-22 Logcat 文本。此仓库保留精简、脱敏的事件摘要，**不包含原始日志、设备标识或应用私有文件**。时间均为设备日志时间。

## 新观测

同一轮启动中，主进程启动、DEC 弹窗和终止已由 [ADB 映射/事件时间线](2026-10-22-adb-module-timeline.md) 记录。此前记为 D 的临时进程在 DEC 窗口启动之前出现了以下连续日志：

| 设备本地时间 | 脱敏后的观察 |
|---|---|
| 20:23:01.083–01.109 | D 的 `app_process`、`ExtensionsLoader` 及 OPPO 扩展框架初始化消息 |
| **20:23:01.111** | D 的 `AndroidRuntime` 输出 `START com.android.internal.os.RuntimeInit uid <app_uid>` |
| 20:23:01.115–01.127 | D 的 SELinux 日志字段 `app=<target package>`，提供与中国移动包的身份关联 |
| 20:23:01.131–02.177 | D 初始化 ART、Android 系统运行时和 `nativeloader` |

该 `RuntimeInit` 日志发生在：

- 主进程 `am_proc_start`（20:22:56.334）后约 **4.777 秒**。
- `DECMsgDialog` 的启动（20:23:05.609）前约 **4.498 秒**。

这条日志表明：存在属于应用身份的一个进程，执行了 `app_process` 所启动的 Java 运行时初始化。结合 Android 12 的 AOSP 启动框架，独立 app_process 可以选择 `RuntimeInit` 入口；这是**启动机制解释**，还不足以从本机证据识别实际入口 Java 类、启动命令行、父 PID 或调用者。AOSP 参考：

- [`frameworks/base/cmds/app_process/app_main.cpp`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android12-release/cmds/app_process/app_main.cpp)
- [`frameworks/base/core/java/com/android/internal/os/RuntimeInit.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android12-release/core/java/com/android/internal/os/RuntimeInit.java)

## 其他候选进程的证据边界

此前记为 B/C 的 PID，在提供的搜索结果中**仅看到** `adbd` 采样器对其 `/proc/PID/maps` 的读取请求。不能据此认定 B/C 执行了 ART、属于 DEC 工作线程或由某个特定父进程创建。

D 的 `Error reading ... boot.art`、`imageless running`、SELinux `avc: denied` 和 OPPO `ExtensionsLoader` 均属于实际日志事实；没有发现将它们与 DEC 风险判定或退出直接相连的调用链。尤其不能将日志中的 `uid`、`scontext` 直接解释成 Root 检测命中。

另外，`adbd service requested '...cat /proc/<PID>/maps'` 是本轮取证命令自身留下的日志，不能把它算成应用自检动作。

## 已纳入的离线验证

`experiments/parse_runtime_events.py` 现在仅在**同一日志 PID** 存在明确 `app=<target package>` 的环境审计记录时，才把 `AndroidRuntime` 的 `RuntimeInit` 启动归属于目标应用。这种关联是一项审慎过滤规则；如果原始日志缺少审计记录，工具会放弃归属，而非猜测。

```powershell
python .\experiments\parse_runtime_events.py .\CNMB-runtime-logcat-private.txt
```

预计可额外输出 `app_process_runtime_init` 类型事件；实际是否输出，仍以用户本地完整日志解析结果为准。代码测试采用合成日志，不引入原始用户记录。

## 现有日志的进一步离线检查（无需重新启动）

增加了只读工具 [`experiments/profile_runtime_worker.py`](../experiments/profile_runtime_worker.py)。它只分析**同一 PID 发出的**日志行，输出消息时间范围、日志标签计数和经严格白名单过滤的运行时事件；不会包含原始日志正文、路径、参数或设备隐私内容。

```powershell
python .\experiments\profile_runtime_worker.py .\CNMB-runtime-logcat-private.txt --pid 9187
```

若日志中有显式 `Calling main entry` 信息，工具会记录 Java 类名及时间；若没有，只报告 `has_explicit_main_entry_log=false`。这不意味着该进程没有 Java 入口，日志本身可能没有打印该信息。

下一轮可选纯 ADB 采样添加 `--parentage`，以 `ps -A -o PID,PPID,NAME` 读取进程父 PID：

```powershell
python .\experiments\capture_loaded_modules.py --launch --parentage --seconds 18 --poll-seconds 0.5 --output .\loaded-modules-parentage-local.json
```

该命令会重启目标应用，需在确认 Frida Server 已停止后执行；输出留在本地。PPID 是**采样瞬间的父进程**，若原始创建者已退出、进程已被重新托管，观测到的 PPID 也可能已变化。工具仅进行 ADB 查询，不能从 PPID 直接推导所执行的 Java 类。

## 可选：短命进程的 PPID 与 Java 入口探针

新增 [`experiments/capture_worker_identity.py`](../experiments/capture_worker_identity.py)，优先查询确切匹配目标包名的 PID、PPID，然后尝试读取对应 `/proc/PID/cmdline`，仅保留：

- 相对采样秒数和目标 PID、采样时 PPID；
- `argv0` 的概括类型（`app_process`、应用包名或其他）；
- 属于有限可信命名空间、最后一段符合 Java 类命名习惯的入口类**候选**。

工具不会存储原始 argv、应用参数或任意命令行文本。即使取得了一个 Java 类名，仍需将其与启动期间的日志或字节码匹配，才能确认它确实被调用。内核可能已经覆盖 argv，读取失败也不能当作不存在入口。

```powershell
python .\experiments\capture_worker_identity.py --launch --seconds 18 --poll-seconds 0.25 --output .\worker-identity-local.json
```

`--launch` 会停止再启动目标应用，因而仅在确实需要重测时使用。实测期间需要 ADB 授权和读取目标进程 `/proc/PID/cmdline` 的权限。该工具的取证流程目前仅通过合成样本测试，**尚未在目标手机上实际执行**。此前的离线 `profile_runtime_worker.py` 仍是首选。

## 后续证据需求

先从当前已有日志确认 D 的后续加载与退出阶段；再开展新一轮**纯 ADB** 实验获取短生命周期进程的真实 `PPID`、命令行入口类名及启动/退出时钟。由于旧记录没有保存这些字段，事后无法仅凭 PID 数字恢复父子关系。

目前 `DeviceEnvironmentCheck.startCheck()` 的方法体及调用者归属依然没有直接证据；`app_process` 的独立启动不能自动算作 DEC 的检测执行。


## 2026-10-22 第二轮：直接观察到主进程的子进程

用户在完成第一轮 Logcat 离线分析后，执行只读监测脚本 `experiments/capture_worker_identity.py --launch --seconds 18 --poll-seconds 0.25`，提供了工具输出的脱敏 JSON。主机 UTC 采样锚点是 `2026-10-22T13:19:32.192158+00:00`，**仅用于识别这一轮实验，未与设备时钟同步**。

| 观测时间（主机采样相对秒） | 进程代号 | 实测父 PID | 命令行类别 | 后续观测 |
| --- | --- | --- | --- | --- |
| +0.33 | A（主进程） | 862，身份尚未核实 | 已改名为应用包名 | +12.17 从 `ps` 消失 |
| +0.41 | B | A | 已改名为应用包名 | +2.01 从 `ps` 消失 |
| +1.04 | C | A | 已改名为应用包名 | +12.17 从 `ps` 消失 |
| +4.07 | D | 1 | 已改名为应用包名 | +4.33 从 `ps` 消失 |

以上 PID 的完整对应关系，均来自用户的实测输出。本报告用 A–D 表示进程身份，避免在公开文档保存短生命周期数字标识。

### 证据等级

- **直接证明**：B/C 在采样瞬间属于 A 的直接子进程，因为其实际 PPID 与 A 的 PID 相等。应用启动后确实存在多个进程。
- **直接证明**：D 在 +4.07 秒观测时，其 PPID 为 1。此前创建者可能已经退出并触发重新托管；**无法从本次记录倒推出初始 PPID**。
- **直接证明**：四个进程的 `argv0` 已经被设置为目标包名。脚本保留的 Java 入口类候选全部为 `null`，这只说明本次未能从白名单参数识别。
- **不得推断**：A 的 PPID 862 是 Zygote、B/C/D 是同一种加固工作进程、D 与上一轮出现的独立 `RuntimeInit` 进程属于同一功能，或其代码执行了 `DeviceEnvironmentCheck.startCheck()`。
- **间接线索**：D 在约 +4 秒出现；上一轮受应用身份佐证的 `RuntimeInit` 进程在主进程启动后约 4.777 秒有初始化日志。两次实验起始时钟不同，不能将这两个时间点直接精确对齐。

### 时间边界

`not_in_ps` 意味着脚本后续轮询未找到该 PID，**不是精确死亡时刻**。A/C 在同一次观察中消失，可能与主进程退出阶段有关，但需要新一轮 Logcat 的 `am_proc_died`、DEC 活动事件交叉验证。

这轮可先使用已保存的 `worker-identity-local.json` 和设备仍存的 Logcat，离线关联 A–D 的事件，无需再启动应用。工具见 [`experiments/correlate_worker_session.py`](../experiments/correlate_worker_session.py)。若环形日志已覆盖，报告应明确“缺失”，不进行插值。

### 下一个证据问题

优先确认第二轮 D 是否也出现 `app_process / RuntimeInit`、它的原生加载路径与退出事件；确认 D 的创建者需要其**首次被重托管之前**的 PPID 观测或操作系统创建事件。分析完成前，`DeviceEnvironmentCheck.startCheck()` 的方法体与 D 的调用关系仍未得到验证。

在完成本次实测后，已提供 [同轮取证关联工具](../experiments/correlate_worker_session.py)。它联合本地 `worker-identity-local.json` 与**第二轮**仍可读取的 Logcat，识别同一主 PID 的 `am_proc_start` 后只处理附近时间窗口。旧文件 `CNMB-runtime-logcat-private.txt` 来源于上一轮启动，不能直接作为本次实验的对应日志。如果 Android 缓冲区中已经没有第二轮主进程启动事件，工具会返回 `device_log_anchor=null`，不猜测其余事件归属。命令见 [README](../README.md)。

## 第二轮 Logcat 确认：D 与第一轮的 RuntimeInit 行为高度重复

同一轮的 `worker-identity-local.json` 经 [`experiments/correlate_worker_session.py`](../experiments/correlate_worker_session.py) 联合**第二轮 Logcat** 核对，找到了精确匹配主 PID 的 `am_proc_start`：`10-22 21:20:10.815`。这是设备自身的统一时钟锚点，避免拿宿主机相对秒数与 Android 系统时间硬对齐。

| 事件 | 第一轮（设备时间） | 第二轮（设备时间） | 各自相对主进程启动的时间 |
|---|---|---|---|
| 主进程启动 | 20:22:56.334 | 21:20:10.815 | 0 |
| D 的首条日志 | 20:23:01.083 | 21:20:15.535 | +4.749 s / +4.720 s |
| D 的 `RuntimeInit` | 20:23:01.111 | 21:20:15.564 | **+4.777 s / +4.749 s** |
| `DECMsgDialog` 启动 | 20:23:05.609 | 21:20:19.976 | +9.275 s / +9.161 s |
| DEC 显示完成 | 20:23:05.818 | 21:20:20.140 | +9.484 s / +9.325 s |
| 主进程死亡 | 20:23:09.310 | 21:20:23.192 | +12.976 s / +12.377 s |

两个 D 进程都恰有 **37 条该 PID 发出的日志**，而且两轮提供的标签计数完全相同：`app_process=16`、`AndroidRuntime=5`、`ExtensionsLoader=4`、`nativeloader=4`、`auditd=2`、`zygote=2`、`libc=1`、`hw-ProcessState=1`、`ProcessState=1`、`OplusUtils=1`。两轮提取器还都识别到了同一顺序的 `libicu_jni.so`、`libjavacore.so`、`libopenjdk.so` 系统库加载。

因此，**额外 `app_process / RuntimeInit` 进程及其在主进程启动约 4.75 秒后初始化，是两轮重复证实的启动行为**。两轮的 `RuntimeInit` 相对时刻只差 **28 ms**；这属于时间相关性与日志特征证据，尚不能证明该进程是 DEC 的检测执行者。

本轮新增的父进程关系：

- B/C 在实际采样时 PPID 指向主进程 A，**确认两个直接子进程**。
- D 在 +4.07 主机相对秒时第一次被捕获，PPID 已经为 `1`，其原始父进程身份**无法恢复**。
- D 的首条设备日志出现于其 `RuntimeInit` 日志前 29 ms，且距离 DEC 启动约 4.441 秒；**不代表 D 的启动命令和源码调用已经找到**。
- 这个进程的入口类依然没有从 `/proc/PID/cmdline` 或现有 Logcat 中恢复，`has_explicit_main_entry_log=false` 是“未观测到”的结论。

第二轮 `process_log_profiles` 还显示 B/C 的 `lines=0`：只是所给 Logcat 时间窗口内没有这两个 PID 自己发出的匹配日志，不能认定它们没有执行代码。

**下一步需要的证据**：D 最初 fork/exec 的创建事件或可信的 `RuntimeInit` 入口；再沿真实代码或调用记录判断与 `DeviceEnvironmentCheck.startCheck()` 的关联。现阶段不再以“这两个进程在时间上接近”替代调用证明。

## 原始 `forked` 字符串归属纠正

对 SHA-256 固定的 12.5.5 原始 `libdatajar.so`，恢复可见字符串索引表 `0x729300c`（Dex 相对基址 `0x727300c`）后，两个进程相关字符串可直接归属：

| 原文字串 | Dex string ID | `const-string/jumbo` 候选 SO 文件偏移 |
|---|---:|---|
| `[DEBUG] Current process is forked from` | 37635 | `0x79e8fda` |
| `forked from pid:` | 49851 | `0x79e9022` |

它们都在 `Lcom/alipay/mobile/common/logging/CrashBridge;` 的 `isForkedCrashOnlyForTracing` 方法中（Dex method ID **46925**，`code_item @0x79e8f88`）。这是**支付宝 SDK 的崩溃日志代码**；无法因此将这两条字串与 D 的创建流程、SecNeo 加固或 DEC 直接关联。

对相同方法体进一步验证，另外两条 `const-string/jumbo` 分别包含 `Process Name: 'com.eg.android.AlipayGphone'`（SID 30484，SO `0x79e8ff2`）和 `Thread Name: 'DFSDump'`（SID 35129，SO `0x79e900a`）。原生指令引用还包括：

- `java.io.StringReader.<init>`，SO `0x79e8fb2`；
- `java.io.BufferedReader.<init>`，SO `0x79e8fbc`；
- `BufferedReader.readLine`，SO `0x79e8fcc`；
- `String.startsWith`，SO `0x79e8fe0`。

这些方法调用和日志行前缀串构成了更强的原版证据：`isForkedCrashOnlyForTracing` **读取并筛查崩溃日志文本**。已恢复的该方法直接调用里没有 `fork`、`execve` 或新的 `app_process` 启动。这里没有证明任何实际创建 D 的代码。



可使用 [`tools/audit_fork_log_owner.py`](../tools/audit_fork_log_owner.py) 在固定原版 APK/SO 上复核；它验证方法所有者、类定义、方法体地址与这两处固定的字符串指令候选。字符串归属不等于执行证据。
