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
