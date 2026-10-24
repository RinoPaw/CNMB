# CNMB

中国移动 Android 客户端设备环境检查与加固行为研究。主要研究对象：`com.greenpoint.android.mc10086.activity`。

本仓库记录**可复核的静态证据和实验观察**，将已验证事实、技术推断和待验证问题分开。研究优先使用 APK 原始字节、Android Manifest、DEX 指令、ELF 结构、系统日志与 Tombstone，不把第三方逆向结论直接当作当前版本事实。

## 当前进度

- 中国移动 12.5.5 APK 的 SecNeo 启动桩、Manifest 中的 `DECMsgDialog` 和若干代码字符串已完成初步定位。
- `classes.dex` 中确认存在读取 `/proc/self/status`、解析 `TracerPid:` 的实现，但**没有证据证明其直接触发 Root 弹窗**。
- 已恢复并验证 **14 组** Dex 元数据表，覆盖 101,716 条类定义记录；能重建部分被遮蔽的字符串索引，确认 `CmccApplication.onCreate()` 调用 DEC 初始化，并恢复 `RootBeer` 的具体检查实现。
- `DeviceEnvironmentCheck.startCheck()` 的方法体仍未定位：14 组片段中其类只有引用、没有定义；`RootBeer` 在对应片段中没有外部直接调用点，**尚无证据表明它触发 DEC 警告**。
- 原版另含 ZIP 包装的 `libZWRiskComm` 风险 SDK，内层 ELF 有确切反 Frida 字符串；目前未证明它介入 DEC。`0x978` 崩溃 Tombstone 记录到 `libDexHelper.so` 和匿名 `rwx` 映射，但缺失原生代码归属证据。
- 在 OPPO CPH2127 / Android 12 上，干净重启后的 DEC 弹窗与 Frida 服务端运行时的原生崩溃属于两类不同的观测结果。崩溃的具体触发代码尚未定位。
- 两轮独立实测都观察到额外 `app_process / RuntimeInit` 在主进程启动约 **4.75 秒**后初始化；第二轮通过 PPID 证实主进程至少有两个直接子进程，另有一进程在首次采样时 PPID 已为 1。两轮随后均显示 DEC 警告并结束主进程，**时间相关性尚不足以证明检测调用**。
- 原版 ELF 的 `libDexHelper.so` `DT_INIT_ARRAY` 经重定位指向 `0x4780` 构造函数；它与 `libdexjni.so` 的可执行段末尾共享 9,030 字节（两库偏移差 `0x2000`）。该构造函数含回溯查找 ELF 头的真实指令；尚未证明它执行 DEC 检测。
- **原版受保护内层 ELF 已成功离线复原。** 内层 `libDexHelper.so` 导入 `fork/execl`，已确认 `JNI_OnLoad:0x16990` 调用注册函数 `0x1DF7C`，把 `0x4E1C8` 写入回调表；该回调函数具备 `pthread_create(…,0x59700,…)` 调用，线程入口内执行双重 `fork` 和 `execl("/system/bin/app_process",…)`。已恢复 `--nice-name=zygote`、`--write-fd`、`--flags 0` 等实际参数；Java 主类已在后续原版数据流中确认默认值为 `com.secneo.apkwrapper.H`，可被运行时配置覆盖。现已恢复回调表的分发线程及条件：初始化配置字段 `+0x4A` 非零时设置位 `0x04`，分发线程调用回调表 `+0x20` 槽，静态路径闭合至双重 `fork`；实际配置值与设备 PID 对应仍需验证。
- **辅助 `app_process` 默认 Java 主类已恢复**：原版内层 ELF 的逐字节构造及堆对象字段数据流证明，默认入口为 `com.secneo.apkwrapper.H`；同一对象 `+0xE0` 字符串被作为 `execl` 的 `x4` 参数。运行时 `config+0x200/+0x208` 允许覆盖，此前两轮设备日志未打印入口类；新核验的一轮重启日志已明确打印实际 Java 入口 `com/secneo/apkwrapper/H`，但它与原版 `fork/execl` 静态路径的 PID 级对应仍待证明。验证工具：[原版入口与参数审计](tools/audit_inner_java_entry.py)。
- **原版内置配置值已验证**：`JNI_OnLoad` 使用 XOR `0xAC` 解码 MessagePack 配置，其第 15 项（流偏移 `+63`）为 `true`，经 `0x14C2C` 写入静态配置 `+0x4A`。后续初始化器的 `+0x4A` 字段来源于另一运行时指针，复制或修改关系仍待核实，不能直接推定实际运行中的标志值。工具：[MessagePack 配置审计](tools/audit_inner_spawn_config.py)。
- 已通过原版 PLT/JUMP_SLOT 精确证明构造函数使用 `dlopen("libc.so",2)` 和 `dlsym("sscanf")`，随后进入 `0x33f8`，通过 `fopen/fgets/sscanf` 解析 `/proc/self/maps`，再执行原生内存映射/权限配置流程。此链属于原版装载行为；尚未定位 DEC 检测条件。
- 原版 APK 全部 191 份 ARM64 SO 中，**174 份**含逐字节相同的 2,564 B 装载辅助核心（其中 10 份多匹配一个字节），附带 `/proc/self/maps`、`mprotect(RWX)`、缓存刷新及九条系统调用封装；该段还有 `__b_a_n_g_c_l_e__check1234567_` 原版签名。此为**共用保护代码证据**，尚未与 DEC 判定建立调用关系。
- 先前原版 SO 中的 `forked from pid:` 及 `Current process is forked from` 已通过 Dex 方法归属和指令核实：它们属于支付宝 `CrashBridge.isForkedCrashOnlyForTracing` 的日志文本解析逻辑，不能作为 SecNeo 创建子进程的证据。

详细报告：[静态取证报告](docs/12.5.5-static-analysis.md)；[DEC Dex 方法调用链](docs/12.5.5-dec-dex-callgraph.md)；[DEC 生命周期](docs/12.5.5-dec-startup-lifecycle.md)；[CmccApplication → DEC 启动连接](docs/12.5.5-cmcc-dec-bridge.md)；[受保护字符串与 RootBeer](docs/12.5.5-dex-string-recovery-rootbeer.md)；[14 组 Dex 元数据扫描](docs/12.5.5-fourteen-dex-census.md)；[原版进程操作与 ARM64 系统调用审计](docs/12.5.5-native-and-dalvik-process-surface.md)；[174 份 ARM64 库共用装载尾段](docs/12.5.5-shared-native-loader-tail.md)；[DexHelper 加载构造函数与 dexjni 共用引导代码](docs/12.5.5-dexhelper-native-constructors.md)；[DexHelper PLT 与映射加载链](docs/12.5.5-dexhelper-plt-maps-loader.md)；[内层 ELF 复原与 fork/execl 创建 app_process](docs/12.5.5-nested-elf-recovery-process-spawn.md)；[完整 app_process 参数与 JNI→线程→fork 静态路径](docs/12.5.5-inner-app-process-argv-thread-chain.md)；[原生加载与崩溃阶段](docs/12.5.5-native-loader-crash-stage.md)；[动态对照记录](docs/2026-10-22-dynamic-observations.md)；[重启日志确认 H Java 入口](docs/2026-10-22-runtime-h-entry-confirmation.md)。

## 复核

Python 3.9+，仅使用标准库：

```powershell
python .\tools\offline_audit.py .\path\to\base.apk
# 或传入包含 apks/01-base.apk 的诊断 ZIP
```

脚本只读输入文件，并输出 APK 哈希、加固启动桩、相关 Manifest 组件及明文字符串命中。

### SecNeo 受保护 Dex 的局部恢复

对 12.5.5 原始 `libdatajar.so`，已确认多个可恢复 Dex 片段、被遮蔽字符串索引的反向恢复方法，以及跨 Dex 的真实 Application 启动调用：

```text
CmccApplication.onCreate()
  -> CmccApplication.DEC_origin_onCreate()
  -> DECApp.intiDECabcOnCreate(Application)
      -> isMainProcessDECabc()  // /proc/<pid>/cmdline
      -> DeviceEnvironmentCheck.startCheck()  // 方法体仍未恢复
```

`startCheck` 的方法体尚未恢复，但现在能证明真实应用的 `onCreate()` 已静态接入 DEC 初始化，并能独立审核 RootBeer 检查实现。所有工具只读，并严格校验样本 SHA-256：

```powershell
python .\tools\inspect_dec_tables.py .\path\to\base.apk
python .\tools\audit_dec_callers.py .\path\to\base.apk
python .\tools\inspect_cmcc_dec_bridge.py .\path\to\base.apk
python .\tools\inspect_rootbeer.py .\path\to\base.apk
python .\tools\carve_all_dex.py .\path\to\base.apk
python .\tools\audit_fork_log_owner.py .\path\to\base.apk
python .\tools\audit_process_calls.py .\path\to\base.apk
python .\tools\audit_native_svc.py .\path\to\base.apk
python .\tools\audit_shared_native_tail.py .\path\to\base.apk
python .\tools\audit_protector_constructors.py .\path\to\base.apk
python .\tools\audit_dexhelper_plt.py .\path\to\base.apk
python .\tools\audit_dexhelper_symbol_fallback.py .\path\to\base.apk
python .\tools\audit_nested_elf.py .\path\to\base.apk
python .\tools\audit_inner_app_process_argv.py .\path\to\base.apk
python .\tools\audit_inner_spawn_thread.py .\path\to\base.apk
python .\tools\audit_inner_spawn_config.py .\path\to\base.apk
python .\tools\audit_inner_java_entry.py .\path\to\base.apk
```

### 原生加载阶段检查（离线）

```powershell
python .\tools\inspect_native_loader.py .\path\to\diagnostic.zip --tombstone .\path\to\tombstone.txt
```

只读展开 APK 及 ZIP 包装的 ELF，核验目标 SO 的静态字面量及崩溃时已映射的库；仅输出脱敏 JSON 摘要。

## 实验脚本

`experiments/process_lifetime.py` 可以通过 ADB 监视主进程启动和退出，不需要 Frida：

```powershell
python .\experiments\process_lifetime.py --monitor-only --observe-seconds 25
```

可选的 `--trace` 加载 `experiments/dec_trace.js`，仅在已经确认动态注入可用、且接受目标进程可能崩溃的测试环境中使用；它需要匹配版本的 `frida` Python 包与服务端。当前设备上**无脚本的 Frida 服务端也曾伴随 Native Crash**，不要将崩溃自动归因为特定 Root 检测规则。

### 只用 ADB 采样运行时加载状态

在已连接、具有读取目标进程 maps 权限的设备上，先保证 Frida 服务端没有运行。以下操作会停止并重新启动中国移动，连续采样 18 秒：

```powershell
python .\experiments\capture_loaded_modules.py --launch --seconds 18 --poll-seconds 0.5 --output .\loaded-modules-local.json
```

采样器保留相对时间、PID、映射库的文件名、匿名可执行区统计，不保存完整设备内存映射或绝对安装路径。输出仅在本地保存，不应直接提交原始取证数据。**2026-10-22 已完成首次设备实测。** 原始采样发现与旧 Tombstone 相同字节数的匿名 RWX 区域，同时暴露了旧版脚本误将空 `maps` 判为卸载的问题，已修正。详情见 [ADB 模块映射时间线](docs/2026-10-22-adb-module-timeline.md)、[应用 UID 下的 RuntimeInit 进程](docs/2026-10-22-app-process-runtime-init.md)。

已经保存的采样可在不连接手机的情况下生成简洁摘要：

```powershell
python .\experiments\capture_loaded_modules.py --from-json .\loaded-modules-local.json
```

新版工具会跳过空 `maps` 并单独记录采样不可用；若旧版输出已出现全空快照，应视为无效观测，参见分析报告。

### 提取 DEC / 进程 / Native Crash 事件（离线）

保留完整原始日志仅在本地，脚本只输出时间、事件类型和可验证的 PID / 信号信息，不打印原始 Intent 内容：

```powershell
adb logcat -d -v threadtime -b main -b system -b events -b crash |
    Set-Content -Encoding utf8 .\CNMB-runtime-logcat-private.txt

python .\experiments\parse_runtime_events.py .\CNMB-runtime-logcat-private.txt
# 已验证会识别 DEC 事件及具有同 PID 应用身份佐证的 RuntimeInit 启动
```

如果原始实验期间的日志已经从 Android 环形缓冲区中被覆盖，必须在下一轮实验重新采集；**当前模块采样仅记录了主机相对时间**，缺少绝对时钟锚点，无法可靠地与旧 Logcat 时间进行亚秒级对齐。

### 独立 app_process 进程取证

在既有日志中，PID `9187` 的 `RuntimeInit` 和同 PID 的应用身份审计已核实。优先复核其自身日志，无需重新启动手机：

```powershell
python .\experiments\profile_runtime_worker.py .\CNMB-runtime-logcat-private.txt --pid 9187
# 对另一轮重启日志，该工具也能识别 AndroidRuntime 的 slash-form Java 入口：
python .\experiments\profile_runtime_worker.py .\CNMB-after-reboot.txt --pid 8714
```

仅在需要进一步确定父进程时，使用新采样器的 `--parentage` 参数（`--launch` 会重新启动应用）：

```powershell
python .\experiments\capture_loaded_modules.py --launch --parentage --seconds 18 --poll-seconds 0.5 --output .\loaded-modules-parentage-local.json
```

`PPID` 是取样时的父进程，可能因为进程重托管而不同于原始创建者；日志缺少显式入口类时不能猜测其身份。完整说明见 [RuntimeInit 进程报告](docs/2026-10-22-app-process-runtime-init.md)。

### 可选：捕获临时进程入口候选

如果现有 PID 9187 的离线日志未包含显式 Java 入口类，需要重新取证时可使用**独立的纯 ADB 工具**：

```powershell
python .\experiments\capture_worker_identity.py --launch --seconds 18 --poll-seconds 0.25 --output .\worker-identity-local.json
```

该工具记录目标进程的 PPID 和经过严格筛选的 Java 入口类**候选**；不会保存原始 `/proc/PID/cmdline` 或启动参数。读取不到候选并不能证明不存在入口。必须在确认设备已连接、Frida Server 停止后使用；`--launch` 会重启目标应用。完整局限参见 [RuntimeInit 研究记录](docs/2026-10-22-app-process-runtime-init.md)。

### 关联第二轮进程身份和 DEC 日志

2026-10-22 第二轮实测已确认主进程的两个子进程（PPID 直接指向主 PID），以及首次捕获时 PPID 已为 `1` 的独立短命进程。先保存**新一轮**手机现存 Logcat，不会重启 App：

```powershell
adb logcat -d -v threadtime -b main -b system -b events -b crash |
    Set-Content -Encoding utf8 .\CNMB-runtime-logcat-2119-private.txt

python .\experiments\correlate_worker_session.py `
    --identity .\worker-identity-local.json `
    --logcat .\CNMB-runtime-logcat-2119-private.txt
```

分析器要求新日志中具有对应主进程 PID 的 `am_proc_start`，才选取该轮的设备本地时间窗口；若已被覆盖，则拒绝关联旧的 DEC 日志。输入与输出都是本地取证材料，仅公开脱敏后的事实。主机相对采样秒数与手机 Logcat 时间不能直接精确相减。

### 重启日志中 H 入口与 DEC 启动的同轮关联

2026-10-22 15:25 这轮原始日志已在独立 PID 的 `AndroidRuntime` 中观察到 `Calling main entry com/secneo/apkwrapper/H`。同轮 OPPO 窗口路由日志在 DEC 启动后 12 毫秒记录了主进程的 `callingPid`，主进程 PID 也由 `ActivityManager` 启动记录佐证。现有证据仍未确认两个进程的实际父子创建路径或 DEC 检测通信。

使用只读工具将 *同一次启动* 的主进程启动、辅助进程身份和 Java 入口、DEC 启动进行严格关联：

~~~powershell
python .\experiments\correlate_reboot_h_entry.py .\CNMB-after-reboot.txt
# 或使用原始日志在本机的绝对路径，无需复制到仓库：
python .\experiments\correlate_reboot_h_entry.py "$HOME\Downloads\CNMB-after-reboot.txt"
~~~

工具拒绝跨天拼接和多会话歧义，输出仅含允许的 PID、UID、时间与证据边界。原始日志保留在本地。 **`CNMB-after-reboot.txt` 是私有设备日志，不包含在 GitHub 仓库中。使用前须从之前保存的原始采集文件恢复；若路径不存在，工具会给出明确的缺失文件提示。**详情：[H 入口与路由核验](docs/2026-10-22-runtime-h-entry-confirmation.md)。

### TracerPid 回传后的原版 native 分支

在原始内层 `libDexHelper.so` 的 `0x5ae38`，接收到的 `H` 结果交给 `atoi`；`0x5ae3c/0x5ae40` 对其执行 `cmp w0,#1` 和 `b.lt 0x5af6c`。当结果 `>=1` 时，`0x5ae50/0x5ae54` 读取运行时对象的 `+0x17c` 字节并检查 bit 0。bit 0=1 跳至 `0x5af18`；bit 0=0 分支包含将 `SP/LR` 置零并通过 `br x10` 跳至低地址 `0x1f8` 的原版机器指令。稍后的 `0x5b344` 存在相似的 bit 0 判断，其另一分支目标为 `0x1f0`。**这些是已验证静态路径，尚未证明设备曾实际执行，也尚未证明 DEC/Frida 归因。** [全部地址与边界](docs/12.5.5-secneo-h-result-guard-branch.md)；[只读验证工具](tools/audit_inner_h_result_branch.py)。

### TracerPid 阳性后的条件文件读写

进一步审计原版内层 ELF 确认，在 `TracerPid>=1` 且运行时配置 bit0=1 后，`0x2616c(1)` 构造记录键 `root`，`0x2682c` 从 `envc.push` 读取已有状态；满足条件时 `0x5af68` 调用 `0x26bc0` 更新同一个文件。后者具有 `access/fopen/flock/fgets`、数据比较和有条件的 `fseek/fwrite/fflush` 流程。**文件名和记录键已获原版证实**；目录前缀仍属于运行时数据，设备是否实际写入及 DEC 因果关系尚未证明。 [完整静态证据](docs/12.5.5-secneo-h-positive-file-update.md)；[只读原版审计](tools/audit_inner_h_followup_file_io.py)。

进一步复核 83/84/48 个直接调用点时，已另外逐条确认**五处** `root` 状态读取后条件更新的静态路径，其记录标识分别为 `0xb6a281f2`、`0xb6a281f3`、`0xb6a281f5`、`0xb6a281f7`、`0xb6a281f8`。这些标识不能直接解读为风险类别，也不代表五次设备执行。[五处原版调用点审计](tools/audit_inner_root_record_sites.py)；[证据表](docs/12.5.5-secneo-h-envc-push-root-record.md)。

### 原版配置进一步闭合：`+0x17c` 的初始值为 13

通过原版 ELF 中 `JNI_OnLoad` 的数据流和 `R_AARCH64_RELATIVE` 重定位，现已证明 `0x5ae50` 访问的配置字段位于原始静态对象 `0x12a440+0x17c=0x12a5bc`。原版 `0x12415b` 的配置字节流经 `0xac` XOR 解码，48 次 MessagePack 读取调用中的 `0x14d88` 将 **整数 13** 写入该字段。初始化 bit0=1，所以在后续字段未变且 `TracerPid>=1` 时，条件跳转优先进入 `0x5af18`：依次调用 `0x2616c`、`0x2682c`，并在两段条件允许时进入 `0x26bc0`。原版 `0x3af48` 写的是另一 BSS 地址 `0x12b17c`，已排除此前的别名猜测。

**这些均为初始化和静态控制流证据**；字段可能发生运行时修改，尚不能对真实设备的崩溃、DEC 弹窗或上层业务含义做归因。[完整配置、指针与后续函数审计](docs/12.5.5-secneo-h-guard-config-alias.md)；[验证工具](tools/audit_inner_h_guard_config.py)。

### 原版 SecNeo H 检查结果的双向管道链路（2026-10-24）

原版 `classes.dex` 与恢复的内层 ELF 已分别独立验哈希，并恢复出一条**静态闭合**的 SecNeo 辅助进程检查通信链：

- 原生工作线程构造匿名管道，通过 `--write-fd <FD> --flags 0` 把写端传给默认 `com.secneo.apkwrapper.H`；
- `H.main` 使用 `ParcelFileDescriptor.adoptFd`，经 `H.b(0)` → `H.a(0)` 读取 `/proc/self/status` 的 `TracerPid`，用 `DataOutputStream.writeUTF` 回传结果整数的十进制文本；
- 父端把同一管道读端通过 JNI `ParcelFileDescriptor.adoptFd` → `AutoCloseInputStream` → `DataInputStream.readUTF` 读取，随后 `GetStringUTFChars` → `atoi` 并以 `>=1` 为条件分支。

这是原版检查结果 IPC 的代码级证据，尚未证明它就是 `DeviceEnvironmentCheck.startCheck()` 或 `DECMsgDialog` 的触发路径。设备 FD 动态采样已证实受访问限制：Root Shell 可读自身 FD，无法读取目标 App FD；后续不再要求重复同样的失败采集。完整地址和原始指令见[SecNeo H 管道链分析](docs/12.5.5-secneo-h-pipe-result-chain.md)。

~~~powershell
python .\tools\audit_secneo_h_ipc.py .\path\to\original-base.apk
python .\tools\audit_inner_h_pipe_receiver.py .\path\to\original-base.apk
~~~

### sw/bs 的进程身份检查及初始配置字节（2026-10-24）

原版 `libDexHelper.so` 中，`sw(Context,int)` 和 `bs(Context,int)` 在各自 `PC_FLAG` 位检查允许继续后，都调用 `0x2BF68`：它根据 `getpid` 构造并读取 **`/proc/<自身PID>/cmdline`**，与运行时配置的期望进程名比较。两个调用点只允许**检查返回零**的分支继续；还要求身份对象的 `+0x0C` 字节非零。

已从原版 ELF 的 `R_AARCH64_RELATIVE` 重定位与初始化指令闭合该身份对象：原始静态地址 `0x12A684` 经全局指针槽 `0x128008` 发布；它的 `+0x0C` 位于 `0x12A690`。原版 XOR/MessagePack 配置 `+0x4A` 为 **true**，会将该字节初始化为 **1**，运行时修改仍未排除。默认 `PC_FLAG=255` 已率先阻止调用；若运行时改变参数，进程身份检查仍是另一道独立守卫。[完整原版指令与证据边界](docs/12.5.5-secneo-h-process-identity-gate.md)；[只读复核工具](tools/audit_inner_h_process_identity_gate.py)。

### SecNeo Messenger Service 绑定路径及默认守卫（2026-10-24）

原版 H 类初始化把 `PC_FLAG` 设置为字符串 **`"255"`**，`AW.onCreate` 调用的 `H.callSW/ H.callBS` 会解析该值传入原生方法 `sw/bs`。内层 ELF 证明 `sw` 的 bit0（`0x2C46C`）和 `bs` 的 bit1（`0x2C90C`）为 1 时提前返回；初始值 `255` 同时满足两项，因此**不能宣称原版默认启动就会建立 Messenger 的 Service 连接**。后续可能的运行时参数变更尚未排查。

通过原版 JNI 代码完整恢复被守卫的服务绑定流程：格式串 **`%s/IsoService`**（类名前缀来自运行时对象 `+0x40`）、`Intent(Context,Class)`、`Context.bindService(Intent,ServiceConnection,BIND_AUTO_CREATE)`；接收 what=1000 回复后可走 `Context.unbindService(H.sConnection)`。原版基础 APK 的 Manifest 共 78 个 Service 声明，**没有任何名称以 `IsoService` 结尾**。此项只约束当前原版基础包，未知其他运行时安装状态；远端 `arg2` 实际数值、成功绑定及 DEC 因果关系仍未证明。[原版四项 JNI 注册、绑定守卫与 Manifest 证据](docs/12.5.5-secneo-messenger-service-binding.md)；[可复核工具](tools/audit_inner_h_service_lifecycle.py)。

### 原版 SecNeo 消息回调接入原生 he(int)（2026-10-24）

原版基础 `classes.dex` 已直接确认：

`b.onServiceConnected → Message.obtain(what=1000)`，将 `Process.myPid()` 赋给 `Message.arg1`、将 `H.a()` 取得的 Messenger 赋给 `replyTo`，随后通过 `H.b()` 取得的 Messenger 调用 `send`。另有 `H$a.handleMessage` 接收 `what=1000` 时把收到的 `Message.arg2` 传给 `H.c(int)`，再由其直接执行 `invoke-static H.he(int)`，原始 JNI 注册将该方法绑定至 `0x36F4C`。**发送端写入 `arg1`，接收端使用 `arg2`；远端服务回复内容尚未恢复**，不得当成已经验证的 PID 回显。

同一 `JNI_OnLoad` 六项注册表已恢复完整方法签名和地址：`gha`、`ghc`、`gah`、`sha`、`he`、`gv`；其中 `sha(String,int)` 直接接入 `0x26BC0` 的记录更新函数，`he(int)` 包含配置守卫及 `_exit` 等原版静态路径。[Messenger/完整 JNI 注册证据](docs/12.5.5-secneo-h-messenger-native-route.md)；[六项 JNI 审计](tools/audit_inner_h_jni_full_registration.py)；[Message→he 审计](tools/audit_h_messenger_he_callchain.py)。

对原版 `libdatajar.so` **14 组** DEX 元数据的新增核验覆盖 101,716 条类定义、133,981 个类型 ID、758,948 个方法 ID：这些片段未包含精确的 `Lcom/secneo/apkwrapper/H;`、`gha` 或 `ghc` 符号，排除了**该限定范围内**直接编码 `H.gha/ghc` 引用的可能。运行时动态生成/加载 DEX、反射或其他 JNI 调用不在此阴性结果覆盖范围内。[14 组方法引用审计](tools/audit_secneo_h_getter_dex_refs.py)。

### Java Native 可查询 envc.push 的状态和标识（2026-10-24）

原版内层 `libDexHelper.so` 的 `JNI_OnLoad` 注册表和固定 SHA-256 的 `classes.dex` 已交叉验证：默认 `com.secneo.apkwrapper.H` 声明了 `gha(String): int`、`ghc(String): long` 两个 Native 接口，分别对应 `0x367a4`、`0x36814`。两个函数都直接调用 `0x2682c` 读取 `envc.push`，前者返回状态低八位，后者返回记录中十六进制标识的零扩展 32 位值。原版 `JNI_OnLoad` 使用 `RegisterNatives` 将它们绑定到通过运行时类名创建的 Java 类引用；运行时类名覆盖仍可能存在。

**现在已经证明 Java 层具备读取原生状态记录的接口。** 在原版基础 `classes.dex` 的代码项内没有找到针对这两个方法的直接 `invoke-*` 候选。调用它们的具体业务代码、DEC 是否消费这些值以及设备执行情况仍待验证。[完整 JNI 与 DEX 证据](docs/12.5.5-secneo-h-java-native-record-getters.md)；[只读静态工具](tools/audit_inner_h_jni_record_getters.py)。

### SecNeo H 的本地 root 状态记录（2026-10-24）

继续从已验证的 H TracerPid 正结果分支追踪，原版证实了本地持久化记录函数：0x2616c(1) 通过真实 AArch64 跳转表映射到键名 **root**，0x2682c 查询同一路径下的 **envc.push**，0x26bc0 在特定返回值条件允许时通过带独占锁的文件更新链回写该记录。两处原版状态上报路径分别是 0x5af68（格式参数标识 0xb6a281fb）和 0x5b40c（0xb6a281f1）。读端的原版字符串格式是 %s= 加一位状态数字、随后用 strtoul(...,16) 解析标识字段。

完整原始 .text 中对键名选择 / 记录读取 / 更新函数的直接 BL 指令数分别是 **83 / 84 / 48**。这是可验证的静态调用点统计，并不代表真实写入次数。当前可以确定 TracerPid 阳性检查**可以触达 root 键的条件更新路径**，仍无法将 root 标签、文件内容或任一写入行为直接归因于 Java DEC 弹窗。用户设备已验证目标进程 FD 读取受限，后续继续依赖原版静态指令和高可信度日志。

[专项证据、读端字段与调用点计数](docs/12.5.5-secneo-h-envc-push-root-record.md)；[只读静态审计](tools/audit_inner_h_envc_push.py)。

## 数据边界

**请勿提交** APK、SO、DEX 转储、完整 logcat、Tombstone、`envc.push`、设备标识、令牌、账号信息或未经审查的诊断 ZIP。公开仓库只保留可公开的分析代码、去标识化结论及校验哈希。此仓库不分发原版商业客户端。

## 研究原则

1. 每项判断标明对应的样本版本和证据来源。
2. 明文字串命中只证明字串存在，不证明调用关系、参数或返回值语义。
3. 对 `SIGSEGV 0x978 / 0x97c` 的反注入猜测均保留为假设，直至取得代码级证据。
4. 研究脚本默认只读取证据，不修改原始 APK、设备状态或应用私有数据。
