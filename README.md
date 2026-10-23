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
- **原版受保护内层 ELF 已成功离线复原。** 内层 `libDexHelper.so` 导入 `fork/execl`，已确认 `JNI_OnLoad:0x16990` 调用注册函数 `0x1DF7C`，把 `0x4E1C8` 写入回调表；该回调函数具备 `pthread_create(…,0x59700,…)` 调用，线程入口内执行双重 `fork` 和 `execl("/system/bin/app_process",…)`。已恢复 `--nice-name=zygote`、`--write-fd`、`--flags 0` 等实际参数；Java 主类值仍未知。现已恢复回调表的分发线程及条件：初始化配置字段 `+0x4A` 非零时设置位 `0x04`，分发线程调用回调表 `+0x20` 槽，静态路径闭合至双重 `fork`；实际配置值与设备 PID 对应仍需验证。
- 已通过原版 PLT/JUMP_SLOT 精确证明构造函数使用 `dlopen("libc.so",2)` 和 `dlsym("sscanf")`，随后进入 `0x33f8`，通过 `fopen/fgets/sscanf` 解析 `/proc/self/maps`，再执行原生内存映射/权限配置流程。此链属于原版装载行为；尚未定位 DEC 检测条件。
- 原版 APK 全部 191 份 ARM64 SO 中，**174 份**含逐字节相同的 2,564 B 装载辅助核心（其中 10 份多匹配一个字节），附带 `/proc/self/maps`、`mprotect(RWX)`、缓存刷新及九条系统调用封装；该段还有 `__b_a_n_g_c_l_e__check1234567_` 原版签名。此为**共用保护代码证据**，尚未与 DEC 判定建立调用关系。
- 先前原版 SO 中的 `forked from pid:` 及 `Current process is forked from` 已通过 Dex 方法归属和指令核实：它们属于支付宝 `CrashBridge.isForkedCrashOnlyForTracing` 的日志文本解析逻辑，不能作为 SecNeo 创建子进程的证据。

详细报告：[静态取证报告](docs/12.5.5-static-analysis.md)；[DEC Dex 方法调用链](docs/12.5.5-dec-dex-callgraph.md)；[DEC 生命周期](docs/12.5.5-dec-startup-lifecycle.md)；[CmccApplication → DEC 启动连接](docs/12.5.5-cmcc-dec-bridge.md)；[受保护字符串与 RootBeer](docs/12.5.5-dex-string-recovery-rootbeer.md)；[14 组 Dex 元数据扫描](docs/12.5.5-fourteen-dex-census.md)；[原版进程操作与 ARM64 系统调用审计](docs/12.5.5-native-and-dalvik-process-surface.md)；[174 份 ARM64 库共用装载尾段](docs/12.5.5-shared-native-loader-tail.md)；[DexHelper 加载构造函数与 dexjni 共用引导代码](docs/12.5.5-dexhelper-native-constructors.md)；[DexHelper PLT 与映射加载链](docs/12.5.5-dexhelper-plt-maps-loader.md)；[内层 ELF 复原与 fork/execl 创建 app_process](docs/12.5.5-nested-elf-recovery-process-spawn.md)；[完整 app_process 参数与 JNI→线程→fork 静态路径](docs/12.5.5-inner-app-process-argv-thread-chain.md)；[原生加载与崩溃阶段](docs/12.5.5-native-loader-crash-stage.md)；[动态对照记录](docs/2026-10-22-dynamic-observations.md)。

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

## 数据边界

**请勿提交** APK、SO、DEX 转储、完整 logcat、Tombstone、`envc.push`、设备标识、令牌、账号信息或未经审查的诊断 ZIP。公开仓库只保留可公开的分析代码、去标识化结论及校验哈希。此仓库不分发原版商业客户端。

## 研究原则

1. 每项判断标明对应的样本版本和证据来源。
2. 明文字串命中只证明字串存在，不证明调用关系、参数或返回值语义。
3. 对 `SIGSEGV 0x978 / 0x97c` 的反注入猜测均保留为假设，直至取得代码级证据。
4. 研究脚本默认只读取证据，不修改原始 APK、设备状态或应用私有数据。
