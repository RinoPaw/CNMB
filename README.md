# CNMB

中国移动 Android 客户端设备环境检查与加固行为研究。主要研究对象：`com.greenpoint.android.mc10086.activity`。

本仓库记录**可复核的静态证据和实验观察**，将已验证事实、技术推断和待验证问题分开。研究优先使用 APK 原始字节、Android Manifest、DEX 指令、ELF 结构、系统日志与 Tombstone，不把第三方逆向结论直接当作当前版本事实。

## 当前进度

- 中国移动 12.5.5 APK 的 SecNeo 启动桩、Manifest 中的 `DECMsgDialog` 和若干代码字符串已完成初步定位。
- `classes.dex` 中确认存在读取 `/proc/self/status`、解析 `TracerPid:` 的实现，但**没有证据证明其直接触发 Root 弹窗**。
- 已恢复多组 Dex 的元数据、原本被遮蔽的早期字符串索引及 50,000+ 方法体；确认 `CmccApplication.onCreate()` 静态调用 DEC 初始化，并恢复 `RootBeer` 的具体检查实现。
- `DeviceEnvironmentCheck.startCheck()` 的方法体仍未定位；`RootBeer` 在对应片段中没有外部直接调用点，**尚无证据表明它触发 DEC 警告**。
- 在 OPPO CPH2127 / Android 12 上，干净重启后的 DEC 弹窗与 Frida 服务端运行时的原生崩溃属于两类不同的观测结果。崩溃的具体触发代码尚未定位。

详细报告：[静态取证报告](docs/12.5.5-static-analysis.md)；[DEC Dex 方法调用链](docs/12.5.5-dec-dex-callgraph.md)；[DEC 生命周期](docs/12.5.5-dec-startup-lifecycle.md)；[CmccApplication → DEC 启动连接](docs/12.5.5-cmcc-dec-bridge.md)；[受保护字符串与 RootBeer](docs/12.5.5-dex-string-recovery-rootbeer.md)；[动态对照记录](docs/2026-10-22-dynamic-observations.md)。

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
```

## 实验脚本

`experiments/process_lifetime.py` 可以通过 ADB 监视主进程启动和退出，不需要 Frida：

```powershell
python .\experiments\process_lifetime.py --monitor-only --observe-seconds 25
```

可选的 `--trace` 加载 `experiments/dec_trace.js`，仅在已经确认动态注入可用、且接受目标进程可能崩溃的测试环境中使用；它需要匹配版本的 `frida` Python 包与服务端。当前设备上**无脚本的 Frida 服务端也曾伴随 Native Crash**，不要将崩溃自动归因为特定 Root 检测规则。

## 数据边界

**请勿提交** APK、SO、DEX 转储、完整 logcat、Tombstone、`envc.push`、设备标识、令牌、账号信息或未经审查的诊断 ZIP。公开仓库只保留可公开的分析代码、去标识化结论及校验哈希。此仓库不分发原版商业客户端。

## 研究原则

1. 每项判断标明对应的样本版本和证据来源。
2. 明文字串命中只证明字串存在，不证明调用关系、参数或返回值语义。
3. 对 `SIGSEGV 0x978 / 0x97c` 的反注入猜测均保留为假设，直至取得代码级证据。
4. 研究脚本默认只读取证据，不修改原始 APK、设备状态或应用私有数据。
