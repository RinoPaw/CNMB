# CNMB

中国移动 Android 客户端设备环境检查与加固行为研究。主要研究对象：`com.greenpoint.android.mc10086.activity`。

本仓库记录**可复核的静态证据和实验观察**，将已验证事实、技术推断和待验证问题分开。研究优先使用 APK 原始字节、Android Manifest、DEX 指令、ELF 结构、系统日志与 Tombstone，不把第三方逆向结论直接当作当前版本事实。

## 当前进度

- 中国移动 12.5.5 APK 的 SecNeo 启动桩、Manifest 中的 `DECMsgDialog` 和若干代码字符串已完成初步定位。
- `classes.dex` 中确认存在读取 `/proc/self/status`、解析 `TracerPid:` 的实现，但**没有证据证明其直接触发 Root 弹窗**。
- `libdatajar.so` 含 `DeviceEnvironmentCheck`、`DECApp`、`RootBeer` 等类描述符；目前**没有恢复其受保护方法体**。
- 在 OPPO CPH2127 / Android 12 上，干净重启后的 DEC 弹窗与 Frida 服务端运行时的原生崩溃属于两类不同的观测结果。崩溃的具体触发代码尚未定位。

详细报告：[docs/12.5.5-static-analysis.md](docs/12.5.5-static-analysis.md)。

## 复核

Python 3.9+，仅使用标准库：

```powershell
python .\tools\offline_audit.py .\path\to\base.apk
# 或传入包含 apks/01-base.apk 的诊断 ZIP
```

脚本只读输入文件，并输出 APK 哈希、加固启动桩、相关 Manifest 组件及明文字符串命中。

## 数据边界

**请勿提交** APK、SO、DEX 转储、完整 logcat、Tombstone、`envc.push`、设备标识、令牌、账号信息或未经审查的诊断 ZIP。公开仓库只保留可公开的分析代码、去标识化结论及校验哈希。此仓库不分发原版商业客户端。

## 研究原则

1. 每项判断标明对应的样本版本和证据来源。
2. 明文字串命中只证明字串存在，不证明调用关系、参数或返回值语义。
3. 对 `SIGSEGV 0x978 / 0x97c` 的反注入猜测均保留为假设，直至取得代码级证据。
4. 研究脚本默认只读取证据，不修改原始 APK、设备状态或应用私有数据。
