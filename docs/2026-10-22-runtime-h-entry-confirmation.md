# 中国移动 12.5.5：重启后日志直接确认一次 `H` Java 入口执行

核验日期：2026-10-23。证据来源为用户保存的 **2026-10-22 15:25–15:26（设备本地时间）** `CNMB-after-reboot.txt`。此原始日志 SHA-256：

`29898947505e6099a465a10d57fc66ec5f3900acf4c3612e1f09d03ac2807f2e`

原始 Logcat 可能包含设备路径、隐私字段及其他应用数据，因此**不上传仓库**。下表只保留与目标组件直接相关的有限事实；临时 PID 仅用于区分同一次运行中的进程。此记录与此前 15:17 的 `SIGSEGV 0x978` Tombstone **属于不同的运行轮次**，不能合并成一次调用栈。

## 同一次启动中的事件

| 设备时间 | 原日志直接可核验的事件 |
| --- | --- |
| 15:25:54.027 | ActivityManager 启动中国移动主进程 PID 8387，应用 UID 10250 |
| 15:25:54.266 | 主 PID 8387 报告成功加载 `libDexHelper.so` |
| 15:25:59.234 | **另一 PID 8714** 的 AndroidRuntime 输出 `START com.android.internal.os.RuntimeInit uid 10250` |
| 15:25:59.238、15:25:59.250 | 同一 PID 8714 的 SELinux 日志记录 `app=com.greenpoint.android.mc10086.activity` |
| **15:26:00.969** | **PID 8714 的 AndroidRuntime 原样输出 `Calling main entry com/secneo/apkwrapper/H`** |
| 15:26:02.981 | PID 8714 输出 `Shutting down VM`，仅能证明进入关闭阶段 |
| 15:26:03.908 | ActivityTaskManager 收到目标应用的 `DECMsgDialog` 启动请求 |
| 15:26:04.106 | ActivityTaskManager 报告 `DECMsgDialog` 显示完成 |

以主进程启动日志为锚点，同一设备时钟上的时间差分别为：`RuntimeInit +5.207 s`、`H main +6.942 s`、`DEC 启动 +9.881 s`。`Shutting down VM` 至 DEC 启动为 **0.927 s**。这些是日志时间差，不是代码执行时长或 IPC 延迟。

## 与原版静态代码的交叉核验

此前已经在原版受保护内层 ELF 中按原始指令证明：默认 `execl` Java 主类是 `com/secneo/apkwrapper/H`，该类路径从字符表构造并被复制到运行时对象 `+0xE0`，然后作为 `execl` 的 `x4` 参数传入；运行时配置仍可能覆盖这个默认值。详见[原版默认入口与参数数据流](12.5.5-inner-app-process-argv-thread-chain.md)。

**本轮日志补上了一个独立的运行时事实**：设备在这次启动中确实执行到了 `com.secneo.apkwrapper.H` 的 Java 入口调用日志，且该日志与应用 UID、应用身份审计记录属于同一 PID。此前另两轮 `RuntimeInit` 日志未提供显式入口，因此其实际主类依然未知。

这仍**没有直接证明** PID 8714 由已恢复的 SecNeo 双重 `fork/execl` 路径创建，也没有证明 `H` 的返回值、文件读写、IPC 或 DEC 风险判定之间存在因果联系；尤其不能据时间接近断言其执行了 `DeviceEnvironmentCheck.startCheck()`。

## 离线复核与解析器修正

`experiments/profile_runtime_worker.py` 原先的 `MAIN_ENTRY` 正则只接受点分形式（`com.example.Main`），实际 AndroidRuntime 会打印斜线形式（`com/secneo/apkwrapper/H`）。该规则现同时识别两种形式，并将输出规范化为 `com.secneo.apkwrapper.H`，保留按确切日志 PID 限定和不输出敏感消息正文的约束；合成回归测试覆盖这条路径。

在本地对**本轮原始日志**执行：

```powershell
python .\experiments\profile_runtime_worker.py .\CNMB-after-reboot.txt --pid 8714
```

输出应包含 `has_explicit_main_entry_log=true` 和 `class_name=com.secneo.apkwrapper.H`；该观察只归属于这一份日志及其 PID。不要把未经审查的完整 Logcat、Tombstone 或私有文件提交到公开仓库。
