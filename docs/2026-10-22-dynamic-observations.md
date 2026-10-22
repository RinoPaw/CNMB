# 2026-10-22 Android 12 / APatch 动态实验记录

## 条件与证据范围

- 手机：OPPO CPH2127 / Android 12 / APatch。
- APK：`com.greenpoint.android.mc10086.activity`，研究版本 12.5.5。
- 测试：ADB 启动及进程采样，Frida 17.5.2 / 17.24.3 的服务端存在性对照。
- 原始 logcat、完整 Tombstone、诊断 ZIP 不在本公开仓库中；本文件仅存放脱敏摘要。
- **关键限制**：不同轮次的进程生命周期并不能单独建立崩溃与 Frida 的直接因果，更不能据此还原 Root 判定逻辑。

## 对照结果

| 环境 | 主要现象 | 证据强度 |
| --- | --- | --- |
| 重启后、无 Frida 服务端 | 应用能够启动，系统记录 `DECMsgDialog` 启动并显示；主进程在延长观察中约 +13.49 秒消失 | 由系统日志和进程采样直接确认 |
| 17.5.2 仅运行服务端、无 Attach | 首个主 PID 约 +7.47 秒消失；发生 `SIGSEGV`，故障地址 `0x97c`，未出现 DEC 窗口 | Logcat `am_crash`、Tombstone 与屏幕观察 |
| 17.24.3 仅运行服务端、无 Attach | 首个主 PID 约 +8.48 秒消失；原生崩溃 `SIGSEGV 0x97c`，未记录 DEC 窗口 | Logcat `am_crash`、Tombstone |
| 17.5.2 启动后按 PID Attach | 约 +1.03 秒尝试附加；目标 PID 在 +2.89 秒消失；约 25 秒后收到 `ProcessNotFoundError` | 独立 ADB 采样时间线；失败原因未直接证明 |

### Native 崩溃签名

部分故障发生于 `SIGSEGV`，`PC=0x97c`、`LR=0`、`SP=0`；也有先前 `0x978` 的记录。由于 PC 指向非法低地址，原生栈无法正常展开；尚没有证据将崩溃指令归属给 `libDexHelper.so`、DEC 或应用反 Frida 逻辑。

17.24.3 测试同一时段还观察到 Termux 在 `libart.so` 的 `art::Unsafe_getObject` 调用路径崩溃，栈涉及 `HiddenApiBypass`。其栈结构与中国移动不同，不能直接认定为同一根因。

## 未证实的可能原因

1. 应用加固组件主动感知 Frida / 注入痕迹。
2. Frida 服务端及其 Zygote / ART 操作与当前设备系统不兼容。
3. 系统运行时状态异常，重启后暂时解除。

Frida 17.6.0 曾公开讨论早期 Zygote 注入策略及跨进程干扰，但这属于**外部背景**，并非该 APK 的代码级因果证据。

## `envc.push` 状态

早期诊断在应用私有目录 `/data/user/0/com.greenpoint.android.mc10086.activity/envc.push` 观察到文件，内容具有约 24 字符 Base64 与换行的外形。文件读写方、数据语义、是否影响 DEC 均未得到验证，禁止将其直接标注为「Root 风险标记」。

## 后续建议

优先对受保护 Java 类定义和调用关系开展离线恢复；在安全、经批准的测试环境中进行对照。不要为了制造预期结果而篡改返回值或应用私有文件。原始取证材料仅保留于可信本地环境，并对设备信息及账户数据脱敏。
