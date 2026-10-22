# 2026-10-22：ADB-only 原生库映射时间线实测

来源：用户在 OPPO CPH2127 / Android 12 上执行 `experiments/capture_loaded_modules.py --launch --seconds 18 --poll-seconds 0.5 --output loaded-modules-local.json` 的**终端输出**。本公开记录只保留相对时间与去标识化 PID 代号；原始 JSON 留在用户本地，不上传至仓库。

## 实测关键数据

| 相对采样时间 | 进程代号 | 重要文件映射 | 匿名 RWX 段 | 总 RWX 字节数 |
|---|---|---|---:|---:|
| +0.35 s | A | `libDexHelper.so`, `libdatajar.so` | 2 | 1,171,456 |
| +0.44 s | B | `libDexHelper.so` | 1 | 1,155,072 |
| +1.22 s | A | `libDexHelper.so`, `libdatajar.so` | 2 | 1,171,456 |
| +1.42 s | C | `libDexHelper.so`, `libdatajar.so` | 2 | 1,171,456 |
| +4.46 s | D | `libDexHelper.so`, `libdatajar.so` | 2 | 1,171,456 |
| +12.36 s | A | **不可判定：读取结果为空** | **无效观测** | **无效观测** |

A/C/D 的匿名 RWX 内存总量比 B 多 **16,384 B**。此前独立的 `SIGSEGV 0x978` Tombstone 里，`x19` 所在匿名 RWX 映射恰好也是 **1,155,072 B**。**数值一致仅构成结构线索**：不同启动轮次、不同 PID 的映射没有地址/内容身份对应关系，不能推断它们是同一份代码，也不能断定属于 SecNeo 或 Frida。

每次有效快照均能看到 `libDexHelper.so`；A/C/D 还能看到 `libdatajar.so`。**这确认文件被映射进入进程地址空间**，尚不能证明任一片段的 Dex 方法体已经解密并执行。

在此次已给出的快照中，未观察到 `libdexjni.so`、`libdexvmp.so`、`libZWRiskComm*`；采样是间歇性的，不能以此证明它们在整个运行期间从未加载。

进程 A 最后的 `native_and_dex_files=[]`、RWX 计数 0：经工具审计发现，是旧版采样器将**空的 /proc/PID/maps 读取结果**当成正常地图的结果。可能是退出/僵尸状态的瞬态，但这份 JSON 无法证明具体原因。正确表示为 **maps-empty / 不可用快照**，不能声称应用突然卸载了所有系统库。

## 当前实验的边界

- 该 Python 脚本本身没有进行 Frida 连接、Attach、注入或内存修改；但输出并未记录 Frida 服务端的存在性，因此**无法确定这轮是否处于严格的 Frida-off 环境**。
- 时间基准是 `adb shell monkey` 返回之后开始的 `monotonic()` 采样，并非应用 `onCreate` 的真实时间零点。ADB 子进程每次运行还有额外延迟。
- 同名 PID A–D 需要通过 logcat 的 `am_proc_start` / `am_proc_died` / `am_crash` 与 `DECMsgDialog` 显示事件关联，才能判断每个 PID 在退出链路中的作用。
- 不能仅凭模块映射结果确认 `DeviceEnvironmentCheck.startCheck()` 的实现或 Root 检测项。

## 工具修正

此次实验后更新的采样器：

1. 对空 `maps` 记录一次 `maps-empty` 错误，并跳过该快照，不再报告“所有库卸载”。
2. 对从 `ps` 中消失的 PID 输出独立的 `not_in_ps` 状态，结束时保留 `present_at_end` 状态。
3. 终端默认显示重点库/RWX 统计的简洁报告，`--output` 仍保存完整去路径 JSON。
4. 支持 `--from-json` 直接总结既有文件而不需要手机，也不会启动应用。

本轮既有文件可直接复核：

```powershell
python .\experiments\capture_loaded_modules.py --from-json .\loaded-modules-local.json
```

关联 DEC 窗口与进程终止事件需通过用户本机的 `logcat` 进行，不能从模块快照反推出弹窗出现时间：

```powershell
adb logcat -d -v threadtime -b main -b system -b events -b crash |
  Select-String 'DECMsgDialog|com.greenpoint.android.mc10086.activity|am_crash|am_proc_died|Fatal signal'
```

后续建议先在干净重启后确认 Frida Server 状态，再进行相同的严格对照。原始 `logcat`、内存映射和商业 APK 不入库。
