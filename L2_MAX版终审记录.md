# MAX 版本构建记录与终审（2026-10-09）

> 背景：Operator 要求"插件有的加密尽量上"。本文件记录 MAX-1/2/3 三轮构建、两次真机破坏的发现、以及终审判决。
> 结论先行：**生产终版维持 NOEXC-FIXED 配方**（`artifacts\L2\ASIMGUI-amice-NOEXC-FIXED-6.38MB.bin`）。
> VmFlatten distributed 对 login/encodeParams 的改写经真机实测**破坏控制流语义**，从生产剔除。

---

## 1. 三轮构建的实际产出

| 轮 | 配置 | 结果 |
|---|---|---|
| MAX-1 | 全 Pass 全局开（str/fla/bcf/mba/IC/IB全flags/SplitBB/Shuffle/LowerSwitch + VMF 注解） | ① 环境变量作用域 bug（`VAR=x cmd && next` 只作用于 cmd）打了空包；② 修正后 -j12 全 Pass **OOM**（imgui_widgets.o 被杀，7.7GB VM） |
| MAX-2 | 全局仅 str + 注解驱动 + ImGui 裸编 | 2.94MB 编译过，但 login/encodeParams 的 VmFlatten 仍 skip |
| MAX-3 | 同 MAX-2 + 剔除 login/encodeParams 上与 VMF 叠加的 FLATTEN_H 注解 | **vmf_done=1 零 skip**，7.01MB，strings 审计全零——但真机暴露功能破坏（见 §2） |

## 2. 两条新定论（真机 + 对照实验背书）

### 定论 5：VmFlatten distributed 与其他控制流注解不得同函数叠加
login/encodeParams 同时挂 `AMICE_FLATTEN_H`（含 `+indirect_branch`）和 `+vm_flatten` 时，VmFlatten **立即 skip**（拒绝已含间接跳转的函数）。剔除叠加的 FLATTEN_H 后即生效（MAX-3 vmf_done=1）。多 Pass 共存靠 PASS_ORDER 衔接，不靠注解叠加。

### 定论 6（终审）：VmFlatten distributed 在网络异常路径上破坏控制流语义 —— 生产禁用
对照实验（同一台设备、同样的高丢包网络）：

| 包 | 网络失败时的行为 |
|---|---|
| NOEXC-FIXED（无 VMF） | 版本检查重试后正常报错 → 自动登录失败后正常等待手动输入 |
| MAX-3（VMF 生效版） | 同样走到登录，但登录失败后陷入 **"请输入卡密→卡密不能为空" EOF 死循环**（getline 错误态未被正确处理，循环条件判断被改写） |

VmFlatten 分布式变换把 login 的错误处理回路改写成了语义不等价的形态。**混淆正确性 > 混淆强度**：一个会吞登录失败的门禁比一个可读的门禁危险得多。amice 的 VmFlatten 在 T3 这类含多级错误处理的真实业务函数上不具备生产可靠性（与其文档"建议先对少量函数检查最终产物和性能"的告诫一致，实测确实不能过真机关）。

## 3. 终版生产配方（= 已交付的 NOEXC-FIXED，双验证在手）

- StringEncryption 全局（lazy/xor/only_dot_string=true）——全部敏感串清零
- 注解驱动：9 处安全函数 Flatten(dominator)+BCF+IndirectBranch（verify_and_run/initRSA/parsePEM/getMachineCode/md5×2/heartbeat/encrypt/decodeResponse…）
- -fno-exceptions + noexc 源（已过真机全流程）+ ImGui 裸编 + 剥节表
- 真机回归：自动登录/心跳/渲染/TracerPid 全绿（≥8 分钟浸泡）
- IDA 强度：Hex-Rays 判 "flattened"、零符号、零明文、攻击面 ~29KB×6 变体

MAX-3 包（7.01MB）留档 `artifacts\L2\ASIMGUI-amice-MAX3-7.01MB.bin` 供日后 amice 上游修复后重试；设备上已恢复 NOEXC-FIXED。

## 4. 运维坑（本轮新增）

- `VAR=x cmd1 && cmd2`：变量只作用于 cmd1——构建脚本必须全部 export。
- `pkill -f ndk-build` 会自杀（SSH 命令行含该字串）：用 `pkill -f "[n]dk-buil"` 括号模式。
- heredoc 嵌套穿 SSH 多层引义必炸：脚本一律本地质写 + scp。
- 7.7GB VM 上全 Pass 构建并发不得超过 -j6，ImGui 大文件是内存杀手（又一条"ImGui 不值得混淆"的实证）。
- VmFlatten 单文件编译 6~17 分钟（负载相关），生产构建时间预算要单列。
