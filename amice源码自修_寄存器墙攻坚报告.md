# amice 源码自修改实验报告：寄存器墙攻坚（2026-10-09）

> Operator 指令："用 amice 源码自己修" → "先看看有没有开源的" → "继续编译"。
> **最终结论：开源无替代品；自修三轮补丁（存活期 v1/v2、ABI 预留 v3）全部实测，墙未破；但产出了完整构建环境 + 上游级诊断数据。生产链路已恢复原版，零影响。**

---

## 1. 开源调研结论（无替代品）

| 项目 | 结论 |
|---|---|
| **ykus4/kagura**（34★, MIT, 2026-09） | 仓库描述写"VM virtualization"，**实际 README 无 VM 档**（仅 str/fla/bcf/mvo/anti-debug/tamper）——描述虚标，排除 |
| **90th/llvm-obfus**（110★, GPL-3.0, LLVM21+） | 有真 VM（`vm`/`strong_vm` 档、编码分派、完整性校验），但**文档明确仅支持 Linux/Windows x86-64，零 aarch64/Android 支持**——排除 |
| OLLVM 系（含 Kagura/Pluto/Hikari fork） | 无指令级 VM 虚拟化 |
| Tigress | 有 VM+寄存器分配，但只吃 C（不支持 C++）、无 Android 工具链、许可限制——排除 |
| **amice** | **Android arm64 C++ 的唯一可用 VMP**（Apache-2.0） |

## 2. 已建成的能力（本轮净收益，可复用）

| 能力 | 细节 |
|---|---|
| VM 上从源码构建 amice 插件 | Rust（rsproxy.cn 镜像绕墙）+ LLVM 21（apt.llvm.org 走宿主 Clash 代理 192.168.117.1:7897） |
| **ABI 匹配工具链** | **clang-18 + NDK r27c sysroot**（关键发现：NDK r30 的 libc++ 用 LLVM19+ 内建函数 `__builtin_ctzg`，clang-18 编不过；且 apt LLVM 21.1.8 与 NDK clang 的 AOSP LLVM 21.0.0 ABI 不通，实测插件崩溃 exit 139/134） |
| 插件构建 | `~/amice-lab/amice-src`，`cargo build --release -p amice --no-default-features --features llvm18-1`（~35s） |
| 生产链路 | bundle 插件已恢复原版（md5 5557e4fe…），零影响 |

## 3. 三轮补丁与实测（全部无效，但诊断数据是金）

### 3.1 补丁 v1/v2：ReusePlan 存活期改进（`global_last_uses`）
- 内容：跨块非 PHI 值不再无条件 pin，改在全局最后使用点释放（SSA 保证安全）；修了 v1 的提前释放 bug。
- 实测：5 函数仍全 skip（-O2 / -O1 / 关展开关向量化，全同）。

### 3.2 补丁 v3：ABI 寄存器预留条件化
- 发现：`translator.rs:2618` **无条件预留** ABI 寄存器跨度（`max(native_args/native_returns/params/returns)+1`）——profile ABI 声明 x0..x7 参数即白扣 8 个寄存器。
- 补丁：仅当函数真含 Call/Invoke/CallBr 时才预留。
- 实测：md5Transform 仍 skip，诊断数字完全不变（说明它不是主因，或 md5Transform 含调用）。

### 3.3 决定性诊断数据（上游级素材）
```
[diag:regwall] bail@temp values=23 aggregates=0 temps=4 allocated=32 free=0 side[allocas=0 alloca_geps=0 static_geps=0]
[diag:regwall] bail@temp values=22 aggregates=0 temps=5 allocated=32 free=0 ...
[diag:regwall] bail@temp values=9  aggregates=0 temps=11 allocated=32 free=0 ...
```
**读数：爆预算时实际持有者仅 20~27 个（values+temps），却有 5~12 个寄存器"消失"。** 已排除：侧表泄漏（dynamic_* 全零）、临时寄存器未登记（两处 allocator 均登记）、ReusePlan 保守 pin（补丁 v2 已解除，无变化）。剩余嫌疑（供上游定位）：
1. `reserve_vregs` 的 ABI 跨度预留（条件化后 md5Transform 数字不变 → 该函数可能真含调用，或预留非其瓶颈）；
2. `native_touched_registers` 相关的 save/restore 临时（`save_native_touched_registers` 每次调用分配 scratch）；
3. 未纳入 `self.values` 的其它长生命周期绑定（建议上游加同类 `diag_register_state` 断言：`allocated == values + temps + aggregates + side + reserved`，任何不等即泄漏）。

### 3.4 决定性实验：强制清零 ABI 预留（2026-10-09 最终数据）

将 `reserved_vregs` 硬编码为 0（`if false && has_calls`）后重测：

| 函数 | 原版（预留 8） | 强制零预留 |
|---|---|---|
| RSACrypto::encrypt | values=23 temps=4 | **values=23 temps=12** |
| encodeParams | values=22 temps=5 | **values=22 temps=13** |
| heartbeat | values=9 temps=11 | **values=11 temps=9 side[static_geps=7]** |
| md5Transform | values=23 temps=4 | **values=23 temps=12** |

**读数结论（定量定案）：**
1. 预留清零后，多出的 8 个寄存器**立刻被临时值吃掉**（temps 4→12）——需求总量不变（≈35），预留只是"提前占用"，不是浪费；
2. **md5Transform 真实需求 = 23 值 + 12 临时 = 35 > 32**——硬件预算物理不够；
3. heartbeat 额外暴露 **7 个侧表持有的 offset 绑定**（`dynamic_static_geps`，设计上终身持有，属次要泄漏）。

**终审：墙的本质是"无溢出机制 + 真实并发需求 > 32"，不是账目 bug。唯一解 = spill-to-stack。** 廉价修复路径（存活期优化 v1/v2、ABI 预留条件化 v3）已全部穷尽并实测无效，此结论有完整数据背书。

## 4. spill 实现（translator 层，零 ISA/runtime 改动）与最终根因

### 4.1 已实现的 spill 基础设施（`translator.rs`，4 处改动，全部实测生效）

| 组件 | 实现 |
|---|---|
| 溢出帧 | 函数入口发射 `alloca`（64 槽 × 8B），帧指针+地址 scratch 两个寄存器排除在 native_call clobber 集外；仅当标量 SSA 值 > 24 时预分配（避免小函数浪费寄存器） |
| 溢出触发 | `ensure_result_binding` / `alloc_temporary_vreg` 分配失败时，选非 PHI、非当前指令操作数的值 → `store` 入槽 → 释放寄存器 → 重试（最多 16 次） |
| 回载 | `materialize_value` 未命中 `self.values` 但在溢出表 → `load` 到临时寄存器 |
| call 保存改走帧 | `save/restore_native_touched_registers` 优先存槽（内存）而非临时寄存器，消灭每次调用的 N 个 scratch |

**实测：spill 确实工作**——`spilled=10~12`（10~12 个值成功溢出到栈帧），帧就绪日志正常。

### 4.2 最终根因（决定性诊断）

在 `alloc_temporary_vreg` 的 bail 点打印当前指令 opcode：

```
[diag:regwall] bail@temp opcode=Some(Call) values=13 temps=16 spilled=10 allocated=32 free=0
[diag:regwall] bail@temp opcode=Some(Call) values=10 temps=16 spilled=12 allocated=32 free=0
```

**爆点全部在 `Call` 指令的降低过程，且 `temps=16` 恒定**（与 -O2/-O1/关向量化/关展开/预留清零/帧式 call 保存全部无关）。含义：

- **调用降低同时持有 16 个临时寄存器**（参数编组：每个实参先物化到临时再搬进 ABI 寄存器 x0..x7，加上返回值处理）；
- 该瞬时峰值 = 13~14 活跃值 + 16 参数临时 + 2 帧/scratch ≈ 32+，任何 spill 策略都救不了**同一指令内部的瞬时峰值**（spill 只能腾出"值"占的寄存器，腾不出指令内部的临时）；
- 各函数真实需求 ≈ 40~45 个寄存器槽位。

### 4.3 剩余工作（上游级，非本地补丁）

**调用降低层重构**：参数直接物化进 ABI 寄存器（或按序物化+溢出中转），消除 16 个瞬时临时；配合已就绪的 spill 帧基础设施，即可让这些函数过预算。工作量：`lower_call`/`emit_native_bridge_call`/`emit_parallel_register_moves` 三处重构 + amice 自带测试套件验证（`crates/amice/tests/`）。


### 4.4 追加：Call 路径逐层排查（2026-10-09 深夜）

为定位 16 个临时的确切来源，做了两组针对性改造并实测：

| 改造 | 预期 | 实测 |
|---|---|---|
| ① `save/restore_native_touched_registers` 改走溢出帧 | 消灭每次调用的 N 个 scratch 临时 | 无变化（该路径本已不是来源） |
| ② 实参经溢出帧暂存（`NativeArgLoc::Staged`）：逐个物化→存槽→释放临时→按序 load 进 ABI 寄存器 | 峰值从 O(参数数) 降到 O(1) | **仍 `temps=16`** —— 参数物化不是来源 |
| ③ 全部 31 个直连分配点接入 spill 重试（`alloc_vreg_or_spill`） | 消除"未插桩分配点"爆点 | ✅ **生效**：login `spilled=49`、heartbeat `values=0`（全溢出） |

**结论：16 个临时来自 Call 路径中除参数物化之外的环节**（结果绑定 `native_call_final_returns`、`call_action` 操作数发射、或 ABI 覆盖检查相关的保存集合）。这些环节的分配点已接入 spill 重试（改造③），但它们在**同一条指令内**同时持有，spill 无法在不改变指令语义的前提下削减该瞬时峰值。

**剩余路径（明确、可执行）**：在 `emit_native_bridge_call` 内逐段打印寄存器占用（进入时 / 保存后 / 参数暂存后 / call_action 发射前），定位峰值段，再把该段的分配改为按序使用。这是纯插件侧的定点工作，不需要源码适配。

## 5. 结论与建议

1. **墙未破，生产零变化**（VMP 仍作用于画像内函数如 fnv1a64）。
2. **正确路径 = 上游级两件事**：(a) 修上述寄存器账目泄漏/预留策略（本轮已定位到疑似点，附诊断方法）；(b) 实现 spill-to-stack（VM ISA 内存操作数 + 编解码 + runtime 支持，特性级）。
3. **建议提 issue/PR**：附本报告 + `global_last_uses` 补丁（可作独立改进先合）+ 诊断 instrumentation（`diag_register_state` + bail 画像日志，对上游排查同样有价值）。
4. 补丁源码留存：VM `~/amice-lab/amice-src`（含 v3 状态）；本地 `artifacts\tmp\translator_{v2,v3,diag*}.rs`。
