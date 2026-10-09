# amice 源码自修改实验报告：寄存器墙攻坚（2026-10-09）

> Operator 指令："用 amice 源码自己修"。目标：拆掉 VmVirtualize 的 x0..x31 寄存器墙，让 T3 核心函数能上 VMP。
> **结论：环境全通、补丁实现并实测，但墙未被撼动——它是结构性开销，需实现 spill 支持（特性级工程）。插件已恢复原版，生产未受影响。**

## 1. 已建成的能力（本轮净收益）

| 能力 | 状态 |
|---|---|
| VM 上从源码构建 amice 插件 | ✅ Rust（rsproxy 镜像）+ LLVM 18/21（apt.llvm.org 走宿主 Clash 代理 192.168.117.1:7897） |
| 插件 ABI 匹配工具链 | ✅ **clang-18 + NDK r27c sysroot**（NDK r30 的 libc++ 需要 LLVM19+ 内建函数，clang-18 编不过；r27 sysroot 解决） |
| 补丁版插件构建 | ✅ `amice-src/target/release/libamice.so`（LLVM18 feature，1m17s） |
| 原版插件备份/恢复 | ✅ `libamice.so.orig`（md5 5557e4fe…），当前生产链路已恢复原版 |

## 2. 补丁内容（ReusePlan 存活期改进，v2 定稿）

`crates/amice/src/aotu/vm_virtualize/translator.rs` 三处：
1. `ReusePlan` 新增 `global_last_uses: HashMap<ValueKey, (BlockKey, usize)>`
2. 跨块非 PHI 值不再无条件 pin，改为记录全局最后使用点；PHI 仍 pin（回边语义必需）
3. 释放路径：跨块值只走全局最后使用点释放（并加 `cross_block_used` 守卫，防块内提前释放=寄存器复用错误）

正确性论证：SSA 下非 PHI 跨块使用只会出现在布局上更靠后的位置（回边流量必经 PHI）。

## 3. 实测结果（决定性）

同一 `t3sdk_noexc.cpp`（5 个 `+vm_virtualize` 注解：login/encodeParams/RSACrypto::encrypt/heartbeat/md5Transform）：

| 配置 | 结果 |
|---|---|
| 原版插件 -O2（基线，此前实测） | 5/5 skip：x-register budget exceeded |
| **补丁 v1** -O2 | 5/5 skip（同因） |
| **补丁 v2** -O2 | 5/5 skip（同因） |
| **补丁 v2** -O1 + `-fno-unroll-loops -fno-slp-vectorize -fno-vectorize` | 5/5 skip（同因） |

**结论：压力不是优化器展开/向量化制造的，也不是保守 pin 造成的（补丁已解除跨块 pin，仍爆）。** 是 amice lowering 的结构性开销：每条 LLVM 指令结果都需绑定 vreg，且在无 spill 的架构下，任何超过 31 个"某点并发活跃"的函数都无解——md5Transform 这种 29 指令的纯计算函数都不行。

## 4. 唯一可行路径（上游级特性，非补丁）

实现 **spill-to-stack**：
- VM ISA 增加"内存操作数"（vreg 溢出槽：`spill[slot]`）
- bytecode 编码器/解码器支持该操作数种类（`OperandKind` 扩展 + profile 的 bytecode.vm/decoder.vm 声明）
- runtime 解释器生成对应的 load/store 序列
- lowering 分配器：x 池耗尽时把 pinned 值转 spill 槽，使用时临时载回

工程量：跨 4 个 crate（isa/bytecode/lowering/runtime + amice profile DSL），数天量级，需完整测试。**这是给上游的正确提案方向，不是本地能安全打补丁的范围。**

## 5. 处置

1. 插件已恢复原版（生产链路无变化：VMP 仍只作用于画像内函数如 fnv1a64）；
2. 补丁 v2 源码留在 `~/amice-lab/amice-src`（VM）与本地 amice-master（未提交 git，避免污染上游基线）；
3. 建议向 fuqiuluo 提 issue：附本报告的实测矩阵 + `global_last_uses` 补丁思路（可先合并为缓解项）+ spill 特性提案。
