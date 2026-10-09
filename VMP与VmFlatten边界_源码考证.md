# VMP 寄存器墙 与 VmFlatten 语义边界 —— amice 源码级考证（2026-10-09）

> 应 Operator 要求精读 `amice-master` 源码后的实现级结论。此前两个概念只有黑盒实验证据（T3Example 七档 + 主工程 MAX 系列），本文补上源码行号。
> 版本：本地 amice-master（crates/amice-vm/src + crates/amice/src/aotu/vm_flatten）。

---

## 一、VMP 寄存器墙（VmVirtualize）

### 1.1 现象回顾
T3Example 七档实验：login/encodeParams/RSACrypto::encrypt/heartbeat/md5Transform 五函数全部报
`VM x-register budget exceeded: x0..x31 are available`，-O1/-O2 无差别。

### 1.2 源码根因（三处，全部硬编码）

**① 分配器 32 上限** —— `crates/amice-vm/src/lowering.rs:3322`：

```rust
pub fn alloc_vreg(&mut self) -> anyhow::Result<u8> {
    if let Some(reg) = self.free_vregs.pop() { return Ok(reg); }
    if self.vreg_count >= 32 {                      // ← 墙在这
        anyhow::bail!("VM x-register budget exceeded: x0..x31 are available");
    }
    ...
}
```

**② ABI 逃逸池更小** —— 同文件 `alloc_vreg_excluding`（:3336）：含 native_call 的函数（所有调外部函数的 C++ 代码）要避开 clobber 集再分配，先用完 free 列表再从 0..32 找非排除槽，找满即报
`no register outside native_call clobbers is available`——这就是 heartbeat（内部调 httpPost）拿到的第二条报错的出处。

**③ 寄存器空间本身是枚举** —— `crates/amice-vm/src/abi.rs:19`：

```rust
pub enum VmRegister {
    X(u8),   // 注释明写"固定 x0..x31 组"
    Q(u8),   // q0..q64，且 profile 里 q.lowering=disabled 时 verifier 拒绝
}
```

**为什么是 32：** VM 寄存器是**物理 ARM64 寄存器的别名**，不是无限虚拟寄存器——bytecode 里的 VReg 操作数最终由 runtime 解释为对真实 x0..x31 的读写（这是"指令级虚拟化"的实现方式：VM 指令直接操作宿主寄存器堆）。bytecode 编码（bytecode.rs）用 profile 驱动的 operand 序列化，**编码层不限制 32**，所以这堵墙理论上一条 PR 就能拆（vreg_count 溢出到更多宿主寄存器不行——arm64 只有 31 个通用寄存器可用——但换成"溢出 vreg 落栈"的混合分配可以）。**这是实现选择，不是数学必然**；上游 issue 修了它，T3 五函数理论上就能上 VMP。
**q 寄存器（q0..q64，64 个）本可以当溢出池用，但 lowering 默认 disabled**（abi.rs 头部注释），等于备胎被锁在库里。

**为什么 LLVM 的无限虚拟寄存器模型会撞墙：** VMP 的 lowering 是线性扫描（每条 IR 指令翻译成 VM 指令时按需 alloc_vreg，SSA 末尾 release_vreg 复用），**没有寄存器分配器**（不做图着色/线性扫描的活跃区间分析）。大函数活跃值一多就爆。login 有几十个 std::string 中间值同时活跃 → 29 条指令的 md5Transform 都爆（MD5 轮内有 16 个状态字活跃）。

### 1.3 判决
结构性限制 = 「**无寄存器分配器的物理寄存器直接映射**」架构决策。绕过方法只有三种：①上游加溢出到栈的混合分配（合理 PR）；②把目标函数手写成活跃值 ≤31 的形态（等于手写汇编）；③用 q 寄存器池（需 profile 开 q.lowering）。当前版本对 T3 类函数无解——实验与源码互证。

## 二、VmFlatten 语义边界（distributed 模式）

### 2.1 现象回顾
主工程 MAX-3：VmFlatten 成功作用 login/encodeParams 后，真机登录失败路径变成"请输入卡密→卡密不能为空"EOF 死循环；NOEXC-FIXED 同网络同设备行为正常。

### 2.2 源码根因（三层改写，每一层都在动控制流）

**① 资格检查只排除五类结构** —— `crates/amice/src/aotu/vm_flatten/distributed.rs:666`：

```rust
fn eligible(function: FunctionValue<'_>) -> bool {
    // 排除: 块数<2 / 有personality(异常) / 已处理过 / naked / COMDAT ExactMatch|SameSize
    ...
    function.get_basic_blocks().iter().all(|block| {
        !block.has_address_taken()          // 块地址没被取过
            && !block.is_eh_pad()           // 不是 EH pad
            && terminator ∈ {Br, Switch, Return, Unreachable}   // ← 关键
    })
}
```

注意 terminator 白名单**只认 Br/Switch/Return/Unreachable**——这是它拒收 `+indirect_branch` 先行注入函数的原因（IndirectBr 不在白名单，MAX-3 定论 5 的源码出处）。但这个检查**全部是结构性的，没有语义层检查**：getline 的 EOF/错误流、重试逻辑、多级错误传播，全都不在排除列表里——变换会照做。

**② 每条边被展开成"认证网关 + 有界重试图 + 拒绝沉底"** —— distributed.rs:1189-1332。每条原本无条件/有条件的跳转变成一个网关块群：

- 网关校验解码出的 tag（`predicate`）→ 成功走 continuation，失败进 retry；
- retry 通路有 **retry_budget（随机 3~9 次，:1136）** 和 retry_entropy（volatile 混淆比较），预算耗尽进 reject；
- **reject 不是退出，是 volatile 死循环** —— distributed.rs:1333-1341 原注释：

```
// A failed authentication is semantically unreachable for a valid VM
// transition. Keep the final recovery arm as a live, volatile sink loop
// instead of emitting an explicit `unreachable` terminator...
```

sink 函数本体（:528-600）就是个自旋：`sink_loop → 校验 → 不合法则 XOR 混淆后 continue → 合法才 return`。**设计假设是"网关认证失败在语义上不可达"（valid VM transition），所以沉底自旋无害。**

**③ PHI 修复只管整数** —— phi_transport.rs:37-40：

```
// Pointer, vector, floating-point and aggregate PHIs keep their original
// values; only their predecessor blocks are repaired.
if value.is_int_value() {
```

**指针/浮点/聚合类型的 PHI 不重建值，只修前驱块。** C++ 里 `std::getline` 的流状态、错误标志位经 i1/ibyte PHI 传播——这些是整数，会重建；但 iostream 内部指针状态的 PHI 不重建。**混合类型 PHI 网络在 CFG 大规模重写后的边一致性问题，就是这个死循环的嫌疑核心**（推测级，需对 MAX-3 产物做 IR diff 才能定罪到具体一条 PHI）。

### 2.3 为什么探针全过而 t3sdk 翻车
maxprobe 六函数（含 VmFlatten 的 f2/f3）真机逐位一致——它们是**纯计算函数**：入参值决定一切，无外部状态、无错误传播、无流状态。t3sdk 的 login 是**错误处理密集型**：httpPost 失败 → error 串 → getline EOF → 流错误位 → 多层 if/continue——每一条边都被翻译成"网关+预算重试+volatile 沉底"，任何一层对边语义的近似都会在错误路径上放大成死循环。**普通路径（登录成功）在 MAX-3 真机上其实是走通了的**（此前实测登录成功、心跳正常），坏的全是异常路径——与"网关认证失败→沉底自旋"的设计假设吻合：**当 tag 校验真的失败时（网络错乱响应），代码进了设计上"不可达"的 reject 自旋**。

### 2.4 判决
语义边界 = 「**变换只保证结构合法函数的"正常路径"语义，错误/异常路径依赖 '认证失败不可达' 的理想化假设**」。对纯计算函数成立（探针实证），对网络错误处理函数不成立（MAX-3 实证）。上游若把 reject 从自旋改成"回退到原始边"（fail-open to original edge），边界即可收窄。当前版本：**VmFlatten 只用于无错误路径的独立小函数**（如自研密码核），业务函数禁用——与 L2_MAX版终审记录.md 的判决一致。

## 四、拆墙可行性终审（2026-10-09 追加：源码深挖结论）

应 Operator"继续给 main 上完全"的要求，评估了绕墙的全部路径，**全部堵死，且比预想更彻底**：

| 绕墙路径 | 源码证据 | 判决 |
|---|---|---|
| 改 profile 开 `q.lowering = enabled` | `runtime.vm:4` 有这行配置；但 `runtime.rs:82` 的 `pub enum WideRegisterPolicy { Disabled }` **只有一个变体**——枚举里根本没有 Enabled | 解析层直接不认识，改了配置包都过不了 parse/verify |
| q 池当整数溢出池 | `runtime.rs` 全文 **0 处 `Q(` 引用**；translator.rs 全部分配走 `alloc_vreg`（x 池） | q 寄存器堆在 runtime 状态模型中**未实现**，ISA 声明的 q0..q64 是纸面能力 |
| 改 Rust 源码实现 q 池 | 需实现 128-bit 寄存器堆读写、全部 VM 指令的 q 变体、runtime 解释器扩展——`runtime.rs` 9843 行的等比扩展 | feature 级工程，非补丁；且 x→q 混存 64-bit 整数还要改 ABI 校验 |
| 加大 x 池（>32） | `alloc_vreg` 上限 = 物理寄存器堆大小，arm64 通用寄存器就 31 个 | VM 直接操作宿主寄存器的架构使这条天然封死 |
| VMP 对小函数 | 探针 f2/f3 实测可用（×426/×326） | **唯一已通的路**——但要求函数活跃值 ≤31 且无指针解引用物化 |

**终审判决：`amice v0.1.5-beta.5` 的 VmVirtualize 能力边界就是当前探针展示的形态。** "完全上满"在插件层的极限 = B_max/C_ultra 配方 + 对符合画像（活跃值≤31、无指针物化、无复杂错误路径）的函数追加 `+vm_virtualize` 注解。要突破只能：①等上游实现 WideRegisterPolicy::Enabled + q 堆；②自研 VM（终审记录 §8.4.3 路线）。

## 4.5 上游核实（2026-10-09，应 Operator"GitHub 上真不行吗"质询）

对照 https://github.com/fuqiuluo/amice 做了三方核对，**结论：本地源码就是最新上游，不存在"我们看的是旧版"的可能**：

| 核对项 | 结果 |
|---|---|
| 本地 HEAD | `e4ac4f9`（2026-10-09 17:17），remote 指向 github.com/fuqiuluo/amice —— 与上游 GitHub HEAD **同一提交** |
| 最新 Release | v0.1.5-beta.5（2026-10-03，与我们实测用的 bundle 同版），修复仅 indirect-branch LTO 一项 |
| 上游 commit 检索（近 30 条） | **无任何** register allocation / vreg / spill / WideRegisterPolicy / q 相关提交；vm_virtualize 相关只有 LLVM 23 适配与 side-effect 保留 |
| 上游 issue 检索（#81/#60/#15/#51） | **零条**寄存器预算/q 池相关 issue——没人报过这个限制，也没有修复计划 |
| 版本号 | Cargo workspace 未标 version 字段（beta 阶段按 release tag 走），无进行中的大版本重构迹象 |

**补充源码发现（解释为什么墙在"大函数"而不是"所有函数"）：** translator.rs:2428 有个 `ReusePlan` 机制——**块内** SSA 临时值有基于最后使用位置的寄存器回收（`block_last_uses` → `release_vreg`），所以 16 指令的 f5 只需 ~6 个寄存器就能跑；但**跨块活跃值和所有 PHI 被无条件 pinned**（`translator.rs:2810-2850`：跨块引用/PHI → `pinned_values`，永不回收）——这是保守正确的选择（VM bytecode 可能绕过本应重新分配的块），代价就是 login 这类跨块值密集的函数必然爆 32。**墙的本质：只有块内线性回收，没有跨块的图着色/liveness 全局分配。**

**行动结论（三选一，按性价比排序）：**
1. **提 issue 给 fuqiuluo**：把我们的实验数据（五函数 skip 日志 + f5 成功画像 + ReusePlan 局限分析）整理成 issue——这是上游 zero-issue 领域，接受率高；
2. **自己提 PR**：跨块 pinned 值的"栈溢出 vreg"（spill slot 映射为 VM 内存操作数）是标准编译器技术，改动集中在 lowering.rs 的 alloc_vreg/excluding 两函数 + bytecode 增一种 SPILL 操作数编码——中等工程量，风险在 runtime 解释器同步；
3. **接受现状**：画像内函数用 VMP（f5 ×2.5 实证），画像外用 VmFlatten/Flatten 替代——当前生产包（NOEXC-FIXED）已是此策略。

作为验证闭环，给探针的无指针对象函数（f5_fullcore，纯算术、活跃值少）追加 VMP 注解做最后一次实测——若通过，则确认"VMP 对小函数可用"结论并可写出精确的画像描述。

## 五、D 档实测闭环：VMP 精确画像成立（2026-10-09 最终实验）

f5_fullcore 换成纯 `+vm_virtualize` 注解（撤掉八件套），D 档构建：

- **`(VmVirtualize) pass done` 历史首次在真实探针函数上出现**（此前所有 skip 均为预算墙）；
- f5：16 ins → 40 ins（×2.5）——VMP 虚拟化本体膨胀不大（字节码 + 解释器桩），配合其余 Pass 无叠加；
- 真机功能等价性通过（输出与 baseline 逐位一致）。

**VmVirtualize 可用画像（实测版）：**

```
✅ 可 VMP：纯算术/位运算、活跃值 ≤ 31、参数与返回值为标量、无指针解引用物化、无异常、无外部调用或调用数极少
❌ 不可 VMP：活跃值 > 31（md5Transform 级别的状态字数即爆）、std::string/vector 等指针密集对象、
           含 native_call 的函数（clobber 池再扣一笔）、任何真实业务函数（T3 五函数全军覆没实证）
```

**"完全上满"最终形态 = B_max 配方 + 对画像内函数追加 `+vm_virtualize`**。D 档产物 `artifacts\tmp\maxprobe.D_vmp.bin`（110,824 B），VM `results-maxprobe/maxprobe.D_vmp.{bin,unstripped}`。

| 边界 | 源码位置 | 本质 | 何时触发 | 绕过 |
|---|---|---|---|---|
| 寄存器墙 | lowering.rs:3322/3336, abi.rs:19 | 无寄存器分配器的物理寄存器直接映射（x0..x31 硬编码，q 池禁用） | 函数活跃值 > 31（native_call 还要扣 clobber 池） | 上游 PR：溢出 vreg 落栈混合分配；或开 q.lowering |
| 语义边界 | distributed.rs:666(eligible)/1333(reject自旋)/phi_transport.rs:37(PHI只修整数) | 网关认证失败被假设"不可达"，沉底自旋；PHI 修复只覆盖整数 | 函数含真实可达的错误路径（网络失败/流 EOF） | 上游改 fail-open；或只混纯计算函数 |
