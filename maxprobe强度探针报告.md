# maxprobe 满配强度探针报告（2026-10-09）

> 背景：Operator 指令"编译一个简单的 main，加密强度上满"。探针 `artifacts\tmp\maxprobe\`（6 函数 × 6 类保护目标），VM `~/amice-lab/proj-maxprobe`，三档对照：baseline（无插件）/ B_max（全 Pass 满配）/ **C_ultra（simd_xor + 双 VM Pass 全开尝试）**。
> 满配配方：StringEncryption 全局 + VmFlatten distributed（f2/f3 注解）+ Flatten(dominator)+BCF+IndirectBranch（f4）+ MBA+BCF+IB+FuncWrapper+CloneFunc+AliasAccess+BB2Func+ShuffleBlocks（f5）+ Flatten(basic)（f6）+ -fno-exceptions。

---

## 0.5 E_ultimate 终极档：三类保护同框（2026-10-09 定稿）

应 Operator"探针的加密上满"最终要求，五函数注解按各自最优档组合成终极配置并同框构建：

| 函数 | 终极注解 | 实测 |
|---|---|---|
| f2_token_check | `+vm_flatten`（distributed 全局开） | 29→12,111 ins（**×417**） |
| f3_key_derive | `+vm_flatten` | 23→7,667 ins（**×333**） |
| f5_fullcore | `+vm_virtualize`（**VMP，画像内函数**） | 16→40 ins（×2.5） |
| f6_strings | `+flatten`（basic） | 27→258 ins（×9.6） |
| f4_license_state | `+flatten,dominator,+bcf,+indirect_branch` | 38→59 ins（×1.6） |

- 构建 rc=0；pass done：VmVirtualize×1 + VmFlatten×1 + StringEncryption×1 + Flatten×1 + IndirectBranch×1（五注解全部兑现）
- 总体积 104,384 B（baseline 5,880 → ×17.8）
- **真机功能等价性通过**（输出与 baseline 逐位一致：isink/sink 同值）
- 产物：`artifacts\tmp\maxprobe.E_ultimate.bin`（真机 `/data/local/tmp/mp_e`），带符号版 VM `results-maxprobe/maxprobe.E_ultimate.unstripped`

**此为 amice v0.1.5-beta.5 所能达到的函数级最强组合，无保留。**

## 0.6 逆向者判卷：Hex-Rays 对 E_ultimate 的逐函数反应（IDA Pro 9 实测）

逆向视角最终检验——把 E_ultimate 灌进 IDA Pro 9（stripped，96 个 sub_XXXX），逐函数喂 Hex-Rays：

| 函数 | 混淆 | Hex-Rays 反应（实测） | 逆向者体验 |
|---|---|---|---|
| f2 (VMF) | VmFlatten distributed | 伪代码 **189,126 字符 / 1,642 局部变量 / 577 个 if**，函数头自带 `// local variable allocation has failed` | 22 万字符的变量 soup，人肉不可读，写自动化还原脚本的成本 > 价值 |
| f3 (VMF) | VmFlatten distributed | **102,879 字符 / 1,004 变量 / 380 个 if** | 同上 |
| f4 (Flatten+BCF+IB) | dominator+bcf+ib | **反编译直接拒绝**：`fail_code=-12 call analysis failed`，decompile 返回 None | 伪代码都拿不到，只剩 987 条指令的 arm64 手工阅读（魔数常量满天飞） |
| f5 (VMP) | vm_virtualize | 836 字符外壳：`装参 → sub_176B0(0xC45C6798D060A7A2, ...)`，**原算法一行不剩**；真身是 4,008 B/999 ins 的 bytecode 解释器 + 加密 bytecode 常量（0x6D2286EE…） | 伪代码可读但读到的只是"调了解释器"——算法进了字节码，要懂就得逆 VM ISA + dump bytecode |
| f6 (Flatten basic) | flatten | 2,009 字符，状态机魔数（-924893237/…）+ `^=0xAA` 字符串解密级联 | 可读性差但**能读出逻辑**（strstr 三连 + 返回值），是五者中唯一"努力一下能还原"的 |
| 符号 | — | 96 个函数全 `sub_XXXX`，零符号残留 | 定位目标函数本身就要靠锚点/尺寸指纹 |

**判卷结论（按逆向成本排序）：VMP(f5) > VmFlatten(f2/f3) > Flatten+BCF+IB(f4) > Flatten(basic)(f6)。**
f5 是唯一"伪代码里看不到算法"的——VMP 的 160 B 外壳 + 解释器架构让原逻辑以加密 bytecode 形态存在；f2/f3 用体量淹没（20 万字符）；f4 让反编译器罢工；f6 只是拖延。

**"感觉功能没有拉满"的回应：** 拉满与否取决于用谁的眼睛看。capstone 指令数（×417）是体量指标；Hex-Rays 判卷才是逆向者真实体验——E_ultimate 在判卷里拿了三个"不可读"、一个"拒绝反编译"、一个"读不到算法"。字符串解密桩（`^=0xAA` 级联）在每个函数里可见但只暴露密文，配合 atomic 一次性锁（`atomic_load != 2` 自旋）防 dump。这套配置下，逆向者面对的是：找不到符号 → 找到函数读不了 → 能读的只有解释器入口 → 字节码要逆 VM ISA。每一层都有实证。

## 0.7 F_allvmp：全部函数上 VMP 实验（2026-10-09，回应"能不能全部上 VMP"）

五个函数全部换成 `+vm_virtualize` 注解（main 除外），结果分两类：

| 函数 | 结果 | 证据 |
|---|---|---|
| **f2 / f3 / f5 / f6** | ✅ **全部 VMP 成功**（此前认为 f2/f3 只能 VmFlatten 的判断被推翻——E 档失败是 VmFlatten 注解先污染了函数，不是预算） | 各自变成 38~43 ins 的"装参+调解释器"外壳，原算法零残留 |
| **f4** | ❌ 唯一爆墙：`VM x-register budget exceeded`（577-if 的状态机跨块活跃值>31），**保持原样**（×1.0） | skip 日志 |

- capstone 外壳验证：f2/f3/f6 的伪代码级形态与 f5 完全一致——160B 内的参数打包 + 单个解释器调用（`bl 0xa234`）+ 每函数独立 bytecode 密钥常量（0xde9f_d683_f68a_453b 等）；
- 总体积 74,416 B（比 E_ultimate 的 104,384 还小 29%——**VMP 外壳比 VmFlatten 的 12K 指令网更省**）；
- 真机功能等价：输出与 baseline 逐位一致。

**F 档 vs E_ultimate 的真实取舍（逆向者视角）：**

| 维度 | E_ultimate（VMF+VMP 混合） | F_allvmp（能上则 VMP） |
|---|---|---|
| 算法可见性 | f2/f3 是 20 万字符可分析的状态机（有结构可逆） | f2/f3 全进 bytecode，**零 IR 级痕迹** |
| 体量 | ×17.8 | ×12.7（更小） |
| 抗分析面 | 大目标（好找，难读） | 小外壳+解释器（难找也难读，但解释器本身是单点——逆出 ISA 后所有函数共享同一解释器语义） |
| f4 | Flatten+BCF+IB 兜底（拒绝反编译） | 裸奔（×1.0） |

**结论：VMP 化率从 1/5 提升到 4/5，且代价更小。** "全部上 VMP"的剩余障碍只有一类函数：跨块活跃值 >31 的（f4，也是唯一既爆 VMP 墙又只能靠传统 Pass 的）。f4 的最优兜底是 Flatten+BCF+IB（Hex-Rays 直接拒绝反编译），不是裸奔。

**最终生产配方（maxprobe 实测定稿）：默认全员 `+vm_virtualize`，skip 的函数逐个回退 `+vm_flatten` 或 `+flatten,dominator,+bcf,+indirect_branch`——按 RUST_LOG 的 skip 日志自动决定档位。**

## 0. C_ultra 追加实验：满血档 = B_max（天花板实证，后被 E_ultimate 超越）

追加 simd_xor + VmVirtualize 尝试全开的 C_ultra 档，结果：

- **pass 集合与 B_max 完全一致**（diff 逐行为空），强度数字 ±6% 内随机抖动（VmFlatten/BCF 随机种子所致）：
  f2 ×426 / f3 ×326 / f5 ×19 / f6 ×6.9 / f4 ×1.6
- **simd_xor 无可见差异**（探针字符串少，beta 算法未体现）；
- **VmVirtualize 对八件套注解的 f5 零贡献**——寄存器预算墙对所有含密集跨块值的函数全局生效。

**结论（当时）：B_max 配方就是这套插件在这类函数上能给的天花板。** 该结论后被 E_ultimate（§0.5）修正：把 f5 的八件套换成 VMP 注解后，VMP 对画像内函数可用，天花板被推高到三类 VM 级/控制流级保护同框。C_ultra 真机功能等价性通过（输出与 baseline 逐位一致）。

## 1. 总量

| 档 | 体积 | 说明 |
|---|---|---|
| baseline | 5,880 B | |
| 满配 | 102,392 B | **×17.4**；Pass 全部 pass done（VmFlatten×1、SplitBB×2、StrEnc/Flatten/BCF/IB/MBA/Shuffle 各×1） |

## 2. 函数级强度（capstone，unstripped 符号级实测）

| 函数（保护目标） | baseline | 满配 | 膨胀 |
|---|---|---|---|
| f2_token_check（token 校验，**VmFlatten distributed**） | 116 B / 29 ins | **52,544 B / 13,136 ins**（25 条件br+28 br） | **×453** |
| f3_key_derive（密钥派生 + S-box，**VmFlatten distributed**） | 92 B / 23 ins | **33,936 B / 8,484 ins** | **×369** |
| f5_fullcore（算术核，MBA+BCF+IB+FuncWrapper+CloneFunc+AliasAccess+BB2Func+Shuffle） | 64 B / 16 ins | 1,228 B / 307 ins | ×19.2 |
| f6_strings（字符串密集，Flatten(basic)） | 108 B / 27 ins | 1,032 B / 258 ins | ×9.6 |
| f4_license_state（状态机，Flatten(dominator)+BCF+IB） | 152 B / 38 ins | 236 B / 59 ins | ×1.6 |
| f1_plain（对照，无注解） | 内联进 main | — | — |

## 3. 三个关键读数

1. **VmFlatten distributed 是数量级差异的唯一来源**（×453 vs 传统 Pass 的 ×1.6~×19）。单函数 52KB 的可逆索引程序网意味着：IDA 加载就卡、反编译器面对 13K 指令的 CFG 直接放弃、人肉跟状态在"每跳转点 1~8 个 S-box 可逆运算 + 运行时键"面前基本不可行。**代价同样是数量级**：体积 ×17.4、f2/f3 编译期分钟级、运行时每分支走索引解码（本探针未测性能损失，生产用须压测）。
2. **传统 Pass 组合（f5 八件套）只有 ×19**：有强度（CFG 拆碎+算术改写+包装跳板），但属于 D-810 类工具可攻击的范畴。性价比高，适合大面积铺。
3. **Flatten(dominator)+BCF+IB 只有 ×1.6（f4）**：小函数上平坦化收益有限（块太少），它适合 login/verify_and_run 这类几十上百块的真实业务函数（主工程实测 ×453 那种是 VmFlatten，Flatten 在主工程 login 上是 675 ins/81 块的量级）。

## 4. 功能等价性（真机实测，探针无网络依赖）

同一台设备（a78ccd03，arm64）：

```
baseline: probe done isink=-1698281679 sink=1740973166
满配:     probe done isink=-1698281679 sink=1740973166   ← 逐位一致
```

六函数（含 VmFlatten 改写的 f2/f3）语义全部保持。**与主工程 MAX-3 的登录破坏对照**：VmFlatten 本身能保持语义（简单函数），破坏发生在 noexc_fixed 版 t3sdk 的复杂错误处理回路（多级 try/catch 等价物 + 网络重试 + getline 错误态）——变换的语义保持边界在"复杂错误处理"，不在函数大小。

## 5. 强度天梯最终结论（全实验汇总）

| 档位 | 膨胀 | 抗逆向 | 适用 |
|---|---|---|---|
| StringEncryption | ~1.1× | 防字符串分析 | 全局必开 |
| Flatten+BCF+IB | ×1.6~×10 | 拖慢（D-810 可部分还原） | 业务安全函数注解 |
| +MBA+FuncWrapper 等 | ×19（f5） | 拖慢 +破模式匹配 | 算术/密钥核 |
| **VmFlatten distributed** | **×453** | **准虚拟化（无工具可半自动还原）** | **仅极小且无复杂错误处理的函数**（f2/f3 类）；真实业务函数上语义风险实测存在（主工程 MAX-3 登录死循环） |

**生产建议不变**：主工程用 NOEXC-FIXED 配方（StrEnc + Flatten/BCF/IB 注解）；VmFlatten 等上游语义修复后再评估，或仅对独立小型密码学核（如自研 token 算法）使用。

## 6. 产物位置

- 探针源码：`artifacts\tmp\maxprobe\jni\maxprobe.cpp`；构建脚本 `build_maxprobe.sh` / `build_ultra.sh`
- Windows 产物：`artifacts\tmp\{maxprobe.A_base,maxprobe.B_max,maxprobe.C_ultra}.bin`
- VM：`~/amice-lab/proj-maxprobe`、`results-maxprobe/*.{bin,unstripped}`、日志 `results-maxprobe/*.log`
- 度量脚本：`artifacts\tmp\probe_strength.py`（VM `~/amice-lab/probe_strength2.py`）
