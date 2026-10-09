# T3Example Amice L2 混淆测试报告（决定性）

> 2026-10-09，Ubuntu VM `wthh@192.168.117.132:~/amice-lab/proj-t3`（SSH 免密直通，HANDOFF §4.2 阻塞解除）。
> 试验田：T3Example_AndroidJNI（main.cpp 248 行 + t3sdk.cpp，最小 T3 验证工程）。
> amice v0.1.5-beta.5 / NDK r30 linux bundle / arm64-v8a / android-21。
> 本报告结论直接修订 `T3加密保护设计.md` §3 的 VMP 假设。

---

## 1. 测试矩阵与结果总表

| 档 | 配置 | 产物 | pass done | 关键证据 |
|---|---|---|---|---|
| A_base | 无插件基线 | 391,816 B | — | 敏感串全明文 |
| B_str | 仅 StringEncryption | 424,088 B | Strenc×2 | **敏感串全清零** |
| C_full_exc | str+fla+bcf 全局 + VMP 注解，**保留异常** | 424,088 B（=B） | 仅 Strenc+CCC | **Flatten/BCF/IB 全部 0 次**——C++ 全灭 |
| D_full_noexc | 同 C 但 -fno-exceptions + 无异常源 | 435,496 B | Fla×1 BCF×1 IB×1 | **VMP 5 函数全 skip：VM x-register budget exceeded** |
| E_vmflat | 无异常源 + VmFlatten 分布式注解 ×5 | 6,324,768 B（14.5×） | VmFlatten×1 | **零 skip，5 函数全部 VM 平坦化成功** |
| F_vmp_O1 | 同 D 但 -O1 降优化 | 460,128 B | BCF×2 Strenc×2 | **VMP 依旧 5 函数全 skip**——降优化救不了 |
| G_vmflat_exc | VmFlatten 注解但**保留异常** | 514,264 B | VmFlatten×1 | **distributed skip 了 login/encodeParams/encrypt/heartbeat 4 函数** |
| 探针 | p1 极小函数→p4 指针解引用 | — | VmVirtualize×1 | p1/p2/p3 成功虚拟化；p4 死于"指针物化不支持" |

## 2. 四个定论（全部有 amice debug 日志原文背书）

### 定论 1：StringEncryption 完美可用，且不依赖异常开关 —— 可立即上生产
B 档（保留异常、SDK 源零改动）单独开启后，llvm-strings 审计全零：

| 关键词 | 基线 | B_str |
|---|---|---|
| t3yanzheng / t3data（域名） | 5 / 1 | **0 / 0** |
| kami / statecode（字段名） | 1 / 1 | **0 / 0** |
| PUBLIC KEY（RSA 公钥全文） | 2 | **0** |
| 76478CC2（调用码）/ fa98f186（APPKEY） | 1 / 1 | **0 / 0** |

T3 对接文档 §4 留给 L2 的全部明文，一个全局开关清零。**这是无需动 t3sdk.cpp、无需 noexc、风险最低的立即可交付项。**

### 定论 2：VMP（VmVirtualize）对 T3 核心函数判死刑 —— 设计文档 §3.1 作废
D 档和 F 档（-O2 与 -O1）同样 5 条 skip，原因一致：

```
skip function "...RSACrypto7encrypt...":  VM x-register budget exceeded: x0..x31 are available
skip function "...T3Verify12encodeParams...": VM x-register budget exceeded: x0..x31 are available
skip function "...T3Verify5login...":        VM x-register budget exceeded: x0..x31 are available
skip function "...T3Verify9heartbeat...":    VM x-register budget exceeded: no register outside native_call clobbers is available
skip function "...md5Transform...":          VM x-register budget exceeded: x0..x31 are available
```

amice 的 VMP 把 VM 操作数映射到 arm64 物理寄存器（x0..x31 共 31 个预算），这 5 个函数的活跃值需求结构性超预算；连 md5Transform 这种纯 C 小函数都超。第二道墙（探针 p4 证实）：**不支持指针参数的解引用物化**——login/encodeParams 的 `std::string&` 参数即使预算过了也过不了这关。降优化（-O1）无效。
探针同时证明 VMP 本身可用（p1/p2/p3 三个无指针小函数 pass done）——不是工具链问题，是函数画像不匹配，且无重构性价比（把 login 拆到"31 个寄存器内 + 无指针解引用"等于重写 SDK）。

**并行会话的"-fno-exceptions 才是 VMP 阻塞"理论被证伪为不完整**：noexc 之后 VMP 依然全 skip（寄存器预算才是根因）。为此付出的 noexc 改造（含 2026-10-09 token 校验事故）没有换来 VMP 收益。

### 定论 3：控制流类 Pass（Flatten/BCF/IndirectBranch/VmFlatten）在 C++ 代码上全部要求 -fno-exceptions
- C 档（保留异常）：全 C++ 工程，Flatten/BCF/IB **零次** pass done——`-fexceptions` 下所有调用是 invoke+landingpad，这些 Pass 全拒绝。
- **主工程推论（重要）**：主工程现有 amice 构建保留异常时，Flatten/BCF 的 29 次 pass done 全部来自 6 个纯 C 的 ghosttrace 文件；**main.cpp / t3sdk / ANativeWindowCreator 等 C++ 代码的控制流混淆实际为零**，只有字符串加密生效。
- G 档：VmFlatten distributed 在保留异常时 skip 了 login/encodeParams/encrypt/heartbeat 全部 4 个核心函数。
- E 档：无异常源 + -fno-exceptions 时，VmFlatten distributed 对 5 函数零 skip 全部生效（体积代价 424KB→6.3MB，14.5 倍）。

### 定论 4：VmFlatten distributed 是 T3 核心函数唯一可行的 VM 级保护，但生产前提是 noexc 源通过真机验证
E 档证明技术上可行。依赖链：

```
VmFlatten(login/encodeParams/encrypt/heartbeat)
  └─ 要求 -fno-exceptions
       └─ 要求 t3sdk.cpp 无 try/catch/throw（现版有 → 编不过）
            └─ 要求 t3sdk_noexc_fixed.cpp 语义等价【未真机验证，v1 版曾破坏 token 校验】
```

体积控制旋钮：`vm_flatten_program_variants`（默认 3，可降 2/1）、缩小注解函数集（建议先只 login + encodeParams 两函数）。

### 定论 5（2026-10-09 追加，主工程 MAX 系列实测）：VmFlatten 的三条共存规则

1. **同函数不得叠加 `+indirect_branch`/`+flatten` 注解**：主工程 login/encodeParams 最初同时挂 `AMICE_FLATTEN_H`（含 +indirect_branch）和 `+vm_flatten`，VmFlatten distributed **立即 skip**（拒绝已有间接跳转的函数）；去掉叠加注解只留 `+vm_flatten` 后可过。多 Pass 想都要时靠 AMICE_PASS_ORDER 顺序衔接，不要注解叠注解。
2. **编译开销是 15 分钟量级/文件**（distributed 默认 variants=3）：同配置同源码在 VM 空闲时 90 秒、高负载时 1033 秒（E5 重放实测）。主工程全套 Pass + -j8 曾把 7.7GB VM 的内存打爆（imgui_widgets.o OOM）——**全混淆全家桶 + ImGui 大文件 = OOM**，-j 不得超过 4~6，或按本报告 §3 路线 ImGui 裸编。
3. **-O3/-O2 都能编**（E3 的慢是负载不是 O3），但对 noexc_fixed 版 61KB 的 t3sdk.cpp，单文件 VmFlatten 阶段 >6 分钟起步，生产构建要预留时间或降 variants=2。

## 3. 修订后的 T3 保护路线（替代原设计 §3）

| 阶段 | 动作 | 依赖 | 状态 |
|---|---|---|---|
| **P0（现在）** | 修心跳 UAF（按值捕获，t3_gate.cpp:164） | 无 | 未做 |
| **P1（现在，零风险）** | amice 全局 StringEncryption 上生产（异常保留、源零改动） | 无 | **本报告已验证** |
| **P2（关键路径）** | t3sdk_noexc_fixed.cpp 真机全流程回归（登录/心跳/到期/token） | 设备 | 未做——VmFlatten 的唯一拦路虎 |
| **P3（P2 通过后）** | VmFlatten distributed 注解 login + encodeParams（variants=2 起步）+ A 级函数 Flatten(dominator)+BCF+IB（同样需 noexc） | P2 | 证据链已通 |
| ~~废弃~~ | ~~VMP(vm_virtualize) 上 T3 函数~~ | — | **结构性不可行，从设计移除** |

## 4. 遗留给并行会话（主工程）的三件事

1. 主工程 exc 构建的"C++ 混淆"实际只有字符串加密——GhostTrace 之外的 C++ 部分等于裸奔，请重估现有 dist 产物的混淆预期。
2. verify_l2.sh 的 [3] skip 检查依赖 debug 日志里的 VmVirtualize 行，但主工程最新构建的 t3sdk.cpp 里 **AMICE_VMP 注解已在 noexc 重写时丢失**——检查项空过不是因为没问题，是因为没人请求 VMP。
3. amice_annotate.h 的注释"VMP 需要 -fno-exceptions"应更正为："noexc 只是必要条件之一；arm64 上还有 x0..x31 寄存器预算墙与指针物化限制，实测 T3 五函数均不可 VMP，改用 VmFlatten distributed"。

## 5. 复现路径（VM）

- 工程：`~/amice-lab/proj-t3`（源码含 t3sdk_exc / t3sdk_noexc / t3sdk_vmf / t3sdk_vmfexc 四变体，5 函数注解齐）
- 脚本：`~/amice-lab/build_t3.sh`（A–D 档）、E–G 为手工命令（见 `results-t3/*.log`）
- 日志：`~/amice-lab/results-t3/{A_base,B_str,C_full_exc,D_full_noexc,E_vmflat,F_vmp_O1,G_vmflat_exc}.log`
- 产物：`~/amice-lab/dist/t3_cli.{A_base,B_str,D_full_noexc}.bin`
- 探针：`~/amice-lab/vmp_probe2.cpp`（寄存器预算/指针物化边界）
