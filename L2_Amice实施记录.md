# L2 Amice 实施记录（2026-10-09 会话）

> 本文件是 L2 落地的**权威进度记录**，替代 `HANDOFF_Amice接入手册.md` §4 的"待实施"状态。
> 前置阅读：`HANDOFF_Amice接入手册.md`（L0/L1/L3 现状）、`L2_加密设计分析.md`（保护分级）、`T3加密保护设计.md`（S 级对象）。
> 本文件是会话产物，**不建议提交 git**。

---

## 0. ⚠️ 事故记录：异常自由化改造破坏了 token 校验（已回退）

### 0.1 事实

为了让 amice 的 Flatten/VMP 生效（它们拒绝含 `invoke`/`landingpad` 的函数，而 `-fexceptions` 会把含 `std::string` 局部量的函数里所有调用都变成 `invoke`），本次把 `jni/src/t3sdk/t3sdk.cpp` 改成了"异常自由"：用文件级错误槽 `g_t3_error` + `t3_raise/t3_failed/t3_take_error` 取代全部 `try/catch/throw`，并全工程 `-fno-exceptions`。

**结果：真机上卡密 token 校验失效。该改造已整体回退**，`jni/src/t3sdk/t3sdk.cpp` 恢复为 `try/catch/throw` 原样（= 当前 HEAD），VM 上所有用异常自由版源码构建的产物（`reverify` / `noexc-v1` / `exp-tweaks` / `FINAL2`）已全部删除，避免误发。

### 0.2 根因（按改造设计反推，症状吻合）

错误槽是**文件级、只写不清**的单一全局状态，而检查点是**散布在各函数开头**的 `if (t3_failed())`。原始代码里每个函数有自己的 `try/catch`，作用域隔离——`getNotice()` 失败不会影响 `login()`。

改造后：

```
verify_and_run()
 ├─ getLatestVersion()   ← 失败/异常时把错误写进全局槽
 ├─ getNotice()          ← 同上
 └─ login()  →  checkInit(); if (t3_failed()) { result.error = t3_take_error(); return result; }
                                  ^^^^^^^^^^^^^^^^ 这里读到的是【前面任何一个请求】残留的错误
```

`httpPost` 在多服务器之间轮询、`getNotice/getLatestVersion` 允许返回非 200，这些"局部可恢复失败"一旦发生就把错误槽点亮，于是**后面正常的 login 被误判为失败**——表现就是"卡密正确却登录不上 / token 校验失败"。

同一根因还有第二个副作用：`login` 内部 `decodeResponse` 之后的 `if (t3_failed())` 同样会被前序残留污染。

### 0.3 结论与约束

- **禁止**在没有真机验证的情况下，用"文件级全局错误槽"替换 T3 SDK 的异常处理。异常处理的作用域语义是它的一部分，不能当纯语法糖删掉。
- **禁止**为了混淆而改动付费门禁的控制流/错误语义——L2 的收益远小于门禁失效的代价。
- 构建脚本已加**硬闸门**：`AMICE_NO_EXCEPTIONS=1` 时若 `t3sdk.cpp` 仍有 `try/catch/throw`，直接拒绝构建（`exit 3`），宁可不构建也不出错产物。
- 因此 **`-fno-exceptions` 这条路线在本工程关闭**；L2 回到"保留异常"的现实边界（见 §0.4 / §8）。

### 0.4 修正后的 L2 交付边界（保留 `-fexceptions`）

| 手段 | 状态 |
|---|---|
| amice `StringEncryption` 全局 | ✅ 生效（27 条特征 0 明文残留） |
| amice `Flatten(basic)` + `BOGUS_CONTROL_FLOW` 全局 | ✅ 生效，但**只覆盖不含异常处理 IR 的函数**（实际主要是 ImGui 等第三方代码） |
| 17 处函数注解（`AMICE_FLATTEN_H`） | ⚠️ 在 `-fexceptions` 下**被 amice 静默跳过**（日志：`has exception handling instructions, skipping`）。注解本身无害（未加载插件时是空宏），保留供将来使用 |
| amice `VmVirtualize` | ❌ 不可用（双重原因：`invoke` 屏障 + VM 只有 x0..x31，见 §8） |

**T3 门禁的真实防线回到：** `appkey`/调用码/公钥的编译期加密（L1）+ 即用即毁（L1.5）+ 完整性自检与反调试（L1.6/L1.9/L3）+ 服务端校验本身。**不要指望 L2 混淆保护门禁。**

### 0.5 修复版（NOEXC-FIXED）—— 已构建验证，**待真机回归**

不推翻异常自由化，而是**把作用域补回来**（源文件：`artifacts/tmp/t3sdk_noexc_fixed.cpp`，61446 B；VM 侧产物：`dist/AndroidSurfaceImguiEnhanced.NOEXC-FIXED.bin`，本机副本 `artifacts/L2/ASIMGUI-amice-NOEXC-FIXED-6.38MB.bin`）：

| 修复点 | 位置 | 作用 |
|---|---|---|
| `static std::string g_t3_error` → `static thread_local std::string` | 第 55 行 | 消除心跳线程/主线程并发访问错误槽的数据竞争 |
| 新增 `t3_clear_error()` | 第 58 行 | 清槽原语 |
| `parsePEM` 入口清槽 | 第 393 行 | 槽只反映本次解析结果 |
| `CustomBase64` 构造入口清槽 | 第 521 行 | 同上 |
| **`checkInit` 入口清槽** | 第 945 行 | **核心修复**：`login`/`simpleRequest` 开头的 `checkInit(); if(t3_failed())` 不再读到前一次请求（公告/版本/其它接口）的残留错误 |
| `httpPost` 入口清槽，且 `t3_raise` 只在**所有服务器都失败后**执行一次（成功路径直接 `return response`） | 第 1002 / 1019 行 | 多服务器轮询中"前面失败、后面成功"不再被误判 |
| 撤销 `t3_check_login_token` 抽取，token 校验**逐字回到真机验证过的内联形态** | 第 1063-1072 行 | 不在门禁算法与调用形态上做任何顺手改动 |

验证结果（`results/NOEXC-FIXED.log`）：

| 项 | 结果 |
|---|---|
| 编译 | ✅ 通过（6 376 160 B，`--tag NOEXC-FIXED`） |
| 代码级 `try/catch/throw` | 0 处（仅 1 行注释命中） |
| strings 审计 | ✅ 明文残留 **0**（42 393 条字符串） |
| 敏感函数 skip | ✅ **0 条**——17 处注解（`verify_and_run` / `integrity_check` / `ANativeWindowCreator::Create` 等）全部生效 |
| Pass | StringEncryption 29 / Flatten 29 / BCF 28 / IndirectBranch 5 |
| VMP | 仍 0（§8 已定论：与异常无关，是 VM 只有 x0..x31 的硬限制） |
| **真机卡密全流程** | ⏳ **未做——能否发布的唯一门槛** |

推送测试：
```powershell
adb push artifacts\L2\ASIMGUI-amice-NOEXC-FIXED-6.38MB.bin /data/local/tmp/imguiobf.sh
adb shell "su -c 'chmod 755 /data/local/tmp/imguiobf.sh'"
adb shell "su -c '/data/local/tmp/imguiobf.sh'"      # 前台，手动输卡密
```
必须验证：① 手动输卡密**登录成功** ② `.t3card` 自动登录成功 ③ 60 s 心跳不报错、持续 >10 分钟不崩
④ 故意输错卡密能正确报"token校验失败"（确认失败路径也没被改坏）。

**四项全过之后**，才可以把 `artifacts/tmp/t3sdk_noexc_fixed.cpp` 覆盖回 `jni/src/t3sdk/t3sdk.cpp`。在那之前仓库保持原始 `try/catch` 版本（门禁已验证可用）。

---

## 1. 阻塞项已解除：Ubuntu 虚拟机访问方式

HANDOFF §4.2 的唯一待答问题（"Ubuntu 虚拟机如何访问项目文件"）已确认并打通：

| 项 | 值 |
|---|---|
| SSH 别名 | `wthh-vm`（`~/.ssh/config` 已配，密钥 `~/.zcode/vm_wthh_key`，免密） |
| 地址 | `192.168.117.132:22`（VMware VMnet8，宿主机侧 `192.168.117.1`） |
| 账号 | `wthh`（Ubuntu 24.04, kernel 7.0.0-34, 16 核 / 7.7 GB RAM / 根分区剩 55 GB） |
| amice bundle | `~/amice-lab/amice-android-ndk-r30-linux-x86_64`（**已存在**，10-03 解压，831 MB tar 在 `~/amice-lab/bundle.tar.gz`） |
| bundle 元数据 | NDK r30 / LLVM llvm21-1 / Android clang r574158c / host linux-x86_64 |
| VMP profile | `~/amice-lab/myprofiles/amice-simple-vmp`（内置档）+ `ruoke`（自定义档） |
| 传输方式 | Windows 侧 `tar.exe` 打包 → `scp` → VM 解压（本机无 bash，PowerShell） |

VM 上另有一个**旧工程** `~/amice-lab/proj`（feiche / 飞车 overlay，10-06 会话产物，带 `Android_ace`/`Android_speed`/`Android_patch` 等模块，与本次的 `AndroidSurfaceImgui-Enhanced` 是两条产品线）。本次新建独立目录 **`~/amice-lab/proj-asimgui`**，互不干扰。

---

## 2. 本次新增的工具（都在 VM 的 `~/amice-lab/`）

| 文件 | 作用 |
|---|---|
| `build_asimgui.sh` | 一键构建：bundle NDK r30 + amice 插件 + strip + 产物隔离到 `dist/`；开关 `--baseline/--no-vmp/--no-str/--no-flat/--no-bcf/--no-drop-demo/--no-strip/--exceptions/--log/--tag/-j N` |
| `audit_strings.sh` | 产物字符串审计（27 条特征，baseline/加固后对比用） |
| `proj-asimgui/jni/tools/strip_elf.py` | 从旧工程复制过来的发布后处理（删节头/清零节表/打乱节名/随机 note） |
| `results/*.log` | 每次构建的完整 amice 日志（RUST_LOG=amice=debug） |
| `dist/*.bin` | 构建产物（baseline / amice 各档） |

Windows 侧新增（`E:\download\AndroidSurfaceImgui-Enhanced加密\artifacts\tmp\`）：

| 文件 | 作用 |
|---|---|
| `annotate_amice.py` | 幂等给工程打/撤 L2 函数注解（`--check` 只体检，`--revert` 撤销） |
| `build_asimgui.sh` / `audit_strings.sh` / `vm_patch_mk.py` | 上表的源文件（改完 scp 到 VM） |

---

## 3. 已落地的源码改动

### 3.1 新增 `jni/include/My_Utils/amice_annotate.h`

编译期注解宏（未加载 amice 插件时 clang 直接忽略，零运行时开销）：

```cpp
#define AMICE_VMP        __attribute__((noinline, annotate("+vm_virtualize,vm_runtime_scope=func")))
#define AMICE_FLATTEN_H  __attribute__((noinline, annotate("+flatten,flatten_mode=dominator,+bcf,+indirect_branch")))
#define AMICE_FLATTEN_B  __attribute__((noinline, annotate("+flatten,flatten_mode=basic,+bcf")))
#define AMICE_NOFLAT     __attribute__((annotate("-flatten,-bcf,-vm_virtualize")))
```

### 3.2 16 处函数注解（`/*L2AMICE*/` 标记，可 grep 定位）

| 文件 | 函数 | 档位 |
|---|---|---|
| `jni/src/t3sdk/t3sdk.cpp` | `md5Transform` / `md5Update` | **VMP** |
| | `RSACrypto::encrypt` | **VMP** |
| | `T3Verify::encodeParams` | **VMP** |
| | `T3Verify::login` | **VMP** |
| | `T3Verify::heartbeat` | **VMP** |
| | `jsonGetString` / `getMachineCode` / `T3Verify::initRSA` / `T3Verify::decodeResponse` | Flatten(dominator)+BCF+IndirectBr |
| `jni/src/t3_gate.cpp` | `t3::verify_and_run` | Flatten(dominator)+BCF+IndirectBr |
| `jni/src/main.cpp` | `security_ok` | Flatten(dominator)+BCF+IndirectBr |
| `jni/src/security_extra/anti_extra.cpp` | `integrity_check` / `frida_extra_check` | Flatten(dominator)+BCF+IndirectBr |
| `jni/include/native_surface/ANativeWindowCreator.h` | `SurfaceComposerClient::CreateSurface` / `ANativeWindowCreator::Create` | Flatten(dominator)+BCF+IndirectBr |

### 3.3 `jni/Android.mk`

- 新增 `AMICE_PLUGIN_FLAG` 注入（`LOCAL_CFLAGS` + `LOCAL_CPPFLAGS`，命令行传 `-fpass-plugin=<bundle>/amice/lib/libamice.so`）。
- 新增 `AMICE_NO_EXCEPTIONS=1` 条件段（`-fno-exceptions`，不注入时行为与原构建一致）。
- 新增 `AMICE_DROP_DEMO=1` 条件段（`-DIMGUI_DISABLE_DEMO_WINDOWS`，堵缺口 B）。
- `LOCAL_C_INCLUDES` 补 `include/native_surface`。

### 3.4 amice 运行参数（`build_asimgui.sh` 内，全档默认）

```
AMICE_PASS_ORDER = StringEncryption,Flatten,BogusControlFlow,VmVirtualize,IndirectBranch
AMICE_STRING_ENCRYPTION=true   AMICE_STRING_ALGORITHM=xor   AMICE_STRING_DECRYPT_TIMING=lazy
AMICE_STRING_ONLY_DOT_STRING=true
AMICE_FLATTEN=true             AMICE_FLATTEN_MODE=basic
AMICE_BOGUS_CONTROL_FLOW=true  （prob=80, max_regions=2, max_region_instructions=8，默认轻档）
AMICE_VM_VIRTUALIZE=false      ← 全局关，只让函数注解 +vm_virtualize 触发
AMICE_VM_RUNTIME_SCOPE=func    AMICE_VM_EMIT_MARKERS=false（生产档关 marker）
AMICE_INDIRECT_BRANCH=false    ← 全局关，只由 A 级注解 +indirect_branch 触发
AMICE_VM_FLATTEN=false
```

> **修正**：`L2_加密设计分析.md` §3.2 给的 pass 列表漏了 `VmVirtualize`，而 `AMICE_PASS_ORDER` 是**允许列表**——漏掉它函数注解 `+vm_virtualize` 也不会跑。已在本记录的配置里补上。

---

## 4. 构建结果与实测证据

### 4.1 基线（无插件，NDK r30，Windows 侧原样源码）

| 项 | 值 |
|---|---|
| 编译 | 成功，16 s（-j8） |
| 产物 | `dist/AndroidSurfaceImguiEnhanced.linux-r30-baseline.bin`，**2 997 128 B**，md5 `ef1c68e185ccaf62651bf0f8d31233d5` |
| 与 Windows 侧产物对照 | `imguiobf.sh` = 2 997 096 B（差异来自工作区未提交的 T3 心跳 UAF 修复） |
| strip | 已执行（节表清零，`Start of section headers = 0`） |
| **strings 明文残留 13 项** | `frida-agent`×1 / `frida`×1 / `gum-js`×2 / `xposed`×3 / `XposedBridge`×2 / `de.robv.android.xposed`×2 / `dear imgui says hello`×1 / `imgui_demo.cpp`×4 / `t3yanzheng`×5 / `t3data`×1 / `statecode`×1 / `kami`×1 / `/proc/self/exe`×1 |

→ 实测确认了 `L2_加密设计分析.md` 的缺口 A（GhostTrace 检测串）、缺口 B（imgui_demo 死代码）、以及 T3 对接文档 §4 列的 SDK 内部明文，全部为真。

### 4.2 amice v1（全局开 StringEncryption + Flatten(basic) + BCF + IndirectBranch，**保留 -fexceptions**）

| 项 | 值 |
|---|---|
| 编译 | 成功 |
| 产物 | **5 565 784 B**（+85.7%），md5 `bea24e9600342d5f86595dbcf4865e59` |
| **strings 残留** | **0 项**（27 条特征全绿，含 frida/xposed/imgui_demo/t3yanzheng/kami） |
| Pass 执行统计 | StringEncryption ×29、Flatten ×29、BogusControlFlow ×27、IndirectBranch ×5 |
| **VmVirtualize** | **一次都没跑** |

### 4.3 致命发现：`-fexceptions` 会让**所有**函数注解失效

amice 自己的日志（`results/linux-r30-amice-vmp-str-fla-bcf-nodemo.log`）原文：

```
(VmVirtualize) skip function "RSACrypto::encrypt": invoke exception edges are not supported by vm_virtualize
(VmVirtualize) skip function "T3Verify::login":    invoke exception edges are not supported by vm_virtualize
(VmVirtualize) skip function "T3Verify::heartbeat":invoke exception edges are not supported by vm_virtualize
(VmVirtualize) skip function "T3Verify::encodeParams": function has non-call address uses
(VmVirtualize) skip function "md5Update":  undef/poison values must be frozen before VM materialization
(VmVirtualize) skip function "md5Transform": VM x-register budget exceeded: x0..x31 are available

(flatten-enhanced) function "t3::verify_and_run" has exception handling instructions, skipping
(flatten-enhanced) function "ANativeWindowCreator::Create" has exception handling instructions, skipping
(flatten-enhanced) function "anti_extra::integrity_check" has exception handling instructions, skipping
(flatten-enhanced) function "T3Verify::initRSA" has exception handling instructions, skipping
(flatten-enhanced) function "T3Verify::decodeResponse" has exception handling instructions, skipping
(flatten-enhanced) function "getMachineCode" has exception handling instructions, skipping
(flatten) function "T3Verify::login" has exception handling instructions, skipping
```

**结论**：`-fexceptions` 下，任何含非平凡局部对象（`std::string` / `std::vector`）的函数都会把跨函数调用编译成 `invoke` + `landingpad`（异常时跑析构），而 amice 的 VmVirtualize 与 Flatten **都拒绝**这类函数。于是 v1 的 +85.7% 体积全部花在混淆 ImGui 上，**所有敏感函数一个都没被混淆**——等于白做。

→ `-fno-exceptions` 不是可选优化，是 L2 生效的**前置条件**。

### 4.4 amice v2（把 t3sdk.cpp 拆成独立静态库，主模块 -fno-exceptions）— 失败，已否决

思路：t3sdk.cpp 是唯一用 try/catch 的文件，拆成 `libt3sdk.a` 保留 `-fexceptions`，主模块 `-fno-exceptions`。

| 项 | 值 |
|---|---|
| 产物 | 5 620 936 B |
| 结果 | **主模块仍然被追加 `-fexceptions`**，`verify_and_run` / `ANativeWindowCreator::Create` / `integrity_check` 依旧全部 skipped |

根因（`ndk-build -n` 干跑抓到编译命令实测）：
```
... -fno-exceptions -fpass-plugin=... -fexceptions -c t3_gate.cpp
                              ^^^^^^^^^^^^ 由 ndk-build 追加，在最后 → clang 取最后一个，异常仍然是开的
```
机制在 NDK 的 `build/core/definitions.mk`：
- `module-handle-c++-features` 会**从依赖模块继承 C++ feature**——主模块 `LOCAL_STATIC_LIBRARIES` 里有 `libt3sdk`（带 exceptions），于是主模块被判定为 `exceptions` feature，`build-binary.mk:346` 在 `LOCAL_CPPFLAGS` **末尾**追加 `-fexceptions`。
- 另外 `module-flags-have-exceptions` 里有个上游笔误：`$(filter -fexceptions -fno-execeptions, ...)`（`-fno-execeptions` 多打一个 e），导致它永远认不出 `-fno-exceptions`。

→ **拆库方案否决**。已把 `Android.mk` 改回单模块，并在注释里写明这个坑（避免后人重踩）。

---

## 5. 当前状态与下一步

### 5.1 已交付（可核查）

- 基线产物 + 13 项明文残留清单（证明缺口真实存在）。
- amice 全档产物：**strings 27 条特征全绿（0 残留）**，体积 5.57 MB。**可用，但注解未生效**（见 5.2）。
- 完整的 pass 级证据链（amice 日志），以及 `-fexceptions` / 拆库两个坑的实测根因。
- 可复现的一键构建 + 审计工具链（VM 侧 + Windows 侧脚本）。

### 5.2 已完成：`t3sdk.cpp` 异常自由化 ✅（详见 §8 的最终定论）

唯一能让 VMP 真正生效的路径：把 `t3sdk.cpp` 的 try/catch/throw 改成"错误槽 + 显式检查"（所有异常原本就在文件内被 catch，语义可等价迁移），然后全工程 `-fno-exceptions`。

验收标准：
- [ ] 编译成功且产物存在
- [ ] 日志出现 `(VmVirtualize) pass done`
- [ ] `login` / `RSACrypto::encrypt` / `heartbeat` / `verify_and_run` / `integrity_check` / `ANativeWindowCreator::Create` 不再被 skip
- [ ] strings 仍 0 残留
- [ ] 真机：卡密登录 / 自动登录 / 60 s 心跳 / 到期拒绝 全流程正常（**需要用户出设备 + 卡密**）

已知会被跳过、需要换手段的函数（amice 原文原因已记录）：
- `encodeParams`：`function has non-call address uses`
- `md5Transform`：`VM x-register budget exceeded`（MD5 一轮 16 个 32 位活值，超 VM 的 x0..x31）
- `md5Update`：`undef/poison values must be frozen`（`memset` 前的未初始化缓冲区）

对这三个：降级为 Flatten(dominator)+BCF（`AMICE_FLATTEN_H`）即可，别硬上 VMP。

### 5.2.1 VMP 的硬上限：VM 只有 x0..x31 共 32 个寄存器

`t3sdk.cpp` 异常自由化后重编（产物 **6 373 688 B**，md5 `b936a78a0542fe81d87b1d2fce795e86`），`invoke exception edges` 类跳过**全部消失**，但 VMP 仍一次没跑——6 个 VMP 目标全被同一条原因挡下：

```
(VmVirtualize) skip function "T3Verify::login":            VM x-register budget exceeded: x0..x31 are available
(VmVirtualize) skip function "RSACrypto::encrypt":         VM x-register budget exceeded: x0..x31 are available
(VmVirtualize) skip function "T3Verify::heartbeat":        VM x-register budget exceeded: x0..x31 are available
(VmVirtualize) skip function "md5Transform":               VM x-register budget exceeded: x0..x31 are available
(VmVirtualize) skip function "md5Update":                  VM x-register budget exceeded: x0..x31 are available
(VmVirtualize) skip function "T3Verify::encodeParams":     function has non-call address uses
```

根因在 profile 的寄存器模型（`~/amice-lab/myprofiles/*/runtime.vm` 第 1-3 行）：
```
registers {
  bank x range x0..x31 type u64      # 固定 32 个整数/指针寄存器
  bank q range q0..q64 type v128     # 宽寄存器组，当前配置策略禁止宽值降低
```
`VMPDesign_zh_CN.md` 明确：**函数参数、返回槽、native-call ABI 槽、phi 结果以及跨基本块活跃的值都会被保守固定占用 x 寄存器**；合计超过 x0..x31 时 pass 必须安全跳过。`login` 有十几个跨块活跃的 `std::string`（每个 IR 上是 alloca 指针 + 参数 + ABI 槽），`md5Transform` 一轮有 16 个 `x[16]` + 4 个链变量，`RSACrypto::encrypt` 是大数运算，全部超预算。

**这是 amice 当前 VM 的硬限制，改配置改不掉**（两个 profile 都是 x0..x31；q 寄存器组官方标注"当前实现尚未提供 q0..q64 的宽值 lowering，profile 必须用 `q.lowering = disabled` 显式声明"）。

**正确的应对不是硬上 VMP，而是"把敏感逻辑切成小函数"**——见 §5.4。

### 5.2.2 异常自由化后的实际收益（本档产物 6 373 688 B）

VMP 未生效，但 **A 级注解全部真正落地了**（异常自由化前它们和 VMP 一起被跳过）：
`t3::verify_and_run`、`ANativeWindowCreator::Create`、`SurfaceComposerClient::CreateSurface`、`main.cpp::security_ok`、`anti_extra::integrity_check`、`anti_extra::frida_extra_check`、`T3Verify::initRSA`、`T3Verify::decodeResponse`、`getMachineCode`、`jsonGetString` —— 全部 Flatten(dominator) + BCF + IndirectBranch。

### 5.3 尚未做（按优先级）

1. **strip 与 C++ 异常的冲突（重要，独立于 L2）**：`strip_elf.py` 默认会把 `PT_GNU_EH_FRAME` 程序头清零并删 `.eh_frame_hdr` 节头，而 unwinder 靠它找 FDE —— 一旦程序里还有 `-fexceptions` 编译的代码（当前 `t3sdk.cpp` 就是），**任何一次 throw 都会变成 `std::terminate`**。构建脚本已加保护：`NOEXC=0`（保留异常）时自动给 strip 传 `--no-drop-sections`。异常自由化完成后这条约束自然消失。
2. **真机回归**：L1.6 篡改退出（`_exit(42)`）、L1.8 Dumpable、L1.9 反 Frida、T3 全流程。
3. **`L2_加密设计分析.md` §3.4 的二阶段增强**：`IndirectBranch` flags 已开 `dummy_block,encrypt_block_index,shuffle_table`；`VmFlatten distributed` 还没试（当前 `AMICE_VM_FLATTEN=false`）。
4. **T3 二阶段**：服务端密钥纠缠（`T3加密保护设计.md` §4.2），根治 patch-bypass。
5. 体积/帧率对比：v1 相对 baseline +85.7%，预期区间 +30%~80%（VMP 未生效都到 85% 了，全档生效后需要重新评估，必要时把全局 Flatten 降到只覆盖自研模块）。

---

## 6. 命令速查

```powershell
# 同步单个文件到 VM
scp "<windows path>" wthh-vm:~/amice-lab/incoming/

# VM 侧落位（示例：注解过的源文件）
ssh wthh-vm 'cp ~/amice-lab/incoming/t3sdk.cpp ~/amice-lab/proj-asimgui/jni/src/t3sdk/'

# 全档构建（后台，-j 4 防 OOM；16 核 7.7G 内存实测 -j8 也可以，但 amice 单文件吃内存）
ssh wthh-vm 'cd ~/amice-lab && export RUST_LOG="amice=debug,amice::aotu::string_encryption=info" && nohup ./build_asimgui.sh -j 4 > results/run.out 2>&1 &'

# 只看 pass 有没有跑
ssh wthh-vm 'cd ~/amice-lab; grep -a "pass done" results/linux-r30-amice-vmp-str-fla-bcf-nodemo.log | sed "s/.*\] //" | sort | uniq -c'

# 只看被 skip 的敏感函数及原因
ssh wthh-vm 'cd ~/amice-lab; grep -aiE "skip function" results/linux-r30-amice-vmp-str-fla-bcf-nodemo.log | grep -aE "login|encrypt|heartbeat|verify_and_run|integrity_check|ANativeWindow"'

# 字符串审计
ssh wthh-vm 'cd ~/amice-lab && ./audit_strings.sh dist/<产物>.bin <标签>'

# Windows 侧打/撤注解
python artifacts\tmp\annotate_amice.py "AndroidSurfaceImgui-Enhanced-main" --check
python artifacts\tmp\annotate_amice.py "AndroidSurfaceImgui-Enhanced-main"
python artifacts\tmp\annotate_amice.py "AndroidSurfaceImgui-Enhanced-main" --revert
```

---

## 7. 本次踩坑记录（新增，接手者必读）

1. **`-fexceptions` 是 amice 的隐形杀手**：不是"VMP 不支持异常"，而是**只要函数里有非平凡局部对象 + 任何调用**就会生成 `invoke`，Flatten 和 VMP 双双拒绝。判断方法：`RUST_LOG=amice=debug` 里搜 `skip function`。
2. **`AMICE_PASS_ORDER` 是允许列表**：`VmVirtualize` 不在列表里，函数注解 `+vm_virtualize` 也完全不跑（且**不报错**）。设计文档 §3.2 的列表漏了它。
3. **拆静态库隔离异常不可行**：ndk-build 会把依赖模块的 C++ feature 传播过来并在编译命令末尾追加 `-fexceptions`，反而让 `-fno-exceptions` 失效。NDK 源码 `definitions.mk` 的 `module-flags-have-exceptions` 还有 `-fno-execeptions` 笔误。
4. **`strip_elf.py` 与 C++ 异常互斥**：默认会清零 `PT_GNU_EH_FRAME`，保留异常的产物一旦 throw 就 `std::terminate`。保留异常时必须 `--no-drop-sections`。
5. **构建前 `rm -rf obj libs`**：amice 配置改了必须重编源码，复用旧 `.o` 不生效（HANDOFF 坑 #7 同源）。构建脚本已内置清理——**注意它会把上一次的 `*.pre-strip` 一起删掉**，要留证就先拷到 `dist/`。
6. **本机（Windows）PowerShell 里 grep 源码要用对根路径**：`$root` 若已含 `\jni`，再拼 `\jni\src` 会静默匹配不到文件（本次因此漏判 t3sdk.cpp 的 try/catch，多花一轮构建）。扫描结果为空时先确认路径存在。

---

## 8. VMP 最终定论（2026-10-09 实测，结论：**本工程用不了 amice VMP**）

### 8.1 证据链（每一步都有日志原文）

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 全局 `-fexceptions` + 16 处注解（含 6 处 VMP） | 全部敏感函数被 skip：`invoke exception edges are not supported` / `has exception handling instructions` |
| 2 | `t3sdk.cpp` 异常自由化（错误槽替代 try/catch/throw）→ 全工程 `-fno-exceptions` | 异常类 skip **全部消失** ✅，但 6 个 VMP 目标**换理由继续被跳过**：`VM x-register budget exceeded: x0..x31 are available` |
| 3 | 把 token 校验抽成独立小函数（6 个 `std::string` 引用参数） | 仍 skip：`VM x-register budget exceeded` |
| 4 | 再改成**全 `const char*` + 定长栈缓冲 + 手写 hex**（彻底避开 `std::string` 临时对象） | 仍 skip，且理由更精确：`VM x-register budget exceeded: **no register outside native_call clobbers is available**` |
| 5 | 用 bundle 自带 clang 做隔离 smoke test（`amice/bin/aarch64-linux-android-clang`，几秒一轮） | 见下表 |

隔离 smoke test 结果（同一 clang、同一 profile、`AMICE_PASS_ORDER=VmVirtualize`）：

| 形状 | 结果 |
|---|---|
| `int f(int x){ return (x*7)^0x55; }` | ✅ `(VmVirtualize) pass done` |
| `bool f(const char* a, const char* b){ return strcmp(a,b)==0; }` | ✅ pass done |
| `bool f(const char* a, const char* b, char* out, int cap){ snprintf(out,cap,"%s-%s",a,b); ... }` | ✅ pass done |
| `bool f(const std::string& a, const std::string& b, const std::string& c){ std::string s=a+b+c; ... }` | ❌ skip：`function has non-call address uses` |
| 4 个 `char buf[N]` + `snprintf` + 两个循环 + 6 参数（token 校验的真实形状） | ❌ skip：`no register outside native_call clobbers is available` |

### 8.2 根因

amice 的 VM 把"跨 native call 活跃"的值固定在**调用不破坏的寄存器**里（AArch64 即 x19..x28，约 10 个）。一旦函数里有若干缓冲区/局部量跨过 `snprintf`/`strftime`/`md5Update` 这类调用还活着，就必然超预算。profile 的寄存器模型写死 `bank x range x0..x31`（`~/amice-lab/myprofiles/*/runtime.vm`），且 `libamice.so` 的 `VmVirtualizeConfig` 只有 `profile_path / runtime_scope / emit_markers / dump_bytecode / dump_lowering`——**没有任何寄存器预算开关**，环境变量与配置都放不开。`q0..q64` 宽寄存器组官方标注"当前实现尚未提供宽值 lowering，profile 必须 `q.lowering = disabled`"。

**结论：amice VMP 只能虚拟化"小标量叶子函数"**（几个整数参数 + 少量局部变量 + 无调用或极少调用）。任何真实的 C++ 业务函数（`std::string`、缓冲、多次库调用）都进不去。设计文档 §3.1 想要的"VMP 掉 login/encrypt/heartbeat/md5*"在 amice 0.1.5-beta.5 上**不可达**，不是配置问题。

### 8.3 因此 L2 的实际交付边界（已全部验证生效）

| 层 | 手段 | 验证 |
|---|---|---|
| 字符串 | amice `StringEncryption`（xor / lazy / only_dot_string）全局 | ✅ 27 条特征 0 明文残留（含 GhostTrace 的 `frida-agent`/`gum-js`/`xposed`、imgui_demo 指纹、T3 的 `t3yanzheng`/`t3data`/`kami`/`statecode`） |
| 控制流 | `Flatten(basic)` + `BogusControlFlow` 全局 | ✅ 29/29 编译单元 pass done |
| 敏感函数 | **17 处 `AMICE_FLATTEN_H`** = Flatten(dominator) + BCF + IndirectBranch（flags: `dummy_block,encrypt_block_index,shuffle_table`） | ✅ 0 skip（异常屏障清除后全部生效） |
| VMP | —— | ❌ 不可用（§8.2） |

`AMICE_VMP` 宏保留在 `jni/include/My_Utils/amice_annotate.h` 里，供将来 amice 版本升级后复用；当前代码里**一处都没用**（用了也是静默跳过，只会让日志产生噪声）。

### 8.3.1 最终交付产物（2026-10-09 13:11）

| 项 | 值 |
|---|---|
| 产物 | `dist/AndroidSurfaceImguiEnhanced.linux-r30-amice-vmp-str-fla-bcf-nodemo.bin` |
| 大小 | **6 254 792 B**（基线 2 997 128 B，**+108.7%**） |
| md5 | `6daf70f1a08d5d9a2ab509b5af03f997`（仅本次构建有效，见 §8.5 坑 7） |
| 日志 | `results/FINAL-pass.log`（本机副本：`artifacts/L2/FINAL-pass.log`） |
| Windows 侧副本 | `artifacts/L2/ASIMGUI-amice-FINAL-6.25MB.bin` |
| Pass | StringEncryption 29 / Flatten 29 / BCF 28 / IndirectBranch 5 / **VmVirtualize 0** |
| 敏感函数 skip | **0 条**（`./verify_l2.sh` 第 [3] 项 `[OK] 全部生效`） |
| strings | **0 残留 / 27 条特征全 OK** |
| ELF | `elf64-littleaarch64`、`no symbols`、节表已清零（`Start of section headers = 0`） |

体积 +108.7% 略超设计文档预期的 +40%~100%。**如果体积/帧率不可接受**，构建脚本已提供旋钮：
`./build_asimgui.sh --no-flat --no-bcf --tag lite` —— 全局关掉 Flatten/BCF，只让 17 处函数注解生效
（允许列表里仍然保留这些 Pass，所以注解照常触发），体积会显著回落，代价是 ImGui 等非敏感代码不再被平坦化。

### 8.3.2 真机回归（**待用户执行**，这是唯一未闭环的验收项）

```powershell
# 推送（伪装名）
scp artifacts\L2\ASIMGUI-amice-FINAL-6.25MB.bin wthh-vm:~/   # 或直接从 VM 拷到手机
adb push ASIMGUI-amice-FINAL-6.25MB.bin /data/local/tmp/imguiobf.sh
adb shell "su -c 'chmod 755 /data/local/tmp/imguiobf.sh'"
# 已有 /data/local/tmp/.t3card 时可后台自动登录
adb shell "su -c '/data/local/tmp/imguiobf.sh > /data/local/tmp/run.log 2>&1 &'"
adb shell "su -c 'cat /data/local/tmp/run.log'"
```
检查点：① 版本检查/公告/卡密登录成功 ② ImGui 面板渲染正常（无花屏、帧率无明显下降）
③ `TracerPid=0` ④ 60 s 心跳周期正常、**持续 >10 分钟不崩**（心跳路径回归）⑤ 篡改 .text 一字节 → 退出码 42。


### 8.4 后续可选路线（按性价比）

1. **接受现状**：T3 门禁已由 Flatten(dominator)+BCF 保护 + appkey 编译期加密 + L1.5 即用即毁 + L1.9 反 Frida。攻击者要伪造 token 必须先运行时拿到 appkey，成本已经不低。
2. **换更强保护**：等 amice 上游支持更大寄存器预算/宽值 lowering；或改用商业壳（APK 级，需重构部署方式）。
3. **自研 VM**：把 token 校验写成字节码解释器（自有指令集 + 加密分派表），不受 amice 限制——工作量大但可控。
4. **服务端密钥纠缠**（`T3加密保护设计.md` §4.2）：不依赖混淆，从协议层根治 patch-bypass，**优先级应高于继续折腾 VMP**。

### 8.5 两个操作层面的坑（本次新增）

7. **amice 产物 MD5 不可复现**：同一源码同一档位两次完整构建（每次 `rm -rf obj libs`）得到 6373688 B / 6229440 B 两个不同 md5——字符串加密密钥、BCF 区域、note 随机化都含随机性。**不要用 MD5 判断"构建是否一致/是否改动生效"**，要看 `RUST_LOG` 的 pass 日志 + `llvm-strings` 审计。
8. **并发会话会互相覆盖**：本次同一 workspace 有并行会话在同一 VM 上构建，`dist/*.bin`、`results/*.log`、`incoming/*` 会被覆盖。约定：**每个会话用 `--tag` 区分产物与日志名**，否则证据会被别人冲掉。
