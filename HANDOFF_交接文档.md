# 接手文档：加固工程现状与下一步（2026-10-10）

> 写给接手 Agent。以真实状态为准，命令可直接复制执行。**先读本文，再按需跳转 `加固方案总览.md` 及各专题文档。**

---

## 0. 一句话现状

AndroidSurfaceImgui-Enhanced（ImGui 叠加层，arm64 裸 ELF，root 运行）已完成 **L0 编译加固 + L1 字符串加密 + L1.5~L1.27 动态防逆向 + L2 amice 混淆（字符串/控制流/VMP 单点）+ L3 反调试 + T3 卡密门禁 + 服务端密钥纠缠 + 远程总闸 + TLS 传输**；生产包真机验证通过。**唯一未闭环的技术攻坚是 amice VmVirtualize 的寄存器墙**（已定位到插件侧 PHI pin 策略，详见 §5）。

**注意：本工程有并行会话同时在工作**（同一 workspace/同一 VM）。最近提交 `f313ebb`（bugscan 修复）、`ab74492`（IDA server 检测）等来自对方；工作区可能随时出现对方的未提交改动。**动 `jni/` 下文件前先 `git status` 确认，避免互相覆盖**（已发生过一次：本会话注入的纯核被对方提交覆盖）。

---

## 1. 产物清单（谁是最新的）

| 产物 | 位置 | 说明 |
|---|---|---|
| **PROD3-TLS-3.38MB.bin** | `artifacts/L2/` | **当前最新生产包**（含 TLS 传输层，由并行会话产出） |
| PROD2-VMP.bin / PROD2-VMP-v2.bin | `artifacts/L2/` | 上一代生产包（StrEnc+Flatten/BCF/IB+VMP(fnv1a64)+纠缠v2+总闸+BTI/PAC） |
| ASIMGUI-PROD2-ENTANGLE.bin | `artifacts/L2/` | VM 构建原始产物（amice 版） |
| 历史留档 | `artifacts/L2/` | NOEXC-FIXED(6.38MB, 旧生产)/MAX3(7.01MB, 功能性破坏留档)/SAFE-exc/baseline |
| 设备 | `/data/local/tmp/imguiobf.sh` | 真机运行副本（adb 推送改名） |

**发布前必做**：当前绑定的是**测试 core（`ASIMGUI-CORE-2026-TEST`）与测试卡**（卡 `QIUQIUD4E9F47B4EF4CD3B3E8094313A` 到期 2026-10-10 20:28）。换正式密钥流程：
```bash
# 1) T3 控制台改该卡的「核心数据」为新密钥  2) 重新生成配置并重编
python jni/tools/gen_entangle.py --core <新core> --spare 0xD8580BC8
# 3) VM 上重跑构建（见 §3）
```

---

## 2. 环境（全部已验证可用）

| 项 | 值 |
|---|---|
| 项目根 | `E:\download\AndroidSurfaceImgui-Enhanced加密\AndroidSurfaceImgui-Enhanced-main` |
| 仓库 | git `hardening` 分支（远端 `sangjie-stack/AndroidSurfaceImgui-Enhanced`） |
| Ubuntu VM | `wthh@192.168.117.132`（SSH 免密已配）；`~/amice-lab` 全套构建设施 |
| 宿主机代理 | Clash Verge `192.168.117.1:7897`（VM 出网走它；apt/github 下载用） |
| Windows NDK r30 | `E:\download\android-ndk-r30-windows\android-ndk-r30\ndk-build.cmd` |
| amice bundle | VM `~/amice-lab/amice-android-ndk-r30-linux-x86_64`（插件 `amice/lib/libamice.so`，**原版 md5 `5557e4fe…`，生产用这个**） |
| amice 源码构建 | VM `~/amice-lab/amice-src`（含本会话的 spill 补丁，**未验证，勿用于生产**） |
| 设备 | USB `a78ccd03`（adb 直连；无线 IP 会变） |
| GitHub token | VM `~/.gh_token`（细粒度，仅自家仓库）与 `~/.gh_token_classic`（public_repo，**建 issue 用这个**） |
| 代理下的命令模板 | `export https_proxy=http://192.168.117.1:7897 http_proxy=$https_proxy` |

### 从源码构建 amice 插件（本会话打通，可复用）
```bash
# 依赖: rustup(rsproxy 镜像) + LLVM 21(apt.llvm.org, 走代理) + clang-18 + NDK r27c sysroot
# 关键: 宿主 clang 必须与插件 ABI 同源 —— 用 clang-18 + NDK r27c sysroot
#       (NDK r30 的 libc++ 需要 LLVM19+ 内建函数 clang-18 编不过;
#        apt LLVM 21.1.8 与 NDK 的 AOSP LLVM 21.0.0 加载即崩)
cd ~/amice-lab/amice-src
export PATH=$HOME/.cargo/bin:$PATH LLVM_SYS_181_PREFIX=/usr/lib/llvm-18
export https_proxy=http://192.168.117.1:7897 http_proxy=$https_proxy
cargo build --release -p amice --no-default-features --features llvm18-1   # ~35s
# 产物: target/release/libamice.so  → 用 clang-18 编译目标文件时 -fpass-plugin=它
```

### 生产构建（VM，19 秒）
```bash
ssh wthh@192.168.117.132 'cd ~/amice-lab && ./build_prod2.sh'
# 配置: 全局仅 StringEncryption + Flatten/BCF/IB 注解驱动 + VMP(fnv1a64) + noexc + drop_demo + strip
# 产物: dist/ASIMGUI-PROD2-ENTANGLE.bin
```

---

## 3. 已完成的加固（按层，全部真机验证）

| 层 | 内容 |
|---|---|
| L0 | `-O3 -ffunction-sections -fdata-sections -fno-ident`、`--gc-sections -z relro -z now`、`-fstack-protector-strong`、**`-mbranch-protection=standard`（BTI/PAC，2533 条指令）**、`-fvisibility=hidden`、strip_elf.py（删节表/清零节头） |
| L1 | AY_OBFUSCATE 编译期字符串加密 + `scoped_plaintext` 即用即毁 |
| L1.5~L1.27 | 完整性自检(L1.6)、dumpable(L1.8)、反 Frida 多向量(L1.9)、行为检测/延迟退出/独立检测线程(L1.13~1.17)、seccomp、memwatch、guard 进程、slowdown 检测、IDA server 检测 等（并行会话持续加，见 `动态防逆向增强方案.md`） |
| L2 | amice：**StringEncryption×30 模块**（域名/APPKEY/公钥/特征串/demo 指纹零明文）+ **Flatten(dominator)+BCF+IndirectBranch 注解驱动**（42 处，全在自家代码）+ **VmVirtualize 仅 fnv1a64**（密钥派生根） |
| L3 | GhostTrace（ptrace/Frida/Xposed）+ PTRACE_SEIZE 双进程守护 |
| 门禁 | T3 卡密（真机验证）+ **服务端密钥纠缠 v2**（core→fnv→LCG+密钥化 CRC，正负双向验证）+ **远程总闸**（心跳 core 吊销） |
| 传输 | TLS 传输层（PROD3，并行会话） |
| 不混淆项 | ImGui/freetype/stb（开源，Operator 明确指令零混淆） |

**强度实证**：IDA 判卷（`PROD2-VMP_IDA判卷.md`）：login 巨型变体 17KB/484 块让 Hex-Rays 产出失真伪代码；零符号零明文。crackme 攻防六项（`crackme动态调试攻防实测.md`）：Frida hook/patch/内存改卡密全部实测，哨兵防线 4/4 拦截伪造。

---

## 4. amice VMP 寄存器墙（唯一未闭环攻坚）

### 4.1 事实链（全部实测，勿重复验证）
1. **现象**：T3 五个核心函数（login/encodeParams/RSACrypto::encrypt/heartbeat/md5Transform）全部 `skip: VM x-register budget exceeded`；
2. **诊断数据**：爆点时 `values`+`temps` 仅 20~27，但 `allocated=32 free=0`；
3. **根因分层**（逐层排除）：
   - ABI 预留（`translator.rs:2618` 无条件预留）→ 条件化后无变化；
   - 跨块值 pin 过保守 → 实现 `global_last_uses` 全局最后使用点释放（补丁 A，安全且独立可合）→ 无变化；
   - **实现 spill**（帧 alloca + 值溢出/回载 + call 保存走帧 + 实参暂存 + 全 31 分配点覆盖）→ **生效**（login 溢出 49 值、heartbeat 活跃值降到 0），但仍有残余峰值；
   - 残余峰值定位：**`Call` 降低瞬时 16 临时**（非参数物化，已排除）与 **PHI 预绑定**（纯核实验暴露：`pinned=97` > 32）。
4. **结论**：墙的本质是 (a) 无 spill 时预算 32 物理寄存器硬顶；(b) **amice 对 PHI 相关值 pin 过保守**（97 个），以及 Call 路径内的瞬时峰值。

### 4.2 本会话的 spill 补丁（VM `~/amice-lab/amice-src`，本地留档 `artifacts/tmp/translator_spill*.rs`）
改动全在 `crates/amice/src/aotu/vm_virtualize/translator.rs`：
- `ReusePlan.global_last_uses` + 跨块非 PHI 值全局最后使用点释放；
- 溢出帧（`alloca` 64×8B，帧指针/scratch 排除 clobber 集，`scalar_values>12` 时预分配）；
- `alloc_vreg_or_spill` / `alloc_vreg_excluding_or_spill` 包装全部 31 个直连分配点；
- `save/restore_native_touched_registers` 走溢出帧；
- `NativeArgLoc::Staged` 实参经帧暂存；
- 诊断设施：`diag_register_state()` + bail 画像日志（`[diag:regwall]`）。
**状态：未验证正确性（未跑 amice 测试套件），未用于生产。**

### 4.3 下一步（按性价比）
1. **插件侧放松 PHI pin**（`prepare_register_reuse` 的 phi 预绑定 / `build_reuse_plan` 的 PHI pin）：只 pin 真正跨回边存活的值（需 CFG 存活期分析）→ 纯核 pinned 97→~15 即可过 32 → **这是解锁 T3 核心函数 VMP 的关键一步**；
2. 改完**先跑 amice 自带测试套件**（`crates/amice/tests/`，含 vm_virtualize fixtures）再谈可用；
3. 通过后 → 用 §4.4 的纯核 → 真机验证 token → 才进门禁。

### 4.4 源码适配产物：T3 token 纯核（`artifacts/tmp/t3_token_core.cpp`）
- 目的：把 login 的 token 校验抽成**无调用 + 寄存器节俭 MD5（按需取字，不缓存 16 块字）+ 64 轮显式展开**的纯核，供 VMP；
- **已实证的等价性**：原版 `md5String` 是标准 MD5（abc/空串/fox/300 字节多块四向量逐字节一致）→ 纯核的节俭 MD5 对同向量 + **900 字符**输入与 python hashlib 一致（`e331a28150f2eebfb02ba4672f7aaa4b`）；
- **⚠️ 已修复的 bug（Operator 指出）**：早期版本缓冲 512/上限 447，而 `tokenSrc` 含 RSA 加密参数串（3×256 hex ≈ 800+）总长 ~900 → **截断导致正确卡密校验失败**。现为 **4096 缓冲**；
- **VMP 状态**：i6 位宽收窄 ✅ 已修、寄存器压力 ✅ 已降、PHI 43→展开后 pinned 97 ⚠️ 仍超 → 卡在 §4.3 第 1 步；
- **处置**：纯核**已从门禁源码撤出**（`git checkout` 还原）。**在真机验证 token 通过前，禁止进入 t3sdk.cpp**——付费门禁必须在已验证路径上。

---

## 5. 上游跟进

- **issue #95**（已提 + 跟评）：https://github.com/fuqiuluo/amice/issues/95 — 含完整诊断矩阵、spill 补丁说明、Call 峰值定位、四条建议；
- 提 issue 用 `~/.gh_token_classic`（细粒度 token 无 public_repo 权限，会 403）；
- 若上游无回应且 §4.3 第 1 步做完，可整理 PR（补丁 A `global_last_uses` + spill + 诊断 instrumentation，**必须先过测试套件**）。

---

## 6. 关键坑（血的教训，勿踩）

1. **`VAR=x cmd1 && cmd2`**：环境变量只作用于 cmd1 → 构建脚本必须 `export`；
2. **`pkill -f ndk-build` 会自杀**（SSH 命令行含该串）→ 用 `pkill -f "[n]dk-buil"`；
3. **heredoc 穿 SSH 多层引义必炸** → 脚本一律本地写 + `scp`（本会话多次踩）；
4. **Python 写文件时 `\\n` 会被吞成真换行** → 用 Write 工具或 `chr(92)+"n"`；
5. **VM 上 -j12 全 Pass 构建会 OOM**（7.7GB RAM，ImGui 大文件）→ -j4~8；
6. **amice 产物 MD5 不可复现**（随机种子）→ 用 pass done 日志 + strings 审计判断，别看 md5；
7. **`grep -c` 无匹配时退出码 1 会断 `&&` 链** → 用 `;` 分隔；
8. **NDK r30 的 libc++ 需要 LLVM19+**（clang-18 编不过）→ 用 NDK r27c sysroot 交叉编译；
9. **apt LLVM 21.1.8 与 NDK clang 的 AOSP LLVM 21.0.0 ABI 不通**（插件加载即崩 exit 139/134）→ 宿主 clang 与插件必须同源；
10. **t3sdk 重构有前科**：异常自由化改造曾破坏 token 校验（全局错误槽污染）→ 改门禁代码后**必须真机全流程回归**；
11. **并发会话会互相覆盖文件**（同一 workspace）→ 动手前 `git status`，改完尽快提交。

---

## 7. 文档索引（按主题）

| 主题 | 文档 |
|---|---|
| **决策总表/入口** | `加固方案总览.md` |
| **寄存器墙攻坚（本会话主线）** | `amice源码自修_寄存器墙攻坚报告.md` |
| VMP/VmFlatten 边界源码考证 | `VMP与VmFlatten边界_源码考证.md` |
| 生产包 IDA 判卷 | `PROD2-VMP_IDA判卷.md` |
| crackme 攻防实测 | `crackme动态调试攻防实测.md` |
| 探针强度六档 | `maxprobe强度探针报告.md` |
| T3 门禁设计/对接 | `T3加密保护设计.md` / `T3卡密验证对接文档.md` |
| L2 实施记录（并行会话权威进度） | `L2_Amice实施记录.md` |
| 动态防逆向方案（L1.x 全景） | `动态防逆向增强方案.md` |
| TLS 传输层 | `L3-TLS传输层-实施与验证.md` |
| 历史：异常自由化/MAX 终审/强度验证 | `L2-异常自由化-验收报告.md` / `L2_MAX版终审记录.md` / `L2强度验证_真机+IDA.md` |

## 8. 本会话产出物速查

| 产物 | 路径 |
|---|---|
| T3 token 纯核（已验 MD5，未进门禁） | `artifacts/tmp/t3_token_core.cpp` |
| spill 补丁各版本快照 | `artifacts/tmp/translator_spill{1..14}.rs` |
| NativeArgLoc 补丁脚本 | `artifacts/tmp/apply_nativearg.py` |
| MD5 验证程序（原版/纯核） | `artifacts/tmp/md5orig.cpp` / `corecheck.cpp` |
| 生产构建脚本 | `artifacts/tmp/build_prod2.sh`（VM 同名） |
| 上游 issue/跟评正文 | `artifacts/tmp/amice_issue.md` / `amice_comment.md` |
| crackme 挑战包 | `artifacts/tmp/crackme/challenge/` |
