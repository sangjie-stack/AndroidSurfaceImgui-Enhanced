# 接手文档：Amice (L2 指令级混淆) 接入

> 本文件写给下一步继续做 L2 加固的接手者（人或 Agent）。内容以 2026-10-07 会话结束时的真实状态为准。
> 本文件是会话产物，**不建议提交到 git 仓库**（需要时可加入 .gitignore）。

---

## 1. 项目一句话

对 `AndroidSurfaceImgui-Enhanced`（ndk-build 工程，C++17 + Dear ImGui + Vulkan/OpenGL，产出 **arm64 Android 裸可执行文件**，root/KernelSU 运行）做开源加固，目前已交付 L0 编译加固 + L1 字符串加密 + L3 反调试，**主线任务是补上 L2 指令级混淆（方案已定为 Amice，尚未实施）**。

## 2. 环境与关键路径（全部已核实）

| 项 | 路径 / 值 |
|---|---|
| 项目根 | `E:\download\AndroidSurfaceImgui-Enhanced加密\AndroidSurfaceImgui-Enhanced-main`（含 jni\、libs\arm64-v8a\、.git） |
| Windows NDK r30 | `E:\download\android-ndk-r30-windows\android-ndk-r30`（ndk-build.cmd 在根；llvm 工具在 `toolchains\llvm\prebuilt\windows-x86_64\bin`，llvm-strings/llvm-readelf 可用） |
| 已加固产物（伪装名） | 项目根下 `imguiobf.sh`（2586.0 KB），与 `libs\arm64-v8a\AndroidSurfaceImguiEnhanced` 同内容 |
| 设备 | 无线 adb（IP 每次重连会变，最近一次 `192.168.137.170:37987`）；adb = `C:\WINDOWS\system32\adb.exe`；KernelSU root（`su -c` 可用）；设备路径 `/data/local/tmp/imguiobf.sh`（755）、日志 `/data/local/tmp/run.log` |
| GitHub 远端 | `https://github.com/sangjie-stack/AndroidSurfaceImgui-Enhanced.git`；本地分支 `hardening`（已推送，tracking origin/hardening，最新提交 `a9aa3e8`）；远端 main = 原版 v2.1.2 |
| Amice 源码 | `E:\download\amice-master\amice-master`（docs/ 全中文文档；VMPDesign_zh_CN.md 233KB 为 VMP 设计文档） |
| 调研中间文件 | `E:\obfus_dl\`（verify_result.txt / verify_final.txt / push_verify.txt / amice_look*.txt / amice_structure.txt 等，可按需回读） |
| 主项目目录（会话产物落点） | `C:\Users\wantaihong\Doubao\chats\2026-10-06\new-chat-5` |

**注意：本机（Windows）无 Bash，一切命令行用 PowerShell；C 盘仅约 5.2GB 空闲，大文件下载到 E 盘。**

## 3. 已完成并验证的加固（L0 / L1 / L3）

### L0 编译加固 — 已交付 ✅
`jni\Android.mk` 增加：`-O3 -ffunction-sections -fdata-sections -fno-ident`、`-Wl,--gc-sections -Wl,-z,relro,-z,now`。

### L1 字符串加密 — 已交付 ✅
- 采用 adamyaxley/Obfuscate（Unlicense），vendored 到 `jni\include\My_Utils\obfuscate.h`。
- 已加密：main.cpp 的 `AImGui` 窗口名；ANativeWindowCreator.h 的 **82 个 Android framework mangled 符号** + libgui/libutils 路径 + `ro.build.version.release` + `dumpsys display` 命令 + 日志串；my_imgui.cpp 字体文件名；draw_Gui.cpp 第二个 Create 调用。
- 兼容性修复：`ResolveMethod` 宏 varargs 处加显式 `(const char*)` 转换（过 clang 变异检查）；`gt_config_t gt_cfg = {}` 修 C++ 聚合初始化。

### L3 反调试 / 反 Frida / 反 Xposed — 已交付 ✅
- 采用 GhostTrace（GitLab marco.romano/ghosttrace，MIT），6 个 .c vendored 到 `jni\src\ghosttrace\`（include 统一改 `#include "ghosttrace.h"`，补 `#if PLATFORM_MACOS` 包住 `PT_DENY_ATTACH` 平台缺陷）；头文件在 `jni\include\ghosttrace\`。
- main() 启动即检测 + 每 90 帧周期复检；**只调用 `gt_detect_ptrace` + `gt_detect_android_frida` + `gt_detect_android_xposed`**（`gt_detect_debugger_android` 含 root 检测会误杀 root 环境，**禁用**）。
- 品牌串 21 处 GhostTrace→CoreGuard 中性化。

### 编译与真机验证结果（已通过）✅
- NDK r30 ndk-build 成功；产物 2584 KB，64 位 arm64 ELF，无 .symtab，GhostTrace/JNI 导出符号 0 个。
- llvm-strings 验证：AImGui / dumpsys / `_ZN7android` / `_ZNK7android` / 字体名 / lib 路径 / GhostTrace 明文全部清除（CoreGuard 与 AndroidSurfaceImguiEnhanced 两处品牌串残留属可接受）。
- 真机：复制为 `imguiobf.sh` 推送 `/data/local/tmp/`，root 启动，进程存活、TracerPid=0、12 线程、VMA 143MB；logcat 窗口名 AImGui + SceneRecognition 正常；截图确认 ImGui 面板完整渲染。用户回复"显示没问题"。

### GitHub 推送 ✅
- 初始化仓库，提交 `4119f64 Add hardening: string obfuscation + anti-debug/anti-Frida (NDK r30 build)`，推送到 **hardening 分支**（未动远端 main）。`.gitignore` 已排除 obj/。
- git 回滚教学已向用户讲解（git log / git reset / git revert 用法；commit 多可随意回滚本地，推送后需 force push 或 revert）。

### L1.5 字符串"即用即毁"（use-and-destroy）— 已交付 ✅（2026-10-09）
- **目标**：L1 只解决了"静态 strings 看不到明文"，但运行时 `decrypt()` 后明文一直躺在 thread_local 存储里（直到进程结束）；攻击者 dump 内存即可拿到。L1.5 把明文窗口从"整个运行期"压缩到**微秒级**（解密→使用→立即重新加密）。
- **方案（不换库）**：继续用 Obfuscate（Unlicense），在 `jni\include\My_Utils\obfuscate.h` 新增 30 行 RAII 辅助类 `ay::scoped_plaintext`（构造 `decrypt()`、析构 `encrypt()`、禁拷贝、隐式转 `const char*`）。核心加解密逻辑仍 100% 在开源库内，RAII 只是使用模式封装（参考 obfusheader.h 的 OBF/MAKEOBF 设计）。
- **改动点（8 处）**：
  1. `obfuscate.h`：新增 `scoped_plaintext`；
  2. `ResolveMethod` 宏内部统一包 RAII → **82 个符号调用点零改动**；
  3. 单点 6 处：4 个 dlopen 库路径、`ro.build.version.release`、`dumpsys display`、`[-] Failed to create surface control` 日志串、`my_imgui.cpp` 两处字体文件名。
- **保持不变**（长生命周期/低敏感，改了反而有风险）：窗口名 `AImGui`、`SURFACE_LOG_TAG`。
- **验证（全部通过）**：ndk-build 编译成功（2586 KB）；llvm-strings 确认 dumpsys / ro.build / AImGui / `_ZN7android` / 字体名明文消失（`dlsym` 为动态链接必需符号属正常残留）；真机推送运行：进程存活、TracerPid=0、ImGui 面板渲染正常（78.5 FPS）、无崩溃无花屏。
- **提交**：`a9aa3e8 feat: use-and-destroy string decryption via RAII scoped_plaintext`（已推送 hardening）。

### L1.6/L1.8/L1.9 动态防逆向增强 — 已完成并真机验证 ✅（2026-10-09）
- **方案文档**：项目根 `动态防逆向增强方案.md`（实时更新的权威状态，接手者先读它）。
- 已实现：ELF 完整性自检（内存 vs /proc/self/exe，检出 `_exit(42)`）、`PR_SET_DUMPABLE=0`、反 Frida 多向量（maps/线程名，特征串 Obfuscate 加密）。
- 代码位置：`jni/src/security_extra/anti_extra.cpp` + `jni/include/My_Utils/anti_extra.h`；main.cpp `security_ok()` 挂接。
- **验证（全部通过）**：clean 全量重编成功（3074 KB，构建环境为 `E:\ndk\android-ndk-r25c`，**非 r30**）；真机：T3 卡密自动登录成功（测试卡密"随便输入"），ImGui 渲染正常（59 FPS）、TracerPid=0、`CoreDumping:0`（dumpable 生效，root/非 root 直读 mem 均 I/O error）、完整性自检在 T3 门禁前通过（无误杀）、anti_extra 特征串 strings 无明文。
- **⚠ T3 崩溃已修复（2026-10-09，T3 agent 接手必读）**：`jni/src/t3_gate.cpp` 心跳线程 lambda 原用 `[&]` 引用捕获 `verify_and_run()` 栈上局部对象（`T3Verify verify`/`card`/`loginResult`），函数返回后悬垂 → 60 秒后首次心跳访问已销毁 string → 垃圾长度 → `std::bad_alloc` 崩溃（真机两次复现，backtrace 栈底 `__pthread_start` + ELF 0x1d6374 string 分配佐证）。**修复**：`verify` 改 `make_shared<T3Verify>()`，心跳 lambda 值捕获 `[verify, hbCard, hbStatecode]`（card/statecode 值拷贝）。验证：跨两次心跳期（165s）稳定存活。**构建坑**：增量构建会因 .o 混用报 `sstream vtable undefined`（missing key function），必须 `ndk-build clean` 后全量重编。

## 4. 待完成：L2 Amice 接入（本次接手的主线）

### 4.1 方案结论（已完成多轮比对，勿再换方案）
**Amice（fuqiuluo/amice，Apache-2.0，v0.1.5-beta.5）是唯一同时满足「开源 + 现成 + 适配 Android 裸可执行文件 + 官方 NDK r30 bundle」的方案。**
已否决：O-MVLL（Windows 交叉编译不支持、官方只测 r26d）、Kagura（需 Windows 自编插件）、Pluto（OLLVM14 工具链不匹配 r30）、UPX（Android 无法自解压）、XopProtector（APK 壳不适配裸 ELF）、ollvm-mingw（非 Android）。再往上只剩商业壳（爱加密/梆梆，非开源且 APK 级）。

### 4.2 前置确认（唯一待用户回答的问题）
**Ubuntu 虚拟机如何访问项目文件：SSH 可达（IP/端口/账号）？共享文件夹？还是拷贝 zip？** —— 此问题未得到用户答复，接手第一步先确认。

### 4.3 详细实施步骤（Ubuntu 侧）

```
① 下载 Amice r30 Linux bundle（GitHub Releases: fuqiuluo/amice）
   https://github.com/fuqiuluo/amice/releases
   文件名：amice-android-ndk-r30-linux-x86_64.tar.gz（含 NDK r30 + 插件 + 匹配 LLVM 动态库 + wrapper，约几百 MB）
   校验：同名 .sha256
   （Windows 无预编译 bundle，v0.1.5-beta.5 无 Windows DLL —— 必须走 Ubuntu）

② 解压并接入编译环境
   tar xzf amice-android-ndk-r30-linux-x86_64.tar.gz
   cd <解压目录>
   source ./amice/env.sh        # 设置 LLVM 动态库路径（LD_LIBRARY_PATH）

③ 把项目源码放入 Ubuntu（方式取决于 4.2 的回答），确认 Android.mk 位于项目根/jni/

④ 编写混淆配置 amice.toml（放项目根，推荐初始档）：
   [string_encryption]
   enable = true
   # 默认 AMICE_STRING_ONLY_DOT_STRING=true 防崩溃，保持默认

   [flatten]
   enable = true
   mode = "basic"          # 或 "dominator"（更强、更慢）

   [bogus_control_flow]
   enable = true
   # prob=80, max_regions=2, max_region_instructions=8 为默认，可先不动

   [pass_order]
   order = ["StringEncryption", "IndirectCall", "Flatten", "BogusControlFlow", "VmFlatten", "Mba"]
   # 注意：BogusControlFlow 必须先于 VmFlatten（硬依赖）

⑤ Android.mk 接入（ndk-build 等效方式，须先在最小 hello.c 上验证）：
   LOCAL_CFLAGS  += -fpass-plugin=$(AMICE_PLUGIN)      # AMICE_PLUGIN=<解压目录>/amice/lib/libamice.so
   LOCAL_CPPFLAGS += -fpass-plugin=$(AMICE_PLUGIN)
   编译前 export AMICE_CONFIG_PATH=$(pwd)/amice.toml
   用 bundle 内的 NDK 跑 ndk-build（ndk-build 必须由加载了 env.sh 的 shell 调用）

⑥ 编译并验证（先小步验证，勿一上来全开）：
   - 最小验证：用 bundle 的 clang wrapper 编译官方 QuickStart 的 hello.c，strings 确认 "AMICE_STRING_TEST" 消失
   - 再对项目整体编译：RUST_LOG=amice=debug 查看日志（"pass done" = 有变换；VMP "skip function" 有原因）
   - 产物拷回 Windows → llvm-strings 对比明文消失 → 改名 imguiobf.sh 推送设备验证

⑦ 真机回归（adb 命令见 §3 环境表）：
   adb push 产物 /data/local/tmp/imguiobf.sh
   adb shell "su -c 'chmod 755 /data/local/tmp/imguiobf.sh; /data/local/tmp/imguiobf.sh > /data/local/tmp/run.log 2>&1 &'"
   检查：进程存活（TracerPid=0）、logcat 窗口名 AImGui + SceneRecognition、截屏确认 ImGui 面板渲染、无花屏无崩溃
   （注意：截图用 cmd /c 重定向，PowerShell `>` 会破坏二进制；远程命令中 $() 会被本地展开，需用引号包裹单引号）
```

### 4.4 建议的混淆强度组合（按"核心逻辑重混淆、渲染循环轻混淆"原则）
- **全局开启**（amice.toml）：StringEncryption + Flatten(basic) + BCF（轻档）—— 覆盖面广、风险低。
- **函数注解**（关键 hook 逻辑，如 ANativeWindowCreator 核心方法）：
  `__attribute__((noinline, annotate("+vm_virtualize,vm_runtime_scope=func")))`
  VMP 默认内置 `amice-simple-vmp` profile；先 1~2 个函数验证，再扩大。
- **建议跳过/轻混淆**：ImGui 渲染循环、字体加载、高频帧路径（强混淆会显著增大体积、拖慢运行）。
- **API 级别**：wrapper 默认 API 23，项目是 `APP_PLATFORM=android-22`，设 `AMICE_ANDROID_API=22` 保持一致。
- 与现有加固叠加：Obfuscate（源码级运行时加密）与 Amice 字符串加密（编译期 .str 段）互补，可并存；GhostTrace 反调试保留。

### 4.5 验证清单（验收标准）
- [ ] ndk-build 编译成功（O3 + LTO 可选先不开）
- [ ] `strings` 检查：AImGui / dumpsys / `_ZN7android` / 字体名 / 命令串明文消失（除品牌残留）
- [ ] RUST_LOG 日志显示各 Pass "pass done"
- [ ] 真机运行：进程存活、面板渲染正常、无崩溃无花屏
- [ ] 性能对比：混淆前后启动时间 / 帧率差异可接受（强混淆函数控制在少数）
- [ ] （可选）用 IDA/Ghidra 抽查关键函数确认已平坦化/虚拟化

## 5. 已修改源码清单（git 状态 = 已提交到 hardening 分支）

| 文件 | 改动 |
|---|---|
| `jni\Android.mk` | L0 flags（§3） |
| `jni\src\main.cpp` | 窗口名 Obfuscate + GhostTrace 初始化/周期检测 |
| `jni\src\Android_draw\draw_Gui.cpp` | 第二个 Create 调用字符串加密 |
| `jni\src\Android_my_imgui\my_imgui.cpp` | 字体文件名加密 + 即用即毁（L1.5） |
| `jni\include\native_surface\ANativeWindowCreator.h` | 82 个符号 + 命令串加密；ResolveMethod 显式转换；宏内 RAII 即用即毁（L1.5） |
| `jni\include\My_Utils\obfuscate.h` | vendored Obfuscate + `scoped_plaintext` RAII 辅助类（L1.5） |
| `jni\include\ghosttrace\ghosttrace.h` | vendored GhostTrace 头（品牌中性化） |
| `jni\src\ghosttrace\*.c`（6 个） | vendored GhostTrace 源码 + PLATFORM_MACOS 修复 |

## 6. 踩坑记录（接手者必读，全是真金白银）

1. **本机无 Bash**：Windows 侧一律 PowerShell + 反斜杠路径。
2. **PowerShell 重定向 `>` 会破坏二进制**（截图/zip 会损坏，曾产生 26KB 损坏 PNG）：需 `cmd /c` 重定向或写文件再读。
3. **PowerShell 里 `$(pidof ...)` 的 `$()` 会被本地先展开**：远程 adb 命令要用引号包裹单引号。
4. **github.com 网页 fetch 被 robots.txt 拒绝**：用 api.github.com（必须带 User-Agent header）+ codeload.github.com。
5. **C 盘空间紧张（~5.2GB）**：大文件下载到 E:\obfus_dl\。
6. **工具输出被吞时先写文件再 Read**（如 amice_structure.txt 模式）。
7. **amice 配置陷阱**：`AMICE_PASS_ORDER` 是允许列表（只装列出的 Pass）；配置解析失败静默回退默认值（看不出错）；改了配置必须重编源码，复用旧 .o 不生效；字符串加密保持 `AMICE_STRING_ONLY_DOT_STRING=true`（false 可能崩溃）。
8. **GhostTrace 勿启用 `gt_detect_debugger_android`**（含 root 检测，误杀 KernelSU root 环境）。
9. **git 分支情况**：本地 `main` 与 `hardening` 都指向 4119f64（init 默认分支），与远端 main（原版 v2.1.2）无关；回滚只影响本地，已推送分支需 revert/force push（force push 需谨慎）。
10. **git 推送代理坑**：git 全局配置了 `http.proxy=http://127.0.0.1:7897`（Clash 端口）——代理软件没开时 push 会报 `Failed to connect to github.com port 443 via 127.0.0.1`。解决：临时直连 `git -c http.proxy= -c https.proxy= push origin hardening`（不改全局配置；直连 github 可达）。

## 7. 参考资料（Amice 文档，按接入优先级）

- `E:\download\amice-master\amice-master\docs\QuickStart_zh_CN.md` —— 最小示例 + 接入方式
- `...\docs\Download_zh_CN.md` —— bundle 选择（r30 Linux x86_64）
- `...\docs\AndroidNDKSupport_zh_CN.md` —— bundle 解压/接入/常见错误
- `...\docs\EnvConfig_zh_CN.md` —— 全部开关全表（23KB，最重要）
- `...\docs\FunctionAnnotations_zh_CN.md` —— 按函数注解（VMP 入口）
- `...\docs\PassOrder_zh_CN.md` —— Pass 顺序/允许列表/优先级
- `...\docs\Troubleshooting_zh_CN.md` —— 加载失败/无效果排查
- `...\docs\VMPDesign_zh_CN.md` —— VMP 设计（233KB，深挖时再读）
- 官方脚本：`scripts\build_android_arm64.sh`、`package_android_ndk_bundle.sh`、`test_android_ndk_bundle.py`

## 8. 会话产物放置约定

- 接手文档：项目根（本文件）；会话总结：`C:\Users\wantaihong\Doubao\chats\2026-10-06\new-chat-5\`。
- 中间调研/验证文件：`E:\obfus_dl\`（保留，可按需回读）。
