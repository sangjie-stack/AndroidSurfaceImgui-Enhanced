# L2 加密强度验证报告（真机回归 + IDA 逆向视角）

> 2026-10-09。验证对象：`ASIMGUI-amice-NOEXC-FIXED-6.38MB.bin`（VM 构建，md5 `ec7422…94dc`）。
> 方法：① 真机全流程回归（设备 192.168.103.10:34417，KernelSU root）② IDA Pro 9 + Hex-Rays（ida-pro-mcp :13337）逆向视角强度度量。
> 结论先行：**加密包可用（真机回归通过），对静态逆向者已构成有效对抗；Hex-Rays 对 login 直接弃疗。**

---

## 1. 真机回归结果（发布门槛项）

| # | 验收项 | 结果 |
|---|---|---|
| ① | 版本检查 / 公告 / 卡密登录 | ✅ 自动登录成功，token 校验通过（任意卡串均通过，见下） |
| ② | .t3card 自动登录 | ✅ 登录成功、账号信息完整打印 |
| ③ | 60s 心跳 + 持续运行 | ✅ 观察窗口内（≥8 分钟，跨多个心跳周期）零心跳报错、进程存活、TracerPid=0、10 线程、AImGui 图层 z=2147483647 持续渲染、VmRSS 146MB 符合健康画像 |
| ④ | 错误卡密报错路径 | ⚠️ **不可测**——T3 平台该应用配置为"卡密随便输入"（公告原文），服务器对任意卡串都签发合法 token（错卡 `WRONGCARD-TEST-999` 也登录成功且 token 校验通过）。这是服务端配置，非客户端缺陷；反而额外证明 token 公式对任意输入都计算正确 |
| ⑤ | 心跳 UAF 回归 | ✅（修复版源码 + 实测跨心跳周期无崩溃；UAF 已由并行会话修复：值捕获 + shared_ptr 保活） |

**结论：NOEXC-FIXED 真机可用。**按 `L2_Amice实施记录.md` §0.5 的约定，t3sdk_noexc_fixed.cpp 现在具备覆盖回 `jni/src/t3sdk/t3sdk.cpp` 的条件。

## 2. IDA 逆向视角强度度量

### 2.1 符号与字符串（第一道墙）

- 函数总数 3922，**全部 `sub_XXXXXX` 无名**（symtab 零残留）。
- 全 IDB 正则搜 `t3yanzheng|t3data|appkey|statecode|kami|PUBLIC KEY|fa98f186|76478CC2` → **0 命中**。域名、调用码、APPKEY、RSA 公钥、请求字段名在二进制里不存在明文。
- 定位 T3 代码本身就需要锚点技巧（本次用 `strftime/localtime` 导入 xref 才找到 login——它是全工程唯一调用者）。

### 2.2 login 的混淆形态（核心证据）

Hex-Rays 反编译 0x4a69f4，**伪代码第一行即 IDA 的自动判词**：

```c
// The function seems has been flattened
__int64 __fastcall sub_4A69F4(...)
{
  if ( byte_627688 )            // ← BCF 不透明谓词
    n1791014216 = -1640338131;
  else
    n1791014216 = 1791014216;
  ...
  for ( i = n1791014216_1; ; i = n1026527638_1 )   // ← flatten 状态机分派器
  {
    while ( i <= -699114471 ) { ... }
    ...
    format_ ^= 0xAAu;            // ← 字符串解密桩：
    byte_619841 ^= 0xAAu;        //    "%Y%m%d%H%M"（token 日期格式串）
    byte_619842 ^= 0xAAu;        //    的 17 字节 lazy 解密级联
    ... (×15)
    strftime(s, 0x40uLL, &format_, tp);
```

三种混淆在同一函数内可见：flatten(basic) 状态机（魔数分派 + switch 已降级为无间接跳转的循环链）、BCF（±状态值二选一的不透明谓词）、StringEncryption（运行时 XOR 解密桩 + atomic 一次性锁）。

### 2.3 攻击面膨胀度量（数字对比）

| 函数 | baseline 预期（单函数可读） | NOEXC-FIXED 实测 |
|---|---|---|
| login 本尊 | ~数十块、伪代码可读 | **675 指令 / 81 块 / 2944 B**，Hex-Rays 判"flattened" |
| login 变体（BCF 克隆链） | — | **617 / 3679 / 4714 指令三个变体**（44/210/525 块） |
| verify_and_run | ~200 行 C++ 可读 | **2403 指令/145 块** + 巨型变体 **7560 指令/754 块/32608 B** |

要找到并 patch token 校验点，攻击者需在 **6 个 login/verify 变体、约 29000 字节**的平坦化+BCF 代码里区分真身与克隆——baseline 里这是一眼可读的一个函数。配合零符号、零明文，静态定位成本从"打开 IDA 五分钟"涨到"需要写 flatten 恢复工具或人肉跟状态机"。

### 2.4 诚实边界（哪些威胁没被防住）

1. **无 VMP/VM 字节码**：T3Example 实测 amice VmVirtualize 有 arm64 x0..x31 寄存器预算墙 + 指针物化限制，T3 核心函数全部不可虚拟化（详见 `T3Example混淆测试报告.md` 定论 2）；本包的强度来自 Flatten+BCF+字符串加密，**不是指令级虚拟化**。flatten(basic) 属业界已知可半自动恢复的混淆档位（存在学术工具如 deflat / D810 可部分还原），对手是有工具链的认真逆向者时，保护是"周级拖延"而非"不可破"。
2. **运行时 hook 仍在**：字符串在调用点解密（可 hook strftime/httpPost 观测）、token 比较仍是明文比较指令（找到后可 patch）。缓解：L1.9 反 Frida + L1.6 完整性自检 + 心跳双保险（已在本包内）。
3. **传输层明文 HTTP**（SDK 自带行为，T3 文档 §6.1 已声明）。
4. 彻底根治 patch-bypass 的下一步是服务端密钥纠缠（`T3加密保护设计.md` §4.2）——把验证产物变成业务必需的解密 key，patch 门禁只会得到错 key。

## 3. 交付物清单

| 产物 | 位置 |
|---|---|
| 加密包（已真机验证） | `artifacts\L2\ASIMGUI-amice-NOEXC-FIXED-6.38MB.bin`（设备 `/data/local/tmp/imguiobf.sh` 同款） |
| 备胎（保留异常的安全档） | `artifacts\L2\ASIMGUI-amice-SAFE-exc-5.60MB.bin` |
| 本报告 | 项目根 `L2强度验证_真机+IDA.md` |
| IDA 数据库 | `artifacts\L2\ASIMGUI-amice-NOEXC-FIXED-6.38MB.bin.i64`（:13337 MCP 在线） |
| T3Example 试验田 | VM `~/amice-lab/proj-t3`（A–G 七档 + 探针，全部可复现） |
