# L3 — TLS 传输层：实施与验证

| 项目 | 内容 |
|---|---|
| 日期 | 2026-10-09 |
| 目标 | 消除 T3 验证链路的明文 HTTP，恢复真 TLS，并挡住抓包/中间人工具 |
| 选型 | mbedTLS 3.6.4 LTS（Apache-2.0，纯 C，零异常） |
| 产物 | `artifacts/L2/ASIMGUI-PROD3-TLS-3.38MB.bin` |
| 体积 | 3,101,344 → 3,377,592 字节（**+276 KB**） |
| 状态 | 主机端三条断言 + 真机四条测试全部通过；amice 混淆已确认作用于新代码 |

---

## 1. 问题

`t3sdk.cpp` 的 `httpPostRaw` 是手写裸 socket 明文 HTTP，且把 https 主动降级：

```cpp
/* HTTPS降级为HTTP（与C版本一致） */
if(info.protocol=="https") info.port=80;
```

实测六台 T3 服务器 **443 端口全部有合法 TLS 证书**（TrustAsia / Let's Encrypt），降级纯属原版 C 代码偷懒，不是服务端限制：

```
w.t3yanzheng.com    443 OK  CN=w.t3yanzheng.com     issuer=TrustAsia DV TLS RSA CA 2024
w2.t3yanzheng.com   443 OK  issuer=TrustAsia
w3/w4/w5.t3yanzheng.com 443 OK  issuer=Let's Encrypt YR1/YR2
w.t3data.net        443 OK  issuer=Let's Encrypt YR1
```

后果：tcpdump/Wireshark 直接可读全部请求（域名、参数框架、心跳节奏）。RSA 载荷加密保护了 kami 明文，但协议格式完全暴露，这是"抓包理解协议 → 挖 appkey → 本地伪造响应"攻击链的第一环。

---

## 2. 选型

| 库 | 许可证 | 结论 |
|---|---|---|
| **mbedTLS 3.6.4 LTS** | Apache-2.0 | **选定** |
| wolfSSL | GPLv2 / 商业双许可 | 排除：闭源 .so 静态链接有 GPL 传染风险 |
| OpenSSL 3.x | Apache-2.0 | 排除：体积大、NDK 交叉编译痛苦 |
| BoringSSL | 混合 | 排除：无稳定 API |
| Java 层 OkHttp + CertificatePinner | Apache-2.0 | 排除：把验证逻辑搬回 Java 层，Frida hook 难度反而降低，与全 native + VMP 路线冲突 |

选定 mbedTLS 的四条硬理由，全部针对本工程：

1. **纯 C、零异常** —— 工程全局 `-fno-exceptions`（amice VMP/Flatten 的前置条件，见 Android.mk 接线说明）。
2. **Apache-2.0** —— 闭源商用零负担。
3. **预编译静态库不传播 C++ feature** —— 源码子模块方式会把 exceptions 传播回主模块（Android.mk 里已记录的坑），预编译 `.a` 不会。
4. **可裁剪** —— 只留 TLS client + X.509 + RSA/ECDHE + AES-GCM/ChaCha20，砍掉服务端/DTLS/调试/自检。

---

## 3. 信任模型（两级）

### 一级：系统 CA + 主机名（硬门槛）

`mbedtls_ssl_conf_authmode(VERIFY_REQUIRED)` + `mbedtls_ssl_set_hostname()`。证书链验不通或主机名不匹配，握手直接失败。

**关键点：只读系统 CA 目录，刻意不读用户 CA 目录。**

```cpp
const char* const kSystemCaDirs[] = {
    "/apex/com.android.conscrypt/cacerts",  // Android 14+ (CA 存储迁到 conscrypt APEX)
    "/system/etc/security/cacerts",         // Android 4.0 ~ 13
    "/etc/ssl/certs",                       // 桌面调试
    nullptr
};
```

用户 CA 存在 `/data/misc/keychain/cacerts-added`，**不在列表里**。效果：攻击者把 Charles/Fiddler/Burp/mitmproxy 的根证书装进手机用户存储，本客户端也永远不会信任它 —— 中间人工具直接出局。

### 二级：颁发者白名单

叶子证书的签发者必须命中已知公共 CA 名单（Let's Encrypt / TrustAsia / DigiCert / Sectigo / GlobalSign / Google Trust Services / ZeroSSL / Buypass / SSL.com / Actalis / Certum / Entrust / Amazon / GoDaddy / Starfield / IdenTrust / HARICA / SecureTrust / Certigna / USERTrust / COMODO）。

防的是 **root 设备上攻击者往系统 CA 存储里塞自签根证书**的场景 —— 那种情况一级门槛会放行，白名单能拦下（自建 CA 不可能叫 "Let's Encrypt"）。

**不锁叶子证书公钥。** 实测 T3 六台服务器证书各自独立、90 天短命、CA 混用两家。锁叶子 = 每次续期全体客户端变砖。锁"颁发者"这一层既挡住自签 MITM CA，又能扛住 T3 的正常证书轮换。

---

## 4. 代码落点

| 文件 | 说明 |
|---|---|
| `jni/include/t3sdk/tls_transport.h` | 接口：`t3tls::httpsPost(host,port,path,postData,outBody)` |
| `jni/src/t3sdk/tls_transport.cpp` | 实现（CA 加载 / BIO 回调 / 白名单 / HTTP 交换） |
| `jni/src/t3sdk/t3sdk.cpp` | `httpPostRaw` 分流：Android 走 TLS，`_WIN32` 保留旧明文路径仅作桌面调试 |
| `jni/Android.mk` | 三个预编译静态库模块 + 源文件 + `-DMBEDTLS_CONFIG_FILE` |
| `jni/include/mbedtls/`、`jni/include/psa/` | mbedTLS 头文件树 |
| `jni/include/mbedtls_config_android.h` | 裁剪配置（113 个 `#define`） |
| `jni/prebuilt/mbedtls/arm64-v8a/*.a` | 交叉编译产物 |
| `jni/tools/build_mbedtls_arm64.sh` | 交叉编译脚本 |
| `jni/tools/run_tls_test_host.sh` | 主机端验证套件 |
| `jni/tools/tls_transport_test.cpp` | 验证台 |
| `jni/tools/build_prod3_tls.sh` | PROD3 构建配方 |

### 实现要点

- **BIO 超时映射**：socket `EAGAIN` 必须映射成 `MBEDTLS_ERR_SSL_TIMEOUT`，**不能**返回 `WANT_READ` —— 否则 mbedTLS 无限重试，请求挂死。
- **线程安全**：整个 TLS 会话持互斥锁串行化（心跳线程与主线程共用同一套 drbg/config；`mbedtls_ctr_drbg_random` 非线程安全）。
- **PSA 初始化**：mbedTLS 3.6 默认开启 `MBEDTLS_USE_PSA_CRYPTO`，必须先 `psa_crypto_init()`。
- **Content-Length 提前收尾**：读完声明长度即停，不等服务器关连接，防 keep-alive 挂到超时。
- **无明文回退**：Android 分支 TLS 失败直接返回空串触发备用线路切换，**不降级明文** —— 有回退就等于给攻击者留了降级通道。

---

## 5. 构建

```bash
# 1) 交叉编译 mbedTLS（Ubuntu, NDK r30, API 22）
bash jni/tools/build_mbedtls_arm64.sh
#    -> ~/amice-lab/mbedtls-out/arm64-v8a/{libmbedtls,libmbedx509,libmbedcrypto}.a

# 2) 生产构建
bash build_prod3_tls.sh
```

**两个踩过的坑：**

1. **ndk-build `-j8` 建目录竞态**：`rm -rf obj` 后立刻并行编译，会随机报
   `unable to rename temporary ... No such file or directory`。`build_prod3_tls.sh` 在构建前显式 `mkdir -p` 目录树规避。
2. **mbedTLS tarball 缺 framework 子模块**：`scripts/config.py` 不可用（改 sed 裁剪），
   `library/Makefile` 需要 `framework/scripts/generate_ssl_debug_helpers.py` 生成
   `ssl_debug_helpers_generated.c`。该文件内容整体被 `#if defined(MBEDTLS_DEBUG_C)` 包裹，
   而我们已关闭 `MBEDTLS_DEBUG_C`，故脚本注入一个生成空文件的存根即可。
3. **主机版 mbedTLS 构建陷阱**：arm64 交叉编译留下的 `.o` 比源码新，`make clean` 不保证清干净，
   会把 AArch64 的 `.o` 重新打包成"主机版"。验证脚本里改为硬删 `.o/.a` 并断言产物架构。

---

## 6. 验证证据

### 6.1 主机端三条断言（`jni/tools/run_tls_test_host.sh`）

```
=== 断言 A: 真实 T3 服务器应通过 (全部 6 台) ===
[PASS] w.t3yanzheng.com:443  ok  body: f  错误的调用  0
[PASS] w2.t3yanzheng.com:443 ok
[PASS] w3.t3yanzheng.com:443 ok
[PASS] w4.t3yanzheng.com:443 ok
[PASS] w5.t3yanzheng.com:443 ok
[PASS] w.t3data.net:443      ok
断言A 失败数: 0

=== 断言 B: 自签证书服务器必须被拒绝 ===
[PASS] host=127.0.0.1:18443 expect=reject got=reject

=== 断言 C: 清空颁发者白名单后, 真实 T3 也必须被拒绝 ===
[PASS] host=w.t3yanzheng.com:443 expect=reject got=reject
```

- **A** 证明 TLS 握手 + 系统 CA 校验 + 主机名校验 + 白名单全链路通，且与 T3 完成了真实 HTTP 交换（返回了 T3 的业务错误响应 `f 错误的调用 0`）。
- **B** 证明自签证书服务器（等价于用户自装 CA 的中间人）被拒绝。
- **C** 是**否定对照**：清空白名单后连真实 T3 都被拒 —— 证明第二级门槛是活的，不是死代码。

### 6.2 真机测试（PKG110 / Android 16 / KernelSU root）

测试二进制：`tls_transport.cpp` + 验证台，arm64 静态链接 mbedTLS，推至 `/data/local/tmp/t3tls_test_arm64`。

```
=== 正向: 真机走 Android 系统 CA 存储 ===
[PASS] host=w.t3yanzheng.com:443   expect=ok got=ok
[PASS] host=w2.t3yanzheng.com:443  expect=ok got=ok
[PASS] host=w.t3data.net:443       expect=ok got=ok

=== 否定: 系统信任但签发者不在白名单 ===
[PASS] host=www.12306.cn:443   expect=reject got=reject   (CFCA 签发)
[PASS] host=www.gdca.com.cn:443 expect=reject got=reject  (GDCA 签发)
```

正向测试证明 **Android 侧 CA 目录加载路径正确**（`/apex/com.android.conscrypt/cacerts` 生效）。
否定测试证明**第二级白名单在真机上确实拦截**：CFCA / GDCA 签发的证书是系统信任的合法证书，仍被拒。

> 注意这是有意的取舍：本客户端只与 T3 通信，任何非白名单 CA 的站点都会被拒。
> 若 T3 未来换用名单外的 CA（例如某些区域性 CA），需要更新 `kIssuerAllowlist` 并重新出包。

### 6.3 混淆验证

`AMICE_FLATTEN_H` 注解确实作用到新代码 —— A/B 对照（同一份源码，仅去掉注解）：

```
带注解: _ZN5t3tls9httpsPostE...  0x2ebc = 11,964 字节
去注解: _ZN5t3tls9httpsPostE...  0x0af4 =  2,804 字节
```

Flatten + BCF + IndirectBranch 使函数体积膨胀 4.3 倍，确证生效。

### 6.4 线级字节 A/B（`jni/tools/wire_capture_ab.sh`）

不需要 root/tcpdump：让客户端对着本地监听器发一次请求，直接看它**出网的原始字节**。
两个探针：`legacy_plaintext_probe.cpp`（复刻改造前的明文路径）与 `tls_transport`（新实现）。

```
--- [legacy] 出网前 96 字节 ---
00000000: 504f 5354 202f 6c6f 6769 6e20 4854 5450  POST /login HTTP
00000010: 2f31 2e31 0d0a 486f 7374 3a20 3132 372e  /1.1..Host: 127.
00000020: 302e 302e 310d 0a43 6f6e 7465 6e74 2d54  0.0.1..Content-T
--- [legacy] 是否含 HTTP 明文关键字 ---
含明文: POST /login  Host: 127.0.0.1  kami=TEST-KAMI-1234
--- [legacy] 首字节 ---  first_byte=0x50   ('P')

--- [tls] 出网前 96 字节 ---
00000000: 1603 0301 5101 0001 4d03 0392 2c7c 8462  ....Q...M...,|.b
00000010: 57cd e144 129c d76d 0d3f 2d45 5efc 5dfa  W..D...m.?-E^.].
00000050: 1302 1301 1304 1305 cca8 cca9 ccaa c02c  ...............,
--- [tls] 是否含 HTTP 明文关键字 ---
无 HTTP 明文
--- [tls] 首字节 ---  first_byte=0x16   (TLS handshake)
```

- 旧路径首字节 `0x50` = `POST /login HTTP/1.1`，卡密 `kami=TEST-KAMI-1234` 明文可见。
- 新路径首字节 `0x16` = TLS handshake 记录，密码套件 `1303/1302/1301/1304/1305`（TLS 1.3）+ `c02c...`，**全流量无任何 HTTP 明文**。

这是本次改造的最终验收证据：改造前抓包能直接读到请求全文，改造后只能看到 TLS 记录。

---

## 7. 残余风险与运维注意

1. **TLS 不解决"离线伪造响应"**：攻击者从内存挖出 appkey + token 公式后，可以本地起假服务器（配合 hosts 劫持）伪造响应 —— TLS 挡不住，因为那是应用层信任问题。根治仍归服务端密钥纠缠（§4.2）。
2. **CA 白名单是硬编码**：T3 换 CA 需改代码重出包。名单刻意放宽到主流公共 CA 以降低概率。
3. **root 攻击者可 patch `.so`**：直接 hook `httpsPost` 返回伪造结果。这已不属于网络层攻击，归 entangle/VMP/内存防线。
4. **`kIssuerAllowlist` / `kSystemCaDirs` 字符串未加密**：amice 的 `only_dot_str=true` 只加密含点的字符串（域名），这两个数组是明文。可被字符串搜索定位。价值有限（知道白名单也造不出这些 CA 的证书），但如需加固可改用 `AMICE_STRING_ONLY_DOT_STRING=false` 或手工 XOR。
5. **体积 +276 KB**：PROD2 3,101,344 → PROD3-TLS 3,377,592 字节。

---

## 8. 现场发现（非本次改动引入）

**amice 插件在本次会话中被替换过。** 时间线：

| 时间 | 事件 |
|---|---|
| 22:08 | `amice/lib/libamice.so.orig` 出现（旧版备份，8,262,824 字节） |
| 22:11 | `libamice.so` 被替换（8,301,352 字节） |
| 22:13+ | 所有 amice 构建失败：`LLVM ERROR: out of memory` @ `amice::plugin_registrar_sys` |

A/B 验证：当前 `libamice.so` 加载即崩（插件注册阶段 `bad_alloc`，与源码无关，任意源文件都一样）；`libamice.so.orig` 正常工作。

**处理**：未覆盖当前 `libamice.so`（不是本次改动创建的，不动它）。`build_prod3_tls.sh` 增加了插件健康探测：用最小样例试编译，崩了就回退 `.orig` 并告警。PROD3 产物即由 `.orig` 构建。

**待办**：确认 22:11 那次替换的来源与意图 —— 若是有意的插件升级，需要单独排查新版在本机的崩溃原因（llvm-sys 21.1 / clang 21.0.0 ABI 匹配问题）。

---

## 9. 回归清单

- [x] 主机端 6/6 真实服务器 TLS 通过
- [x] 主机端自签 MITM 被拒
- [x] 白名单否定对照（清空后 T3 被拒）
- [x] 真机 Android CA 存储加载 + 真实 TLS 交换
- [x] 真机非白名单签发者被拒
- [x] amice Flatten 确认作用于 `httpsPost`
- [x] **线级字节 A/B**：旧路径明文 `POST /login` + `kami=` 可见；新路径仅 TLS 记录（首字节 `0x16`）
- [x] PROD3 产物归档（`artifacts/L2/ASIMGUI-PROD3-TLS-3.38MB.bin`）
- [ ] **真机全流程回归**（登录 / 自动登录 / 心跳 / 到期 / token 校验）—— 需在目标游戏环境跑完整 App
