#!/usr/bin/env bash
# build_mbedtls_arm64.sh -- 为 AndroidSurfaceImguiEnhanced 交叉编译 mbedTLS 3.6.4 (arm64-v8a)
#
# 目的: t3sdk.cpp 的 httpPostRaw 需要真 TLS。
# 选型: mbedTLS 3.6.4 LTS / Apache-2.0 / 纯 C 零异常 (工程全局 -fno-exceptions)
#
# 产物: ~/amice-lab/mbedtls-out/arm64-v8a/{libmbedtls.a,libmbedx509.a,libmbedcrypto.a}
#       + include/ 头文件树 + mbedtls_config_android.h
#
# 注: 本 tarball 不带 framework 子模块, scripts/config.py 不可用,
#     因此裁剪直接用 sed 改 config-default.h。
set -uo pipefail

SRC=~/amice-lab/mbedtls-3.6.4
OUT=~/amice-lab/mbedtls-out
NDKBIN=~/amice-lab/amice-android-ndk-r30-linux-x86_64/android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin
API=22
ABI=arm64-v8a
CFGHDR=mbedtls_config_android.h

CC=$NDKBIN/aarch64-linux-android${API}-clang
AR=$NDKBIN/llvm-ar
RANLIB=$NDKBIN/llvm-ranlib
READELF=$NDKBIN/llvm-readelf

[ -x "$CC" ] || { echo "FATAL: 找不到 $CC"; exit 1; }

cd "$SRC" || exit 1

# ---- 1. 生成裁剪配置 ----
# 3.6.x 的"默认配置"就是 include/mbedtls/mbedtls_config.h (configs/ 下只有变体)
cp include/mbedtls/mbedtls_config.h "$CFGHDR"

unset_opt() { sed -i "s|^#define $1\b|//#define $1|" "$CFGHDR"; }
set_opt()   { sed -i "s|^//#define $1\b|#define $1|"  "$CFGHDR"; }

# 传输层: 自带 socket, 不用库的 net/timing
unset_opt MBEDTLS_NET_C
unset_opt MBEDTLS_TIMING_C
# 文件系统: 证书由自己的代码读入内存
unset_opt MBEDTLS_FS_IO
# 服务端: 纯客户端
unset_opt MBEDTLS_SSL_SRV_C
# DTLS: 不用
unset_opt MBEDTLS_SSL_DTLS_ANTI_REPLAY
unset_opt MBEDTLS_SSL_DTLS_HELLO_VERIFY
unset_opt MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
unset_opt MBEDTLS_SSL_DTLS_CONNECTION_ID
unset_opt MBEDTLS_SSL_PROTO_DTLS
unset_opt MBEDTLS_SSL_COOKIE_C
# 用不到的 X509 功能
unset_opt MBEDTLS_X509_CRL_PARSE_C
unset_opt MBEDTLS_X509_CSR_PARSE_C
unset_opt MBEDTLS_X509_CREATE_C
unset_opt MBEDTLS_X509_CRT_WRITE_C
unset_opt MBEDTLS_X509_CSR_WRITE_C
unset_opt MBEDTLS_PKCS12_C
unset_opt MBEDTLS_PKCS5_C
unset_opt MBEDTLS_PKCS7_C
unset_opt MBEDTLS_PK_WRITE_C
unset_opt MBEDTLS_PK_PARSE_EC_LEGACY
# 自检/调试: 自检表体积大, 调试字符串污染二进制
unset_opt MBEDTLS_SELF_TEST
unset_opt MBEDTLS_DEBUG_C
unset_opt MBEDTLS_MEMORY_BUFFER_ALLOC_C
unset_opt MBEDTLS_PLATFORM_TIME_ALT
# PSA 存储
unset_opt MBEDTLS_PSA_ITS_FILE_C
unset_opt MBEDTLS_PSA_CRYPTO_STORAGE_C
# 旧协议/弱算法
unset_opt MBEDTLS_SSL_PROTO_TLS1
unset_opt MBEDTLS_SSL_PROTO_TLS1_1
unset_opt MBEDTLS_ARC4_C
unset_opt MBEDTLS_DES_C
unset_opt MBEDTLS_BLOWFISH_C
unset_opt MBEDTLS_XTEA_C
unset_opt MBEDTLS_CAMELLIA_C
unset_opt MBEDTLS_ARIA_C
unset_opt MBEDTLS_MD2_C
unset_opt MBEDTLS_MD4_C
unset_opt MBEDTLS_RIPEMD160_C
unset_opt MBEDTLS_PADLOCK_C
unset_opt MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
unset_opt MBEDTLS_SSL_ALPN
unset_opt MBEDTLS_SSL_ENCRYPT_THEN_MAC
# 必须保留
set_opt MBEDTLS_HAVE_TIME
set_opt MBEDTLS_HAVE_TIME_DATE
set_opt MBEDTLS_SSL_PROTO_TLS1_2
set_opt MBEDTLS_SSL_PROTO_TLS1_3
set_opt MBEDTLS_SSL_SERVER_NAME_INDICATION

echo "=== 裁剪后 #define 计数 ==="
grep -cE '^#define MBEDTLS_' "$CFGHDR"
[ -f "$CFGHDR" ] || { echo "FATAL: 配置头未生成"; exit 1; }

# 3.6.4 的 tarball 不带 framework 子模块, 而 library/Makefile 的规则要求
# framework/scripts/generate_ssl_debug_helpers.py 生成 ssl_debug_helpers_generated.c。
# 该生成文件内容整体被 #if defined(MBEDTLS_DEBUG_C) 包裹, 而我们已经关掉 MBEDTLS_DEBUG_C,
# 所以用存根脚本生成空文件即可 (零语义影响, 省掉拉 framework 子模块)。
mkdir -p framework/scripts
cat > framework/scripts/generate_ssl_debug_helpers.py <<'PYEOF'
#!/usr/bin/env python3
"""存根: 生成空的 ssl_debug_helpers_generated.c。
   真实内容受 MBEDTLS_DEBUG_C 保护, 本项目已关闭该选项。"""
import sys
out = "ssl_debug_helpers_generated.c"
for i, a in enumerate(sys.argv):
    if a == "--output":
        out = sys.argv[i + 1]
open(out, "w").write("/* stub: MBEDTLS_DEBUG_C disabled */\n")
PYEOF
echo "stub generator: $(wc -l < framework/scripts/generate_ssl_debug_helpers.py) lines"

# ---- 2. 构建 ----
make clean >/dev/null 2>&1
make -j8 lib \
  CC="$CC" AR="$AR" RANLIB="$RANLIB" \
  CFLAGS="-O2 -fPIC -fvisibility=hidden -DMBEDTLS_CONFIG_FILE='\"$CFGHDR\"' -I$SRC -I$SRC/include -I$SRC/library -Wall -Wno-unused-parameter" \
  2>&1 | tail -25

rc=${PIPESTATUS[0]}
echo "make rc=$rc"

# ---- 3. 归档产物 ----
if [ "$rc" -eq 0 ]; then
  rm -rf "$OUT/$ABI"
  mkdir -p "$OUT/$ABI/include"
  cp library/libmbedtls.a library/libmbedx509.a library/libmbedcrypto.a "$OUT/$ABI/"
  cp -r include/mbedtls include/psa "$OUT/$ABI/include/" 2>/dev/null
  cp "$CFGHDR" "$OUT/$ABI/include/"
  echo "=== 产物 ==="
  ls -la "$OUT/$ABI/"/*.a
  for f in "$OUT/$ABI"/*.a; do
    printf -- "-- %-16s objs=%-4s arch=%s\n" "$(basename "$f")" "$("$AR" t "$f" | wc -l)" "$("$READELF" -h "$f" 2>/dev/null | grep -m1 Machine | awk '{print $2,$3}')"
  done
  echo "=== 总体积 ==="
  du -sh "$OUT/$ABI"
fi
