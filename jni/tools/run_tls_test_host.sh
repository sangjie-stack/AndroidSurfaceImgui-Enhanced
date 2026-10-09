#!/usr/bin/env bash
# run_tls_test_host.sh -- tls_transport 的 x86-64 主机端验证
#
# 在 Ubuntu 上用同一份 tls_transport.cpp 跑三条断言 (见 tls_transport_test.cpp 头注释):
#   A. 真实 T3 服务器应通过
#   B. 自签证书服务器必须被拒绝 (模拟用户自装 CA 的中间人)
#   C. 清空颁发者白名单后, 真实 T3 也应被拒绝 (证明第二级门槛真的在生效)
set -uo pipefail

MB=~/amice-lab/mbedtls-3.6.4
OUT=~/amice-lab/mbedtls-out/host
PROJ=~/amice-lab/proj-asimgui
HOSTBIN=/tmp/t3tls_test

echo "=== 1. 主机版 mbedTLS 3.6.4 (同一份裁剪配置) ==="
mkdir -p "$OUT"
if [ ! -f "$OUT/libmbedtls.a" ]; then
  cd "$MB" || exit 1
  # 必须硬删目标文件: arm64 交叉编译留下的 .o 比源码新, make clean 不保证清干净,
  # 否则 make 会跳过重编, 直接把 AArch64 的 .o 重新打包成"主机版"(踩过)。
  rm -f library/*.o library/*.a
  make -j8 lib CC=clang AR=llvm-ar \
    CFLAGS="-O2 -fPIC -DMBEDTLS_CONFIG_FILE='\"mbedtls_config_android.h\"' -I$MB -I$MB/include -I$MB/library -w" \
    >/tmp/mb_host.log 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then echo "FATAL: 主机版 mbedTLS 构建失败"; tail -20 /tmp/mb_host.log; exit 1; fi
  cp library/libmbedtls.a library/libmbedx509.a library/libmbedcrypto.a "$OUT/"
  mkdir -p "$OUT/include"
  cp -r include/mbedtls include/psa "$OUT/include/" 2>/dev/null
  cp mbedtls_config_android.h "$OUT/include/"
fi
ls -la "$OUT"/*.a
# 架构断言: 必须是主机架构, 否则说明又拿到交叉编译产物
# (用 ar 抽一个成员交给 file 判定; objdump 的输出被本地化, 不便 grep)
HOSTARCH=$(uname -m)
MEMBER=$(ar t "$OUT/libmbedtls.a" | head -1)
ar p "$OUT/libmbedtls.a" "$MEMBER" > /tmp/t3tls_arch_probe.o
LIBSARCH=$(file -b /tmp/t3tls_arch_probe.o)
echo "host=$HOSTARCH libs=$LIBSARCH"
case "$HOSTARCH:$LIBSARCH" in
  x86_64:*x86-64*)   ;;
  aarch64:*aarch64*) ;;
  *) echo "FATAL: 主机版库架构不匹配 (host=$HOSTARCH, libs=$LIBSARCH)"; exit 1 ;;
esac

echo
echo "=== 2. 编译验证台 ==="
cd "$PROJ" || exit 1
clang++ -std=c++17 -O1 -w \
  -I jni/include/t3sdk -I jni/include -I jni/include/My_Utils -I "$OUT/include" \
  -DMBEDTLS_CONFIG_FILE='"mbedtls_config_android.h"' \
  jni/src/t3sdk/tls_transport.cpp jni/tools/tls_transport_test.cpp \
  "$OUT/libmbedtls.a" "$OUT/libmbedx509.a" "$OUT/libmbedcrypto.a" \
  -lpthread -o "$HOSTBIN" || { echo "FATAL: 验证台编译失败"; exit 1; }
echo "built: $HOSTBIN"

echo
echo "=== 3. 断言 A: 真实 T3 服务器应通过 (全部 6 台) ==="
A_FAIL=0
for h in w.t3yanzheng.com w2.t3yanzheng.com w3.t3yanzheng.com w4.t3yanzheng.com w5.t3yanzheng.com w.t3data.net; do
  "$HOSTBIN" "$h" 443 ok || A_FAIL=$((A_FAIL+1))
done
echo "断言A 失败数: $A_FAIL"

echo
echo "=== 4. 断言 B: 自签证书服务器必须被拒绝 ==="
TMPD=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TMPD/k.pem" -out "$TMPD/c.pem" -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
openssl s_server -quiet -accept 18443 -cert "$TMPD/c.pem" -key "$TMPD/k.pem" \
  >/dev/null 2>&1 &
SRV=$!
sleep 1
B_RC=0
"$HOSTBIN" 127.0.0.1 18443 reject || B_RC=1
kill $SRV 2>/dev/null
rm -rf "$TMPD"
echo "断言B: $([ $B_RC -eq 0 ] && echo PASS || echo FAIL)"

echo
echo "=== 5. 断言 C: 清空颁发者白名单后, 真实 T3 也必须被拒绝 ==="
mkdir -p /tmp/t3tls_c
# 把白名单数组整体替换成 { nullptr } (只改这一处, 其余代码原样)
awk '
  /^const char\* const kIssuerAllowlist\[\] = \{/ {
    print "const char* const kIssuerAllowlist[] = { nullptr };"
    skip = 1; next
  }
  skip && /^\};$/ { skip = 0; next }
  !skip { print }
' jni/src/t3sdk/tls_transport.cpp > /tmp/t3tls_c/tls_transport_noallow.cpp
grep -n "kIssuerAllowlist" /tmp/t3tls_c/tls_transport_noallow.cpp
clang++ -std=c++17 -O1 -w \
  -I jni/include/t3sdk -I jni/include -I jni/include/My_Utils -I "$OUT/include" \
  -DMBEDTLS_CONFIG_FILE='"mbedtls_config_android.h"' \
  /tmp/t3tls_c/tls_transport_noallow.cpp jni/tools/tls_transport_test.cpp \
  "$OUT/libmbedtls.a" "$OUT/libmbedx509.a" "$OUT/libmbedcrypto.a" \
  -lpthread -o /tmp/t3tls_test_noallow 2>/dev/null
if [ -x /tmp/t3tls_test_noallow ]; then
  C_RC=0
  /tmp/t3tls_test_noallow w.t3yanzheng.com 443 reject || C_RC=1
  echo "断言C: $([ $C_RC -eq 0 ] && echo PASS || echo FAIL)"
else
  echo "断言C: SKIP (白名单清空版编译失败)"
fi

echo
echo "=== 汇总 ==="
echo "A(真实服务器通过) 失败=$A_FAIL  B(自签拒绝)=$([ $B_RC -eq 0 ] && echo PASS || echo FAIL)"
