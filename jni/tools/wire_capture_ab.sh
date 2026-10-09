#!/usr/bin/env bash
# wire_capture_ab.sh -- 线级字节 A/B: 旧明文路径 vs 新 TLS 路径
#
# 不需要 root/tcpdump: 让客户端对着本地监听器发一次请求, 直接看它出网的原始字节。
#   旧路径 (legacy_plaintext_probe): 应看到 "POST /login HTTP/1.1" 明文
#   新路径 (tls_transport):          应看到 TLS 记录头 16 03 .. , 无任何 HTTP 明文
set -uo pipefail

PROJ=~/amice-lab/proj-asimgui
OUT=~/amice-lab/mbedtls-out/host
cd "$PROJ" || exit 1

echo "=== 编译两个探针 ==="
clang++ -std=c++17 -O1 -w jni/tools/legacy_plaintext_probe.cpp -o /tmp/legacy_probe || exit 1
clang++ -std=c++17 -O1 -w -I jni/include/t3sdk -I jni/include -I jni/include/My_Utils -I "$OUT/include" \
  -DMBEDTLS_CONFIG_FILE='"mbedtls_config_android.h"' \
  jni/src/t3sdk/tls_transport.cpp jni/tools/tls_transport_test.cpp \
  "$OUT/libmbedtls.a" "$OUT/libmbedx509.a" "$OUT/libmbedcrypto.a" -lpthread -o /tmp/t3tls_test || exit 1
echo "ok"

# 本地监听器: 收 N 字节或超时后落盘
cat > /tmp/grab.py <<'PY'
import socket, sys, time
port, outpath = int(sys.argv[1]), sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1); s.settimeout(12)
try:
    c, _ = s.accept()
except socket.timeout:
    open(outpath, "wb").write(b""); sys.exit(0)
c.settimeout(4)
buf = b""
try:
    while len(buf) < 4096:
        d = c.recv(1024)
        if not d: break
        buf += d
except socket.timeout:
    pass
open(outpath, "wb").write(buf)
PY

run_case() {
  local name=$1 port=$2 cmd=$3 out=/tmp/cap_$1.bin
  rm -f "$out"
  python3 /tmp/grab.py "$port" "$out" &
  local grab=$!
  sleep 0.6
  eval "$cmd" >/dev/null 2>&1
  wait $grab 2>/dev/null
  echo
  echo "--- [$name] 出网前 96 字节 ---"
  xxd -l 96 "$out" 2>/dev/null || echo "(无数据)"
  echo "--- [$name] 是否含 HTTP 明文关键字 ---"
  if strings "$out" 2>/dev/null | grep -qE 'POST |Host:|kami=|HTTP/1\.1'; then
    echo "含明文: $(strings "$out" | grep -oE 'POST /[^ ]*|Host: [^ ]*|kami=[^&]*' | head -3 | tr '\n' ' ')"
  else
    echo "无 HTTP 明文"
  fi
  echo "--- [$name] 首字节 ---"
  head -c 1 "$out" 2>/dev/null | xxd -p | sed 's/^/first_byte=0x/'
}

run_case legacy 18444 "/tmp/legacy_probe 127.0.0.1 18444"
run_case tls    18445 "/tmp/t3tls_test 127.0.0.1 18445 reject"

echo
echo "=== 判定 ==="
echo "legacy 应含明文且首字节 0x50 ('P'); tls 应无明文且首字节 0x16 (TLS handshake)"
