#!/usr/bin/env bash
# build_prod3_tls.sh -- PROD2 配方 + L3 TLS 传输层
#
# 与 build_prod2.sh 的差异:
#   1. 新增 jni/src/t3sdk/tls_transport.cpp (mbedTLS 静态链接), 随之链接
#      lib_mbedtls/lib_mbedx509/lib_mbedcrypto 三个预编译静态库。
#   2. 构建前显式 mkdir obj 目录树 —— PROD2 的 `rm -rf obj` + `-j8` 组合会踩
#      ndk-build 建目录竞态 (报 "unable to rename temporary ... No such file or
#      directory"), 表现为随机若干源文件编译失败。实测 -j1 必过, 加 mkdir 后 -j8 也稳。
set -uo pipefail
cd ~/amice-lab
B=~/amice-lab/amice-android-ndk-r30-linux-x86_64
NDK=$B/android-ndk-r30
P=~/amice-lab/proj-asimgui
export LD_LIBRARY_PATH=$B/amice/llvm-lib
export RUST_LOG=amice=debug
export AMICE_ANDROID_NDK_HOME=$NDK

# ---- amice 插件健康探测 ----
# 2026-10-09 22:08~22:11 期间 amice/lib/libamice.so 被替换过一次 (留有 libamice.so.orig
# 备份), 替换后的版本在本机加载即崩: "LLVM ERROR: out of memory" @ amice::plugin_registrar_sys
# (所有源文件都一样, 与源码无关)。这里先用最小样例探测, 崩了就退回 .orig, 避免整轮构建白跑。
PLUGIN=${PLUGIN:-$B/amice/lib/libamice.so}
PLUGIN_ORIG=$B/amice/lib/libamice.so.orig
PROBE_CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android22-clang++
if [ -f "$PLUGIN" ] && [ -f ~/amice-lab/amice_probe.cpp ]; then
  if ! $PROBE_CC -std=c++17 -fpass-plugin="$PLUGIN" -c ~/amice-lab/amice_probe.cpp -o /tmp/amice_probe_check.o >/dev/null 2>&1; then
    echo "!! 警告: $PLUGIN 加载失败 (探测样例编译崩溃)"
    if [ -f "$PLUGIN_ORIG" ] && $PROBE_CC -std=c++17 -fpass-plugin="$PLUGIN_ORIG" -c ~/amice-lab/amice_probe.cpp -o /tmp/amice_probe_check.o >/dev/null 2>&1; then
      echo "!! 回退到 $PLUGIN_ORIG (当前 libamice.so 有问题, 未覆盖它)"
      PLUGIN=$PLUGIN_ORIG
    else
      echo "!! FATAL: 两个插件都不可用"; exit 1
    fi
  fi
fi
echo "plugin=$PLUGIN"

export AMICE_STRING_ENCRYPTION=true AMICE_STRING_ALGORITHM=xor AMICE_STRING_DECRYPT_TIMING=lazy AMICE_STRING_ONLY_DOT_STRING=true
export AMICE_FLATTEN=false AMICE_BOGUS_CONTROL_FLOW=false AMICE_MBA=false
export AMICE_INDIRECT_BRANCH=false AMICE_INDIRECT_CALL=false
export AMICE_SPLIT_BASIC_BLOCK=false AMICE_SHUFFLE_BLOCKS=false AMICE_LOWER_SWITCH=false
export AMICE_VM_VIRTUALIZE=false AMICE_VM_FLATTEN=false
export AMICE_PASS_ORDER=StringEncryption,Flatten,BogusControlFlow,VmVirtualize,IndirectBranch

rm -rf $P/obj $P/libs
# 预建目录树, 规避 ndk-build -j8 建目录竞态
mkdir -p $P/obj/local/arm64-v8a/objs/AndroidSurfaceImguiEnhanced/src/{t3sdk,ghosttrace,ImGui,ImGui/backends,ImGui/misc/freetype,Android_draw,Android_touch,Android_Graphics,Android_my_imgui,My_Utils,security_extra,entangle}

# -j 并发: amice 插件每个 clang 实例都要加载一遍, 内存开销大。
# 本机 7GB/16核, -j8 会 LLVM OOM ("LLVM ERROR: out of memory"), 故用 -j4。
JOBS=${JOBS:-4}

t0=$(date +%s)
$NDK/ndk-build -j$JOBS \
  NDK_PROJECT_PATH=$P APP_BUILD_SCRIPT=$P/jni/Android.mk NDK_APPLICATION_MK=$P/jni/Application.mk \
  NDK_OUT=$P/obj NDK_LIBS_OUT=$P/libs \
  AMICE_PLUGIN_FLAG="-fpass-plugin=$PLUGIN" \
  AMICE_NO_EXCEPTIONS=1 AMICE_DROP_DEMO=1 > results/PROD3-TLS.log 2>&1
rc=$?
dt=$(( $(date +%s) - t0 ))
size=$(stat -c%s $P/libs/arm64-v8a/AndroidSurfaceImguiEnhanced 2>/dev/null || echo 0)
echo "rc=$rc jobs=$JOBS dt=${dt}s size=$size"
echo "--- 混淆统计 ---"
grep -a "pass done" results/PROD3-TLS.log | sed 's/.*\] //' | sort | uniq -c | sort -rn
echo "--- httpsPost 是否被 Flatten ---"
grep -a "httpsPost" results/PROD3-TLS.log | head -5
echo "--- 被跳过的敏感函数 ---"
grep -aE "skip function|not supported|skipping" results/PROD3-TLS.log | head -10
