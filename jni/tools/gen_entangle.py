#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_entangle.py -- 生成服务端密钥纠缠的加密配置头

机制: T3 控制台给卡密设置"核心数据(core)"字段 -> 登录响应带回 ->
客户端用 fnv1a(core) ^ fnv1a(appkey) 派生密钥 -> 解密内嵌配置。
没有经过真实登录(被 patch 的门禁) => core 为空 => 密钥错 => 解出垃圾 => 静默退出。

用法: python gen_entangle.py --core SECRET [--appkey fa98...] [--tick 90]
产出: entangled_cfg.h (含 ENC_CFG 密文与结构定义)
"""
import argparse, struct

def fnv1a64(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def keystream(key: int, n: int) -> bytes:
    out = bytearray()
    x = key & 0xFFFFFFFFFFFFFFFF
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out.append((x >> 33) & 0xFF)
    return bytes(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True, help="T3 控制台给卡密设置的核心数据")
    ap.add_argument("--appkey", default="fa98f186f0ee325b653331c1fdb02e8f")
    ap.add_argument("--tick", type=int, default=90, help="安全复检周期(帧)")
    ap.add_argument("--out", default="entangled_cfg.h")
    args = ap.parse_args()

    key = fnv1a64(args.core.encode()) ^ fnv1a64(args.appkey.encode())

    # 明文配置: magic + security_tick + draw_flags + spare + tag
    real = struct.pack("<IIII4s",
                       0x5A17C0DE,
                       args.tick & 0xFFFFFFFF,
                       0x000000C3,   # 绘制标志位(真值)
                       0xA5A5A5A5,   # 备用
                       b"T3OK")
    enc = bytes(r ^ k for r, k in zip(real, keystream(key, len(real))))

    hdr = []
    hdr.append("// 自动生成: gen_entangle.py --core <T3控制台核心数据>  (勿提交真实 core 到公开场合)")
    hdr.append("#pragma once")
    hdr.append("#include <cstdint>")
    hdr.append("")
    hdr.append("namespace t3 {")
    hdr.append("")
    hdr.append("struct EntangledCfg {")
    hdr.append("    uint32_t magic;        // 0x5A17C0DE")
    hdr.append("    uint32_t security_tick;// 安全复检周期(帧)")
    hdr.append("    uint32_t draw_flags;   // 绘制标志")
    hdr.append("    uint32_t spare;")
    hdr.append("    char     tag[4];       // \"T3OK\"")
    hdr.append("};")
    hdr.append("")
    hdr.append("// 明文配置与 fnv1a(core)^fnv1a(appkey) 密钥流的 XOR 结果")
    hdr.append("static const uint8_t ENC_CFG[20] = { %s };" % ", ".join("0x%02X" % b for b in enc))
    hdr.append("")
    hdr.append("} // namespace t3")
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(hdr) + "\n")

    print("[+] %s 生成完毕 (20 字节密文)" % args.out)
    print("    控制台 core = %r  security_tick = %d" % (args.core, args.tick))
    print("    提醒: T3 控制台该卡的'核心数据'字段必须填入相同 core, 否则程序将静默退出")

if __name__ == "__main__":
    main()
