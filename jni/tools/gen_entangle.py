#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_entangle.py -- 生成服务端密钥纠缠的加密配置头 (v2: 密钥化校验, 无已知明文)

机制: T3 控制台给卡密设置"核心数据(core)"字段 -> 登录响应带回 ->
客户端用 fnv1a(core) ^ fnv1a(appkey) 派生密钥 -> LCG 密钥流 XOR 解密内嵌配置。
没有经过真实登录(被 patch 的门禁) => core 为空 => 密钥错 => 解出垃圾 => 延迟静默退出。

v2 变更 (审计 P0-2 修复):
  - 去掉固定明文校验常量(magic 0x5A17C0DE / tag "T3OK")——它们与密文同处一个
    二进制构成已知明文, 攻击者可直接 XOR 出 8 字节密钥流并用格攻击还原 LCG 状态。
  - 改为密钥化 CRC 校验: ecc = crc32_le32(tick ^ draw_flags ^ spare ^ key低32位),
    二进制内不存在任何"明文-密文"对。
  - spare 默认随机生成(每次构建不同), 进一步抬高猜测明文的成本。

用法: python gen_entangle.py --core SECRET [--appkey fa98...] [--tick 90]
产出: entangled_cfg.h (含 ENC_CFG 密文与结构定义)
"""
import argparse, os, struct, zlib

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
    ap.add_argument("--flags", type=lambda x: int(x, 0), default=0x000000C3,
                    help="绘制标志位(真值), 业务侧每帧异或消费")
    ap.add_argument("--spare", type=lambda x: int(x, 0), default=None,
                    help="二级 XOR 种子; 缺省每次随机生成(打印出来可复现)")
    ap.add_argument("--out", default="entangled_cfg.h")
    args = ap.parse_args()

    spare = args.spare if args.spare is not None else struct.unpack("<I", os.urandom(4))[0]
    tick = args.tick & 0xFFFFFFFF
    flags = args.flags & 0xFFFFFFFF
    spare &= 0xFFFFFFFF

    key = fnv1a64(args.core.encode()) ^ fnv1a64(args.appkey.encode())

    # 密钥化校验: 与 entangle_decode.cpp 的 crc32_ieee 完全一致
    ecc_input = struct.pack("<I", (tick ^ flags ^ spare ^ (key & 0xFFFFFFFF)) & 0xFFFFFFFF)
    ecc = zlib.crc32(ecc_input)

    real = struct.pack("<IIII", tick, flags, spare, ecc)
    enc = bytes(r ^ k for r, k in zip(real, keystream(key, len(real))))

    hdr = []
    hdr.append("// 自动生成: gen_entangle.py --core <T3控制台核心数据>  (勿提交真实 core 到公开场合)")
    hdr.append("// v2: 密钥化CRC校验(无已知明文常量) —— 必须与 entangle_decode.cpp 同版本")
    hdr.append("#pragma once")
    hdr.append("#include <cstdint>")
    hdr.append("")
    hdr.append("namespace t3 {")
    hdr.append("")
    hdr.append("struct EntangledCfg {")
    hdr.append("    uint32_t security_tick;// 安全复检周期(帧) -> 检测线程慢周期调制")
    hdr.append("    uint32_t draw_flags;   // 绘制标志 -> 检测随机源种子混合")
    hdr.append("    uint32_t spare;        // 二级 XOR 种子 -> 随机源种子混合")
    hdr.append("    uint32_t ecc;          // crc32(tick^flags^spare^key低32位)")
    hdr.append("};")
    hdr.append("")
    hdr.append("// 明文配置与 fnv1a(core)^fnv1a(appkey) 密钥流的 XOR 结果 (16 字节)")
    hdr.append("static const uint8_t ENC_CFG[16] = { %s };" % ", ".join("0x%02X" % b for b in enc))
    hdr.append("")
    hdr.append("} // namespace t3")
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(hdr) + "\n")

    print("[+] %s 生成完毕 (16 字节密文, v2 密钥化校验)" % args.out)
    print("    控制台 core = %r  security_tick = %d  draw_flags = 0x%08X" % (args.core, tick, flags))
    print("    spare = 0x%08X (随机生成; 复现加 --spare 0x%08X)" % (spare, spare))
    print("    提醒: T3 控制台该卡的'核心数据'字段必须填入相同 core, 否则程序将静默退出")

if __name__ == "__main__":
    main()
