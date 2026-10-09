#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_entangle.py -- 生成服务端密钥纠缠的加密配置头 (v2.5)

机制: T3 控制台给卡密设置"核心数据(core)"字段 -> 登录响应带回 ->
客户端用 fnv1a(core) ^ fnv1a(appkey) 派生密钥 -> LCG 密钥流 XOR 解密内嵌配置。
没有经过真实登录(被 patch 的门禁) => core 为空 => 密钥错 => 解出垃圾 => 延迟静默退出。

v2.5 变更:
  - LCG 参数 (A,C) 每次构建随机生成(Hull-Dobell: A≡1 mod 4, C 奇), 写入头文件。
    旧版固定常数对是 .text 里的静态指纹, 扫描即定位解码器; 现在每构建不同。
  - --blob <file>: 业务特征常量(偏移/参数, 任意二进制)与主配置共用同一条
    密钥流接续加密(偏移 16 之后)。运行时 entangled_features() 取解密结果。
    patch 门禁 => 垃圾偏移 => 功能静默失效(数据依赖, 难于控制流 patch)。

v2 变更 (审计 P0-2 修复):
  - 去掉固定明文校验常量(magic 0x5A17C0DE / tag "T3OK")——它们与密文同处一个
    二进制构成已知明文, 攻击者可直接 XOR 出 8 字节密钥流并用格攻击还原 LCG 状态。
  - 改为密钥化 CRC 校验: ecc = crc32_le32(tick ^ draw_flags ^ spare ^ key低32位),
    二进制内不存在任何"明文-密文"对。
  - spare 默认随机生成(每次构建不同), 进一步抬高猜测明文的成本。

用法: python gen_entangle.py --core SECRET [--appkey fa98...] [--tick 90]
                          [--blob features.bin] [--seed N] [--spare 0x...]
产出: entangled_cfg.h (含 ENC_CFG / ENC_LCG_A / ENC_LCG_C / ENC_FEATURES)
"""
import argparse, os, random, struct, zlib

def fnv1a64(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def keystream(key: int, a: int, c: int, n: int, skip: int = 0) -> bytes:
    """LCG 密钥流; skip 用于接续主配置之后的流(特征 blob 与主配置同一流)"""
    out = bytearray()
    x = key & 0xFFFFFFFFFFFFFFFF
    for i in range(skip + n):
        x = (x * a + c) & 0xFFFFFFFFFFFFFFFF
        if i >= skip:
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
    ap.add_argument("--blob", default=None,
                    help="业务特征常量文件(任意二进制), 与主配置同密钥流接续加密")
    ap.add_argument("--seed", type=int, default=None,
                    help="随机源种子(A/C/spare 全确定, 用于复现同一构建)")
    ap.add_argument("--out", default="entangled_cfg.h")
    args = ap.parse_args()

    rng = random.Random(args.seed)  # None => 真随机
    spare = args.spare if args.spare is not None else rng.getrandbits(32)
    tick = args.tick & 0xFFFFFFFF
    flags = args.flags & 0xFFFFFFFF
    spare &= 0xFFFFFFFF

    # v2.5: 按构建随机 LCG 参数 (Hull-Dobell 全周期条件: A≡1 mod 4, C 奇)
    lcg_a = (rng.getrandbits(62) << 2) | 1
    lcg_c = rng.getrandbits(64) | 1

    blob = b""
    if args.blob:
        blob = open(args.blob, "rb").read()
        if len(blob) > 65535:
            raise SystemExit("[!] blob 超过 65535 字节(ENC_FEATURES_LEN 为 uint16)")

    key = fnv1a64(args.core.encode()) ^ fnv1a64(args.appkey.encode())

    # 密钥化校验: 与 entangle_decode.cpp 的 crc32_ieee 完全一致
    ecc_input = struct.pack("<I", (tick ^ flags ^ spare ^ (key & 0xFFFFFFFF)) & 0xFFFFFFFF)
    ecc = zlib.crc32(ecc_input)

    real = struct.pack("<IIII", tick, flags, spare, ecc)
    full_plain = real + blob                      # 主配置 + 特征 blob 同一条流
    ks = keystream(key, lcg_a, lcg_c, len(full_plain))
    enc = bytes(r ^ k for r, k in zip(full_plain, ks))
    enc_cfg, enc_features = enc[:16], enc[16:]

    hdr = []
    hdr.append("// 自动生成: gen_entangle.py --core <T3控制台核心数据>  (勿提交真实 core 到公开场合)")
    hdr.append("// v2.5: 按构建随机LCG参数 + 特征blob同源加密 —— 必须与 entangle_decode.cpp 同版本")
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
    hdr.append("// v2.5: 本构建的 LCG 参数(Hull-Dobell: A≡1 mod 4, C 奇); 每次构建不同,")
    hdr.append("// 消除固定常数对的 .text 指纹")
    hdr.append("static const uint64_t ENC_LCG_A = 0x%016Xull;" % lcg_a)
    hdr.append("static const uint64_t ENC_LCG_C = 0x%016Xull;" % lcg_c)
    hdr.append("")
    hdr.append("// 明文配置与 fnv1a(core)^fnv1a(appkey) 密钥流的 XOR 结果 (16 字节)")
    hdr.append("static const uint8_t ENC_CFG[16] = { %s };" % ", ".join("0x%02X" % b for b in enc_cfg))
    hdr.append("")
    if blob:
        hdr.append("// 业务特征常量密文(与主配置同一条密钥流, 接续偏移16); 运行时")
        hdr.append("// 经 t3::entangled_features() 解密消费——错误密钥 => 垃圾偏移")
        hdr.append("static const uint16_t ENC_FEATURES_LEN = %d;" % len(blob))
        hdr.append("static const uint8_t ENC_FEATURES[%d] = { %s };" % (
            len(enc_features), ", ".join("0x%02X" % b for b in enc_features)))
    else:
        hdr.append("// 业务特征常量(--blob 生成时替换; 0 = 本构建未启用)")
        hdr.append("static const uint16_t ENC_FEATURES_LEN = 0;")
        hdr.append("static const uint8_t ENC_FEATURES[1] = { 0 };")
    hdr.append("")
    hdr.append("} // namespace t3")
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(hdr) + "\n")

    print("[+] %s 生成完毕 (16 字节配置%s, v2.5)" % (
        args.out, (" + %d 字节特征blob" % len(blob)) if blob else ""))
    print("    控制台 core = %r  security_tick = %d  draw_flags = 0x%08X" % (args.core, tick, flags))
    print("    spare = 0x%08X  LCG_A = 0x%016X  LCG_C = 0x%016X" % (spare, lcg_a, lcg_c))
    if args.seed is None and args.spare is None:
        print("    (随机生成; 完全复现加 --seed N)")
    print("    提醒: T3 控制台该卡的'核心数据'字段必须填入相同 core, 否则程序将静默退出")

if __name__ == "__main__":
    main()
