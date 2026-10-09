// 自动生成: gen_entangle.py --core <T3控制台核心数据>  (勿提交真实 core 到公开场合)
// v2: 密钥化CRC校验(无已知明文常量) —— 必须与 entangle_decode.cpp 同版本
#pragma once
#include <cstdint>

namespace t3 {

struct EntangledCfg {
    uint32_t security_tick;// 安全复检周期(帧) -> 检测线程慢周期调制
    uint32_t draw_flags;   // 绘制标志 -> 检测随机源种子混合
    uint32_t spare;        // 二级 XOR 种子 -> 随机源种子混合
    uint32_t ecc;          // crc32(tick^flags^spare^key低32位)
};

// 明文配置与 fnv1a(core)^fnv1a(appkey) 密钥流的 XOR 结果 (16 字节)
static const uint8_t ENC_CFG[16] = { 0x2E, 0x0F, 0xA4, 0x14, 0xDA, 0x2F, 0x44, 0xF2, 0x5C, 0x4D, 0x65, 0x96, 0x2B, 0x31, 0x39, 0xC5 };

} // namespace t3
