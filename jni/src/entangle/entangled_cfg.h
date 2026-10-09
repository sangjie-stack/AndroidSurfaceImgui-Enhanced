// 自动生成: gen_entangle.py --core <T3控制台核心数据>  (勿提交真实 core 到公开场合)
#pragma once
#include <cstdint>

namespace t3 {

struct EntangledCfg {
    uint32_t magic;        // 0x5A17C0DE
    uint32_t security_tick;// 安全复检周期(帧)
    uint32_t draw_flags;   // 绘制标志
    uint32_t spare;
    char     tag[4];       // "T3OK"
};

// 明文配置与 fnv1a(core)^fnv1a(appkey) 密钥流的 XOR 结果
static const uint8_t ENC_CFG[20] = { 0xAA, 0xCF, 0xB3, 0x4E, 0x43, 0x2F, 0x44, 0xF2, 0x57, 0x46, 0x3D, 0x4E, 0xAC, 0xAD, 0xD8, 0x6D, 0x76, 0x20, 0xE1, 0xFD };

} // namespace t3
