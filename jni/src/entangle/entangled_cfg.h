// 自动生成: gen_entangle.py --core <T3控制台核心数据>  (勿提交真实 core 到公开场合)
// v2.5: 按构建随机LCG参数 + 特征blob同源加密 —— 必须与 entangle_decode.cpp 同版本
// 注意: 本文件当前密文由 v2 生成(固定经典 A/C); 下次跑 gen_entangle.py 重新生成
// 时 v2.5 会写入随机 A/C —— 旧密文与新参数不兼容, 必须整体重生成, 不可混搭。
#pragma once
#include <cstdint>

namespace t3 {

struct EntangledCfg {
    uint32_t security_tick;// 安全复检周期(帧) -> 检测线程慢周期调制
    uint32_t draw_flags;   // 绘制标志 -> 检测随机源种子混合
    uint32_t spare;        // 二级 XOR 种子 -> 随机源种子混合
    uint32_t ecc;          // crc32(tick^flags^spare^key低32位)
};

// v2.5: 本构建的 LCG 参数(Hull-Dobell: A≡1 mod 4, C 奇)。当前为经典值,
// 与现存密文的生成参数一致; v2.5 gen 重新生成时按构建随机化, 消除 .text 指纹
static const uint64_t ENC_LCG_A = 6364136223846793005ull;
static const uint64_t ENC_LCG_C = 1442695040888963407ull;

// 明文配置与 fnv1a(core)^fnv1a(appkey) 密钥流的 XOR 结果 (16 字节)
static const uint8_t ENC_CFG[16] = { 0x2E, 0x0F, 0xA4, 0x14, 0xDA, 0x2F, 0x44, 0xF2, 0x5C, 0x4D, 0x65, 0x96, 0x2B, 0x31, 0x39, 0xC5 };

// 业务特征常量(--blob 生成时替换; 0 = 本构建未启用)
static const uint16_t ENC_FEATURES_LEN = 0;
static const uint8_t ENC_FEATURES[1] = { 0 };

} // namespace t3
