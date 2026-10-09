// entangle_decode.cpp -- 服务端密钥纠缠: 纯解码器 (v2.5)
//
// 防线逻辑(与 crackme 攻防实测同型):
//   正确密钥 -> 解出合法配置(密钥化CRC对上) -> 业务消费 cfg/features
//   错误密钥(patch 门禁/无服务器/控制台未配 core) -> 垃圾 -> 调用方武装延迟退出
//
// v2.5: LCG 参数读 entangled_cfg.h(按构建随机, 消除固定常数对的 .text 指纹);
//       新增特征 blob 同源解密(与主配置同一条密钥流, 接续偏移16)。
// v2 (审计 P0-2 修复): 旧版 magic(0x5A17C0DE)/tag("T3OK") 是与密文同二进制的
// 已知明文——攻击者 XOR 出 8 字节密钥流即可格攻击还原 LCG 状态, 整条密钥派生
// 被旁路。现改为 crc32(tick^flags^spare^key低32位), 校验值依赖密钥, 二进制内
// 不存在任何"明文-密文"对。惩罚策略(延迟退出)移至 t3_gate.cpp——本文件只做
// 密码学, 不做策略。
#include "amice_annotate.h" //L2: amice 混淆注解
#include "entangle_decode.h"

#include <cstdint>
#include <cstring>

namespace t3 {

// VMP 注解: fnv1a64 是密钥派生根函数(core+appkey→session key), 循环内活跃值
// ~3 个, 符合 VMP 画像(同探针 f6 字符串循环)。加载 amice 插件时虚拟化为字节码;
// 未加载时注解被忽略, 零影响。
// 注意: entangle_decode 本体实测爆寄存器墙(O2 下 16 字节展开 >31 活跃值),
// 保持明指令, Flatten 由调用方(t3_gate)覆盖。
AMICE_VMP /*L2AMICE*/
static uint64_t fnv1a64(const char* s) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        h ^= *p;
        h *= 0x100000001b3ull;
    }
    return h;
}

// IEEE CRC-32 (poly 0xEDB88320 反射, init/xorout 0xFFFFFFFF) —— 与 python zlib.crc32 一致
// 逐位实现: 无查表(表本身也是可定位的静态指纹), 4 字节输入开销可忽略
// VMP 注解: 纯标量小循环(~4 活跃值), 符合 VMP 画像——校验函数虚拟化后,
// 攻击者改跳转绕过 CRC 比对的成本从 patch 分支升到改 VM 字节码
AMICE_VMP /*L2AMICE*/
static uint32_t crc32_ieee(const uint8_t* p, uint32_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return crc ^ 0xFFFFFFFFu;
}

// 由登录响应 core + APPKEY 派生会话密钥 (与 gen_entangle.py 完全一致)
AMICE_FLATTEN_H /*L2AMICE*/
uint64_t derive_session_key(const char* core, const char* appkey) {
    return fnv1a64(core ? core : "") ^ fnv1a64(appkey ? appkey : "");
}

// 解码 ENC_CFG 并做密钥化CRC校验 (与 gen_entangle.py 的 ecc 公式一致)
bool entangle_decode(uint64_t key, EntangledCfg* out) {
    uint64_t x = key;
    uint8_t dec[sizeof(ENC_CFG)];
    for (size_t i = 0; i < sizeof(ENC_CFG); i++) {
        x = x * ENC_LCG_A + ENC_LCG_C;
        dec[i] = ENC_CFG[i] ^ (uint8_t)(x >> 33);
    }
    __builtin_memcpy(out, dec, sizeof(dec));
    // 密钥化校验: ecc = crc32_le32(tick ^ draw_flags ^ spare ^ key低32位)
    uint32_t v = out->security_tick ^ out->draw_flags ^ out->spare ^ (uint32_t)key;
    uint8_t ecc_in[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    return crc32_ieee(ecc_in, 4) == out->ecc;
}

// v2.5: 业务特征常量解密——与主配置同一条密钥流(跳过前16字节配置段)。
// key 必须是实际解开 ENC_CFG 的候选; 错误密钥 => 垃圾偏移(数据依赖型反patch)
AMICE_FLATTEN_H /*L2AMICE*/
bool entangle_decode_features(uint64_t key, uint8_t* out, uint32_t cap) {
    if (ENC_FEATURES_LEN == 0 || cap < ENC_FEATURES_LEN) return false;
    uint64_t x = key;
    for (uint32_t i = 0; i < 16 + ENC_FEATURES_LEN; i++) {
        x = x * ENC_LCG_A + ENC_LCG_C;
        if (i >= 16)
            out[i - 16] = ENC_FEATURES[i - 16] ^ (uint8_t)(x >> 33);
    }
    return true;
}

} // namespace t3
