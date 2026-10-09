#pragma once
// entangle_decode.h -- 服务端密钥纠缠解码器接口(实现见 entangle_decode.cpp)
// v2: 密钥化CRC校验(二进制内无已知明文常量); 惩罚策略移至 t3_gate(策略层)
#include "entangled_cfg.h"
#include <cstdint>

namespace t3 {

// core + appkey -> 会话密钥(与 gen_entangle.py 一致)
uint64_t derive_session_key(const char* core, const char* appkey);

// 解码 ENC_CFG; 密钥化CRC校验通过返回 true
// 注意: v2 起二进制中不存在 magic/tag 明文常量, 校验值与 key 相关
bool entangle_decode(uint64_t key, EntangledCfg* out);

} // namespace t3
