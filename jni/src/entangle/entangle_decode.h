#pragma once
// entangle_decode.h -- 服务端密钥纠缠解码器接口(实现见 entangle_decode.cpp)
#include "entangled_cfg.h"
#include <cstdint>

namespace t3 {

// core + appkey -> 会话密钥(与 gen_entangle.py 一致)
uint64_t derive_session_key(const char* core, const char* appkey);

// 解码 ENC_CFG; magic/tag 校验通过返回 true
bool entangle_decode(uint64_t key, EntangledCfg* out);

// 解码失败的处置: 延迟随机 3~9 秒后 _exit(0) (静默, 不给即时反馈)
void entangle_punish();

} // namespace t3
