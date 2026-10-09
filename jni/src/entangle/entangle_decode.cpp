// entangle_decode.cpp -- 服务端密钥纠缠: 解码器 + 失败时的静默处置
//
// 防线逻辑(与 crackme 攻防实测同型):
//   正确密钥 -> 解出合法配置(magic/tag 对上) -> 业务用 cfg
//   错误密钥(patch 门禁/无服务器/控制台未配 core) -> 垃圾 -> 延迟随机秒数后 _exit
//   (延迟+静默: 不给攻击者"改这里就过了"的即时反馈)
#include "entangled_cfg.h"
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

namespace t3 {

static uint64_t fnv1a64(const char* s) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        h ^= *p;
        h *= 0x100000001b3ull;
    }
    return h;
}

// 由登录响应 core + APPKEY 派生会话密钥 (与 gen_entangle.py 完全一致)
uint64_t derive_session_key(const char* core, const char* appkey) {
    return fnv1a64(core ? core : "") ^ fnv1a64(appkey ? appkey : "");
}

bool entangle_decode(uint64_t key, EntangledCfg* out) {
    uint64_t x = key;
    uint8_t dec[20];
    for (int i = 0; i < 20; i++) {
        x = x * 6364136223846793005ull + 1442695040888963407ull;
        dec[i] = ENC_CFG[i] ^ (uint8_t)(x >> 33);
    }
    __builtin_memcpy(out, dec, 20);
    return out->magic == 0x5A17C0DEu && out->tag[0]=='T' && out->tag[1]=='3'
        && out->tag[2]=='O' && out->tag[3]=='K';
}

// 解码失败: 延迟随机 3~9 秒后静默退出 (不给即时反馈, 退出码 0 伪装正常退出)
void entangle_punish() {
    uintptr_t addr = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    srand((unsigned)(addr & 0xFFFFFFFFu));
    usleep((3000000u + ((unsigned)rand() % 6000000u)));
    _exit(0);
}

} // namespace t3
