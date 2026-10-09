// T3卡密验证门禁 —— ImGui覆盖层与T3验证SDK的对接层
// 流程与官方命令行示例一致(终端stdin输入卡密), 所有密钥/调用码经AY_OBFUSCATE编译期加密
#pragma once

#include <cstdint>

namespace t3 {

// 阻塞式执行完整验证流程(版本检查/公告/自动登录/终端手动输入循环)
// 登录成功后启动60秒心跳线程(连续5次失败exit(1)), 然后返回true放行业务
// 初始化失败或版本过旧返回false, 调用方应直接退出
bool verify_and_run();

// —— 服务端密钥纠缠(anti patch-bypass) ——
// verify_and_run() 成功后可用: 实际解开 ENC_CFG 的那个会话密钥(主候选或
// hex 解码候选)。仅真实登录才拿得到 core; 门禁被 patch 时返回 false。
bool session_key(uint64_t* out);

// 解码内嵌加密配置(v2 密钥化CRC校验, 见 entangled_cfg.h)。
// 失败时不再返回 false: 武装 anti_extra 延迟退出(20~90s 随机)并返回 true
// 伪装通过——垃圾配置流入下方消费接口, 检测行为悄悄劣化后静默退出。
bool entangle_or_die();

// —— 解码配置的消费者接口(审计 P0-1) ——
// security_tick: 检测线程慢周期调制(帧); draw_flags/spare: 检测随机源种子混合。
// 仅在 entangle_or_die() 真正解码成功后返回非零真值。
uint32_t entangled_security_tick();
uint32_t entangled_flags();
uint32_t entangled_spare();

} // namespace t3
