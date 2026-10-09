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
// verify_and_run() 成功后可用: 由登录响应 core + APPKEY 派生的会话密钥。
// 门禁被 patch 跳过时(未发生真实登录)返回 false —— 调用方应静默退出。
bool session_key(uint64_t* out);

// 解码内嵌加密配置(EntangledCfg 见 entangled_cfg.h); 失败即延迟静默退出
bool entangle_or_die();

// 解码后的安全复检周期(帧) — 仅在 entangle_or_die() 成功后有效
uint32_t entangled_security_tick();

} // namespace t3
