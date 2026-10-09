// T3卡密验证门禁 —— ImGui覆盖层与T3验证SDK的对接层
// 流程与官方命令行示例一致(终端stdin输入卡密), 所有密钥/调用码经AY_OBFUSCATE编译期加密
#pragma once

namespace t3 {

// 阻塞式执行完整验证流程(版本检查/公告/自动登录/终端手动输入循环)
// 登录成功后启动60秒心跳线程(连续5次失败exit(1)), 然后返回true放行业务
// 初始化失败或版本过旧返回false, 调用方应直接退出
bool verify_and_run();

} // namespace t3
