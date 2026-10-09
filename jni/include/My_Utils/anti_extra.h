#pragma once
// 动态防逆向增强（L1.6 / L1.8 / L1.9 / L1.13 / L1.14 / L1.15）
// 说明：核心逻辑为环境特征检查与自比对，参考 GhostTrace / anti_Android 等开源思路，
//       不涉及加密/混淆核心逻辑（仍由 Obfuscate / Amice 负责）。
#include <cstdint>

namespace anti_extra {

// L1.8: 禁止其他进程读取本进程内存（/proc/pid/mem）。
//       main() 最早调用；root 攻击者仍可绕过（门槛作用）。
void set_dumpable();

// L1.6: ELF 完整性自检。
//       内存中的可执行段 vs /proc/self/exe 磁盘原始字节，逐段比对。
//       返回 true=完整；false=代码被篡改（调用方决定立即退或延迟退）。
bool integrity_check();

// L1.9: 反 Frida 多向量增强（maps 注入特征 + 线程名特征）。
//       返回 true=干净；false=发现 Frida 注入痕迹。
bool frida_extra_check();

// L1.13: 行为型注入检测（不依赖特征串，针对魔改版 Frida）。
//         可执行段必须属于：自身 / [vdso] / 系统白名单前缀；
//         匿名可执行段（memfd/裸 mmap 注入的 agent.so 特征）或
//         非白名单路径可执行段 → 判定注入。
//       返回 true=干净；false=发现未知可执行映射（注入）。
bool injected_check();

// L1.14: 延迟退出机制（防"行为反推"：检测到异常不立即退出，
//        伪装正常继续运行，随机 20~90 秒后由调用方 _exit(42)）。
//        detect 命中后调用 arm_detected()（幂等，只武装一次）。
void arm_detected();
// 每帧调用；true=倒计时已到，应立即 _exit(42)。
bool should_exit();

} // namespace anti_extra
