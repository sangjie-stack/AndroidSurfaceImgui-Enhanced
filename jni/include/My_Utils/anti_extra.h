#pragma once
// 动态防逆向增强（L1.6 / L1.8 / L1.9）
// 说明：核心逻辑为环境特征检查与自比对，参考 GhostTrace / anti_Android 等开源思路，
//       不涉及加密/混淆核心逻辑（仍由 Obfuscate / Amice 负责）。
namespace anti_extra {

// L1.8: 禁止其他进程读取本进程内存（/proc/pid/mem）。
//       main() 最早调用；root 攻击者仍可绕过（门槛作用）。
void set_dumpable();

// L1.6: ELF 完整性自检。
//       内存中的可执行段 vs /proc/self/exe 磁盘原始字节，逐段比对。
//       返回 true=完整；false=代码被篡改（调用方应立即退出）。
bool integrity_check();

// L1.9: 反 Frida 多向量增强（maps 注入特征 + 线程名特征）。
//       返回 true=干净；false=发现 Frida 注入痕迹。
bool frida_extra_check();

} // namespace anti_extra
