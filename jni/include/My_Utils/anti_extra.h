#pragma once
// 动态防逆向增强（L1.6 / L1.8 / L1.9 / L1.13 / L1.14 / L1.15 / L1.16 / L1.17）
// 说明：核心逻辑为环境特征检查与自比对，参考 GhostTrace / anti_Android 等开源思路，
//       不涉及加密/混淆核心逻辑（仍由 Obfuscate / Amice 负责）。
#include <cstdint>

namespace anti_extra {

// 每项检测均可由环境变量独立控制（默认全开；仅影响本进程，不写全局状态）：
//   SEC_INJ=0/1         L1.13 行为型注入检测（可执行段白名单）
//   SEC_MEMFD=0/1       memfd:(deleted) 精确判注入
//   SEC_THREAD=0/1      L1.17 线程突变检测（线程数超基线+阈值 = 注入）
//   SEC_INTEGRITY=0/1   L1.6  ELF 完整性自检
//   SEC_TRACER=0/1      TracerPid 周期轮询（ptrace attach 检测补充）
//   SEC_SELFCHK=0/1     L1.16 检测规则数据自校验（防 patch 白名单绕过）
//   SEC_DELAY=min-max   延迟退出窗口秒（默认 20-90）
//   SEC_THRDBASE=N      线程基线（默认启动后首个周期自动设定）
//   SEC_THRDLIMIT=N     线程突变阈值（默认 3）
//   SEC_FAST_INTV=min-max 快周期（注入面轻检测）秒（默认 1-2）
//   SEC_SLOW_INTV=min-max 慢周期（完整性重检测）秒（默认 4-8）
//   SEC_SECCOMP=0/1       L1.24 seccomp-bpf 禁危险 syscall（默认开）
//   SEC_LIBC=0/1          L1.25 libc inline-hook 检测（默认开）
//   SEC_MEMWATCH=0/1      L1.26 inotify 反内存 dump（默认开）
//   SEC_UNICORN=0/1       L1.27 反 Unicorn 模拟器（默认开）
//   SEC_GUARD=0/1         L1.28 守护进程 ptrace 占位（默认开）
//   SEC_MAPWATCH=0/1      L1.29 maps 段数突变检测（默认开）
//   SEC_POISON=0/1        L1.30 命中投毒（默认开）
struct SecurityConfig {
    bool enable_injected   = true;
    bool enable_memfd      = true;
    bool enable_thread     = true;
    bool enable_integrity  = true;
    bool enable_tracerpid  = true;
    bool enable_selfcheck  = true;
    bool enable_seccomp    = true;
    bool enable_libc       = true;
    bool enable_memwatch   = true;
    bool enable_unicorn    = true;
    bool enable_guard      = true;
    bool enable_mapwatch   = true;
    bool enable_poison     = true;
    int  delay_min = 20;          // L1.14 延迟退出窗口下限(秒)
    int  delay_max = 90;          // L1.14 延迟退出窗口上限(秒)
    int  thread_baseline = -1;    // L1.17 线程基线（-1=未定，首个周期自动设定）
    int  thread_threshold = 3;    // L1.17 线程突变阈值（超基线+阈值=注入）
    int  fast_interval_min = 1;   // L1.15 快周期下限(秒)——注入面轻检测
    int  fast_interval_max = 2;   // L1.15 快周期上限(秒)
    int  slow_interval_min = 4;   // L1.15 慢周期下限(秒)——完整性重检测
    int  slow_interval_max = 8;   // L1.15 慢周期上限(秒)
};
// 进程级配置单例（main() 最早期 load_sec_cfg_from_env() 后只读）
SecurityConfig& sec_cfg();
// 从环境变量加载配置覆盖（未设置的项保持默认）
void load_sec_cfg_from_env();

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

// L1.17: 线程突变检测（实测：kxmwp memfd 注入 +6 线程，改线程名也躲不掉数量突变）。
//        首次调用自动设定基线；此后线程数 > 基线+阈值 → 注入。
//       返回 true=干净；false=线程数异常增长（注入）。
bool thread_spike_check();

// TracerPid 周期轮询：ptrace attach 时 TracerPid!=0。
//       返回 true=无调试器；false=被 ptrace attach。
bool tracerpid_check();

// L1.23: RELRO/GOT 段权限检测（防 PLT hook 企图——字节跳动 bhook 类）。
//        编译已带 -z,relro,-z,now（full RELRO，GOT 只读）；攻击者要 PLT hook
//        必须先 mprotect 解除 RELRO → 检测该段被降级为可写。
//       返回 true=RELRO 完整；false=RELRO 段意外可写（hook 企图）。
bool relro_check();

// L1.24: seccomp-bpf 禁危险 syscall（参考 Android zygote seccomp policy / MSeccomp）。
//        禁 memfd_create(319)/process_vm_readv(270)/process_vm_writev(271)/perf_event_open(241)：
//          memfd 是 frida agent 在本进程内建可执行映射的路径（禁→只能 fallback tmpfile+dlopen，
//          非白名单可执行段会被 injected_check 抓到=双保险）；
//          process_vm_* 防远程读写本进程内存；perf_event_open 防侧信道采样。
//        注意：不禁 ptrace（GhostTrace 需 PTRACE_TRACEME 自占位）。
//        main() 早期调用；失败/未开启时放行（保守）。
void apply_seccomp_filter();

// L1.25: libc inline-hook 检测（参考 TUGOhost/anti_Android——frida 核心是 hook 目标 libc）。
//        对比常用 libc 函数（open/read/fopen/ioctl/mmap/mprotect）内存 prologue 字节
//        与磁盘 /system/lib64/libc.so 对应偏移原始值——被 inline hook（trampoline 跳转）→ 判异常。
//       返回 true=libc 干净；false=检测到 libc 被 hook。
bool libc_hook_check();

// L1.26: inotify 反内存 dump（移植 TUGOhost/anti_Android anti_mem_dump.cpp）。
//        inotify 监控 /proc/self/mem + /proc/self/pagemap（含每线程）的 IN_ACCESS|IN_OPEN——
//        任何进程（含 KernelSU root）读本进程内存/pagemap → 检出（root 读 mem 也会触发事件）。
//        不监控 maps（自身检测会自读 maps，避免误报；且 maps 非直接内存 dump 面）。
//        main() 早期启动独立监控线程；命中 → arm_detected()（走延迟退出）。
void start_mem_watch_thread();

// L1.27: 反 Unicorn 模拟器（Unicorn/QEMU 系 CPU 模拟——攻击者摘代码段模拟执行）。
//        检测点（用户态 EL0 可读，真机永不误杀）：
//          ① CNTVCT_EL0 虚拟计数器两次读取相等 → 假时钟（真机硬件时钟必递增）；
//          ② faccessat2(439)/openat2(437) 返回 ENOSYS 且内核 >= 5.10 → Unicorn 无 syscall hook。
//       返回 true=非模拟；false=疑似 Unicorn 模拟环境。
bool unicorn_check();

// L1.31: 内核单步过慢检测（第五轮: 对冲 lsdriver/内核 stepbp 单步）。
//        内核单步执行被步进区域慢 >=100x(每条指令一次内核往返); 固定负载环
//        用 CNTVCT_EL0 计时, 与首调用基线比对, 30x 阈值 + 连续 3 次命中才判
//        (DVFS/温控波动 ~2-4x, 随机抢占靠连续计数排除)。首调用=记录基线。
//       返回 true=正常; false=疑似单步/强降速干预。
bool slowdown_check();

// L1.28: 守护进程 ptrace 占位（主动反调试）。
//        主进程 fork 守护进程，守护 PTRACE_ATTACH 主进程 → 攻击者任何 attach 都 EPERM。
//        守护死 → 主进程 TracerPid 异常（0 或第三方）→ 检测闭环自杀。
//        main() 最早调用（须在 startup_security_check 之前）。
void start_guard_process();
// 供 GhostTrace Method1/Method2 白名单：当前守护 pid（未启动返回 -1）。
extern "C" int gt_guard_pid(void);
// 守护状态：-1=attach 中（放行 TracerPid==0），1=存活，0=已死（检出），-2=未启用。
int guard_state();

// L1.29: maps 段数突变检测（防注入新映射段）。
//        历史 max 基线 + 连续 2 次超阈值才判（防瞬时/渐进 mmap 误杀）。
bool maps_spike_check();

// L1.30: 命中投毒（arm 后向诱饵区撒随机毒数据，反 dump）。
void poison_memory();

// L1.16: 检测规则数据自校验（白名单前缀表等关键常量哈希比对）。
//        首次调用记录基线哈希；此后重算比对，不一致 = 检测逻辑被 patch。
//       返回 true=规则数据完整；false=被篡改。
bool rules_selfcheck();

// L1.21: 检测线程心跳监控（防检测线程被 kill 后防线全失效——Promon watchdog 思路）。
// 检测线程每周期 heartbeat_ping()；主渲染循环每帧 heartbeat_expired()，
// 超时（SEC_HB_TIMEOUT 秒，默认 10）= 检测线程已死/被 kill → 主循环直接 _exit(42)。
void heartbeat_ping();
bool heartbeat_expired();

// L1.18: armed 后冻结检测函数（mprotect 只读 RX，参考 protect_memory_segments 思路）。
// 延迟退出窗口内检测函数不可写——防攻击者 inline-patch 掉"最终必退"逻辑。
void freeze_detectors();

// L1.14: 延迟退出机制（防"行为反推"：检测到异常不立即退出，
//        伪装正常继续运行，随机 20~90 秒后由调用方 _exit(42)）。
//        detect 命中后调用 arm_detected()（幂等，只武装一次）。
void arm_detected();
// 每帧调用；true=倒计时已到，应立即 _exit(42)。
bool should_exit();

} // namespace anti_extra
