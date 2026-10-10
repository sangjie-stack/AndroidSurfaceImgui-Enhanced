// anti_extra.cpp
// 动态防逆向增强实现（L1.6 完整性自检 / L1.8 dumpable / L1.9 反Frida多向量）
#include "amice_annotate.h"   //L2: amice 混淆注解
#include "anti_extra.h"
#include "obfuscate.h" // 检测特征串加密，避免静态暴露检测点

#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#ifdef __aarch64__
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#endif

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>

namespace anti_extra {

// ---------- 配置：环境变量开关（默认全开，可单关/调参） ----------
namespace {
SecurityConfig g_cfg;
std::atomic<bool> g_cfg_loaded{false};

// steady_ms 定义在文件后部（匿名 namespace），此处前置声明供 thread_spike_check 使用
static uint64_t steady_ms();
// 审查修复（B12 fail-open）：syscall_read_proc 连续失败计数——攻击者 fd 耗尽 /
// hook syscall 伪造失败时, 3 次即视为防线被破坏 → arm_detected（延迟退出）。
// 成功读取一次即清零（偶发瞬时失败不误杀）。
static std::atomic<int> g_proc_read_fail{0};

static int env_int(const char* name, int def) {
    const char* v = ::getenv(name);
    if (!v || !*v) return def;
    return atoi(v);
}
static bool env_bool(const char* name, bool def) {
    const char* v = ::getenv(name);
    if (!v || !*v) return def;
    return atoi(v) != 0;
}
static bool parse_range(const char* v, int& lo, int& hi) {
    if (!v || !*v) return false;
    const char* dash = strchr(v, '-');
    if (!dash) return false;
    int a = atoi(v), b = atoi(dash + 1);
    if (a <= 0 || b < a) return false;
    lo = a; hi = b; return true;
}
} // namespace

// arm_detected 定义在文件后部（外部链接，anti_extra.h 声明），前置声明供前部检测函数调用
void arm_detected();

SecurityConfig& sec_cfg() { return g_cfg; }

void load_sec_cfg_from_env() {
    if (g_cfg_loaded.load(std::memory_order_relaxed)) return;
#ifndef SEC_ALLOW_ENV_CFG
    // 审计修复(2026-10-09): getenv 由进程启动者控制——SEC_*=0 曾可静默全部检测。
    // 生产构建一律忽略环境变量, 全部检测保持 SecurityConfig 默认开启;
    // 调试构建加 -DSEC_ALLOW_ENV_CFG=1 恢复运行时调参。
    g_cfg_loaded.store(true, std::memory_order_relaxed);
    return;
#else
    g_cfg.enable_injected   = env_bool("SEC_INJ", true);
    g_cfg.enable_memfd      = env_bool("SEC_MEMFD", true);
    g_cfg.enable_thread     = env_bool("SEC_THREAD", true);
    g_cfg.enable_integrity  = env_bool("SEC_INTEGRITY", true);
    g_cfg.enable_tracerpid  = env_bool("SEC_TRACER", true);
    g_cfg.enable_selfcheck  = env_bool("SEC_SELFCHK", true);
    g_cfg.enable_seccomp    = env_bool("SEC_SECCOMP", true);
    g_cfg.enable_libc       = env_bool("SEC_LIBC", true);
    g_cfg.enable_memwatch   = env_bool("SEC_MEMWATCH", true);
    g_cfg.enable_unicorn    = env_bool("SEC_UNICORN", true);
    g_cfg.enable_guard      = env_bool("SEC_GUARD", true);
    g_cfg.enable_mapwatch   = env_bool("SEC_MAPWATCH", true);
    g_cfg.enable_poison     = env_bool("SEC_POISON", true);
    g_cfg.enable_dbus       = env_bool("SEC_DBUS", true);        // E3
    g_cfg.enable_sigtrap    = env_bool("SEC_SIGTRAP", true);     // E2
    g_cfg.enable_pagemap    = env_bool("SEC_PAGEMAP", true);     // E1
    g_cfg.enable_smaps      = env_bool("SEC_SMAPS", true);       // F1
    g_cfg.enable_tramp      = env_bool("SEC_TRAMP", true);       // F2
    g_cfg.enable_got        = env_bool("SEC_GOT", true);         // F3
    g_cfg.enable_libctxt    = env_bool("SEC_LIBCTXT", true);     // G1
    int lo = g_cfg.delay_min, hi = g_cfg.delay_max;
    if (parse_range(::getenv("SEC_DELAY"), lo, hi)) { g_cfg.delay_min = lo; g_cfg.delay_max = hi; }
    int base = env_int("SEC_THRDBASE", -1);
    if (base >= 0) g_cfg.thread_baseline = base;
    g_cfg.thread_threshold = env_int("SEC_THRDLIMIT", 3);
    lo = g_cfg.fast_interval_min; hi = g_cfg.fast_interval_max;
    if (parse_range(::getenv("SEC_FAST_INTV"), lo, hi)) { g_cfg.fast_interval_min = lo; g_cfg.fast_interval_max = hi; }
    lo = g_cfg.slow_interval_min; hi = g_cfg.slow_interval_max;
    if (parse_range(::getenv("SEC_SLOW_INTV"), lo, hi)) { g_cfg.slow_interval_min = lo; g_cfg.slow_interval_max = hi; }
    g_cfg_loaded.store(true, std::memory_order_relaxed);
#endif
}

// ---------- L1.8: 禁止内存 dump（非 root 进程读 /proc/pid/mem 失效） ----------
void set_dumpable() {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

// ---------- 工具：大小写不敏感子串查找 ----------
static bool str_contains_ci(const std::string& hay, const char* needle) {
    size_t nlen = strlen(needle);
    if (hay.size() < nlen) return false;
    for (size_t i = 0; i + nlen <= hay.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < nlen; ++j) {
            char a = hay[i + j];
            if (a >= 'A' && a <= 'Z') a += 32;
            char b = needle[j];
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

// ---------- L1.22: syscall 直读 /proc 文件（防 libc hook 伪造输出） ----------
// 魔改版 frida 可 hook libc 的 fopen/fgets 伪造 maps/status 内容（注入检测读到假数据放行）。
// 参考 TUGOhost/anti_Android 的 syscall 用法：直接发 openat/read 系统调用，绕过 libc wrapper。
static bool syscall_read_proc(const char* path, std::string& out) {
    out.clear();
    long fd = ::syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[4096];
    for (;;) {
        long r = ::syscall(SYS_read, fd, buf, sizeof(buf));
        if (r < 0) { ::syscall(SYS_close, fd); return false; }
        if (r == 0) break;
        out.append(buf, static_cast<size_t>(r));
    }
    ::syscall(SYS_close, fd);
    return true;
}

// ---------- L1.6: ELF 完整性自检 ----------
struct TextSeg {
    uintptr_t start;
    size_t size;
    uint64_t file_off;
};

// 解析 /proc/self/maps，收集"自身可执行文件"的可执行映射段
static bool collect_text_segs(const std::string& self_path, std::vector<TextSeg>& segs) {
    // basename 兜底匹配：容忍 maps 中 pathname 与 readlink 结果的微小差异
    std::string self_base;
    size_t slash = self_path.rfind('/');
    if (slash != std::string::npos) self_base = self_path.substr(slash + 1);
    else self_base = self_path;

    std::string data;
    if (!syscall_read_proc("/proc/self/maps", data)) return false;
    std::istringstream maps(data);
    std::string line;
    while (std::getline(maps, line)) {
        // 格式: start-end perms offset dev inode pathname
        size_t p0 = line.find('-');
        if (p0 == std::string::npos) continue;
        size_t p1 = line.find(' ', p0);
        if (p1 == std::string::npos) continue;
        uintptr_t start = strtoull(line.substr(0, p0).c_str(), nullptr, 16);
        uintptr_t end   = strtoull(line.substr(p0 + 1, p1 - p0 - 1).c_str(), nullptr, 16);

        size_t p2 = line.find(' ', p1 + 1);
        if (p2 == std::string::npos) continue;
        std::string perms = line.substr(p1 + 1, p2 - p1 - 1);
        if (perms.find('x') == std::string::npos) continue; // 只要可执行段

        size_t p3 = line.find(' ', p2 + 1);
        if (p3 == std::string::npos) continue;
        uint64_t off = strtoull(line.substr(p2 + 1, p3 - p2 - 1).c_str(), nullptr, 16);

        // dev inode 之后才是 pathname
        size_t p4 = line.find(' ', p3 + 1);
        size_t p5 = line.find(' ', p4 + 1);
        if (p5 == std::string::npos) continue;
        std::string path;
        if (p5 + 1 < line.size()) path = line.substr(p5 + 1);
        // maps 行 inode 与 pathname 之间存在对齐空格 → 跳过前导空白
        size_t pb = path.find_first_not_of(" \t");
        if (pb == std::string::npos) continue;
        path = path.substr(pb);
        if (path.empty()) continue;             // 匿名映射跳过

        // 匹配自身：完整路径 或 basename 均算命中（防 readlink/maps 格式微小差异导致漏检）
        bool match = (path == self_path);
        if (!match && !self_base.empty()) {
            size_t lp = path.rfind('/');
            std::string path_base = (lp == std::string::npos) ? path : path.substr(lp + 1);
            if (path_base == self_base) match = true;
        }
        if (!match) continue;

        segs.push_back({start, static_cast<size_t>(end - start), off});
    }
    return !segs.empty();
}

AMICE_FLATTEN_H /*L2AMICE*/
bool integrity_check() {
    // 自身路径
    char selfpath[512];
    ssize_t n = readlink("/proc/self/exe", selfpath, sizeof(selfpath) - 1);
    if (n <= 0) return true; // 读不到就放行，不误杀
    selfpath[n] = '\0';
    std::string self(selfpath);

    std::vector<TextSeg> segs;
    if (!collect_text_segs(self, segs)) return true; // 解析不到也放行（保守，防误杀）

    // 用系统调用循环读磁盘，确保完整读取（ifstream 缓冲在 -O3/大段下可能短读导致误放行）
    int fd = ::open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return true; // 打不开也放行（保守）

    bool ok = true;
    for (const auto& seg : segs) {
        // 段大小异常（>64MB 不可能出现在自身 ELF）视为异常 → 判定篡改
        if (seg.size == 0 || seg.size > (64u << 20)) { ok = false; break; }

        if (::lseek(fd, static_cast<off_t>(seg.file_off), SEEK_SET) < 0) { ok = false; break; }

        std::vector<char> buf(seg.size);
        size_t got = 0;
        while (got < seg.size) {
            ssize_t r = ::read(fd, buf.data() + got, seg.size - got);
            if (r <= 0) { ok = false; break; } // 读不完整 = 磁盘异常（文件被改/替换）→ 判定篡改
            got += static_cast<size_t>(r);
        }
        if (!ok) break;

        if (memcmp(reinterpret_cast<const void*>(seg.start), buf.data(), seg.size) != 0) {
            ok = false; // 内存被篡改！
            break;
        }
    }
    ::close(fd);
    return ok;
}

// ---------- L1.9: 反 Frida 多向量 ----------
// 特征串全部用 Obfuscate 编译期加密 + 即用即毁（不暴露检测点）

static bool scan_maps_frida() {
    std::string data;
    if (!syscall_read_proc("/proc/self/maps", data)) return false;
    std::istringstream maps(data);
    std::string line;
    while (std::getline(maps, line)) {
        {
            auto& o = AY_OBFUSCATE("frida");
            ay::scoped_plaintext sp(o);
            if (str_contains_ci(line, (const char*)sp)) return true;
        }
        {
            auto& o = AY_OBFUSCATE("gadget");
            ay::scoped_plaintext sp(o);
            if (str_contains_ci(line, (const char*)sp)) return true;
        }
        {
            auto& o = AY_OBFUSCATE("libgum");
            ay::scoped_plaintext sp(o);
            if (str_contains_ci(line, (const char*)sp)) return true;
        }
        {
            auto& o = AY_OBFUSCATE("linjector");
            ay::scoped_plaintext sp(o);
            if (str_contains_ci(line, (const char*)sp)) return true;
        }
    }
    return false;
}

static bool scan_threads_frida() {
    DIR* d = opendir("/proc/self/task");
    if (!d) return false;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        std::string comm_path = std::string("/proc/self/task/") + e->d_name + "/comm";
        std::string cdata;
        if (syscall_read_proc(comm_path.c_str(), cdata)) {
            // comm 只有一行（可能有尾随换行），取首行
            size_t nl = cdata.find('\n');
            std::string name = (nl == std::string::npos) ? cdata : cdata.substr(0, nl);
            {
                auto& o = AY_OBFUSCATE("gum-js-loop");
                ay::scoped_plaintext sp(o);
                if (str_contains_ci(name, (const char*)sp)) { closedir(d); return true; }
            }
            {
                auto& o = AY_OBFUSCATE("pool-frida");
                ay::scoped_plaintext sp(o);
                if (str_contains_ci(name, (const char*)sp)) { closedir(d); return true; }
            }
            {
                auto& o = AY_OBFUSCATE("frida");
                ay::scoped_plaintext sp(o);
                if (str_contains_ci(name, (const char*)sp)) { closedir(d); return true; }
            }
        }
    }
    closedir(d);
    return false;
}

AMICE_FLATTEN_H /*L2AMICE*/
// ---------- A: IDA android_server 检测（23946 端口 + 服务器文件） ----------
// IDA 动态调试 native 必须先推送 android_server 到 /data/local/tmp 并监听 23946。
// 23946 = 0x5D8A（/proc/net/tcp 本地端口为小端十六进制）。root 下可改名/换端口规避——
// 此处是低成本兜底面（进程名检测另有 GT 侧，见 ghosttrace_android.c）。
static bool scan_ida_server() {
    std::string data;
    if (!syscall_read_proc("/proc/net/tcp", data)) return false; // 读失败放行（保守）
    if (data.find(":5D8A ") != std::string::npos) return true;    // 23946 LISTEN
    // 服务器二进制（常见名 android_server / android_server64）——文件存在即视为调试环境
    if (::syscall(SYS_faccessat, AT_FDCWD, "/data/local/tmp/android_server", F_OK) == 0) return true;
    if (::syscall(SYS_faccessat, AT_FDCWD, "/data/local/tmp/android_server64", F_OK) == 0) return true;
    return false;
}

bool frida_extra_check() {
    if (scan_maps_frida()) return false;
    if (scan_threads_frida()) return false;
    if (scan_ida_server()) return false;   // A: IDA 调试服务器
    if (!trampoline_scan_check()) return false;  // F2: ARM64 trampoline 模式
    if (!got_hook_check()) return false;         // F3: GOT/PLT 劫持
    return true;
}

// ---------- L1.13: 行为型注入检测（不依赖特征串，针对魔改版 Frida） ----------
// 实测基线（真机 KernelSU root, Vulkan + ImGui 全栈）：
//   可执行段 = 自身 imguiobf.sh + [vdso] + /system /vendor /apex /data/app 系统库
//   正常环境不存在"匿名可执行段"（唯一匿名可执行段是 [vdso]）。
// 检测规则：可执行段必须 ∈ {自身路径, [vdso]} ∪ 系统白名单前缀；
//           匿名可执行段（memfd / 裸 mmap 注入 agent.so 的特征）或
//           非白名单路径可执行段（如 /data/local/tmp/xxx.so、/data/data/...）
//           → 判定注入。
// 说明：内核级隐藏 maps 的魔改工具超出用户态能力范围（文档诚实声明）。

static const char* kSystemWhitePrefixes[] = {
    "/system/", "/vendor/", "/apex/", "/odm/", "/product/",
    "/system_ext/", "/data/app/", "/data/user_de/",
    "/linkerconfig/",
};

static bool starts_with(const std::string& s, const char* prefix) {
    size_t n = strlen(prefix);
    return s.size() >= n && memcmp(s.data(), prefix, n) == 0;
}

AMICE_FLATTEN_H /*L2AMICE*/
bool injected_check() {
    char selfpath[512];
    ssize_t n = readlink("/proc/self/exe", selfpath, sizeof(selfpath) - 1);
    if (n <= 0) return true; // 读不到自身路径就放行（保守）
    selfpath[n] = '\0';
    std::string self(selfpath);

    std::string data;
    if (!syscall_read_proc("/proc/self/maps", data)) { // 审查修复（B12）：连续失败=防线被破坏
        if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
        return true;
    }
    g_proc_read_fail.store(0);
    std::istringstream maps(data);
    std::string line;
    while (std::getline(maps, line)) {
        // 格式: start-end perms offset dev inode pathname
        size_t p0 = line.find('-');
        if (p0 == std::string::npos) continue;
        size_t p1 = line.find(' ', p0);
        if (p1 == std::string::npos) continue;

        size_t p2 = line.find(' ', p1 + 1);
        if (p2 == std::string::npos) continue;
        std::string perms = line.substr(p1 + 1, p2 - p1 - 1);
        if (perms.find('x') == std::string::npos) continue; // 只看可执行段

        // inode 之后的 pathname（第 6 列起）
        size_t p3 = line.find(' ', p2 + 1);
        if (p3 == std::string::npos) continue;
        size_t p4 = line.find(' ', p3 + 1);
        if (p4 == std::string::npos) continue;
        size_t p5 = line.find(' ', p4 + 1);
        if (p5 == std::string::npos) continue;
        std::string path;
        if (p5 + 1 < line.size()) path = line.substr(p5 + 1);
        // maps 行 inode 与 pathname 之间存在对齐空格 → 跳过前导空白
        size_t pb = path.find_first_not_of(" \t");
        // 审查修复（B3）：path 为空（真匿名可执行映射）时 find_first_not_of 返回 npos，
        // 原代码 continue 吞掉了——裸 mmap(PROT_EXEC) 注入永远不被判。正常环境唯一匿名
        // 可执行段是 [vdso]（下方白名单），其余空 path 直接判注入。
        if (pb == std::string::npos) return false;
        path = path.substr(pb);

        if (path.empty()) return false; // 真匿名可执行段 = 注入（正常环境不存在）

        // L1.13 增强：memfd 匿名文件注入（实测 kxmwp：/memfd:kxmwp-agent-64.so (deleted)）
        if (g_cfg.enable_memfd) {
            if (starts_with(path, "/memfd:") ||
                path.find("(deleted)") != std::string::npos)
                return false; // memfd/已删除文件的可执行段 = 注入
        }

        if (path == "[vdso]") continue;              // 唯一合法匿名可执行映射
        if (path == self) continue;                  // 自身主段/分页
        {
            // 白名单长度用 sizeof 推导（防增删前缀后遍历越界/漏判）
            constexpr size_t kWP = sizeof(kSystemWhitePrefixes) / sizeof(kSystemWhitePrefixes[0]);
            bool sys = false;
            for (size_t i = 0; i < kWP; ++i) {
                if (starts_with(path, kSystemWhitePrefixes[i])) { sys = true; break; }
            }
            if (sys) continue;
        }

        return false; // 非白名单路径可执行段 = 注入（如 /data/local/tmp 下的 agent.so）
    }
    return true;
}

// ---------- L1.17: 线程突变检测 ----------
// 实测（kxmwp memfd 注入）：注入后线程 8→14（+6），线程名可伪装但数量躲不掉。
// 首次调用自动记录基线（启动稳定后首个周期）；此后 线程数 > 基线+阈值 → 注入。
AMICE_FLATTEN_H /*L2AMICE*/
bool thread_spike_check() {
    if (!g_cfg.enable_thread) return true;
    DIR* d = opendir("/proc/self/task");
    if (!d) return true; // 读不到就放行（保守）
    int count = 0;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        ++count;
    }
    closedir(d);
    // 审查修复（B9 v2）：前 60s 为稳定窗口——只跟踪建立真实基线，不判。
    // 实测：启动 3s 内线程从 1 一次性跳到 10+（T3 心跳 + security_thread + mem_watch +
    // Vulkan 初始化快速建线程）→ 渐进基线来不及爬升 → 连续 2 周期超阈值 → 误杀。
    // 60s 后：基线=稳态 max（11~12），线程渐变为零；注入突增（+6~8）→ 连续 2 次超阈值 → 命中。
    static uint64_t t_start_ms = 0;
    if (t_start_ms == 0) t_start_ms = steady_ms();
    static int hist_max = 0;
    static int spike_hits = 0;
    if (steady_ms() - t_start_ms < 60000) {
        if (count > hist_max) hist_max = count; // 只跟踪
        return true;
    }
    if (hist_max > 0 && count > hist_max + g_cfg.thread_threshold) {
        if (++spike_hits >= 2) return false; // 连续 2 次超阈值 = 线程突增（注入）
    } else {
        spike_hits = 0;
        if (count > hist_max) hist_max = count; // 渐进扩展：刷新历史 max
    }
    return true;
}

// ---------- L1.28: 守护进程 ptrace 占位（主动反调试） ----------
// 参考开源 anti-debug 双进程方案：主进程 fork 守护进程，守护 PTRACE_ATTACH 主进程，
// 抢占 ptrace 槽位 → 攻击者（含 root）attach 一律 EPERM（already traced）。
// 闭环：守护死（被 kill / 主进程死）→ pipe EOF → guard_state()==0；
//       或主进程 TracerPid 变成 0/第三方 → tracerpid_check / GhostTrace Method2 检出。
// 说明：主进程 TracerPid 常态 = 守护 pid（非 0），相关检测须白名单（见 tracerpid_check、
//       ghosttrace_detection.c Method2）。
namespace {
volatile pid_t g_guard_pid = -1;
int g_guard_pipe[2] = {-1, -1};
volatile int g_guard_state = -2; // -2 未启用 / -1 attach 中 / 1 存活 / 0 已死
} // namespace

extern "C" int gt_guard_pid(void) { return static_cast<int>(g_guard_pid); }

int guard_state() {
    if (!g_cfg.enable_guard || g_guard_pid < 0) return -2;
    return g_guard_state;
}

// 主进程侧循环尝试收 attach 完成信号 / EOF（每轮检测调用，非阻塞）
static void guard_poll() {
    if (g_guard_state >= 0) return; // 已定论
    if (g_guard_pipe[0] < 0) { g_guard_state = -2; return; }
    char c = 0;
    ssize_t r = ::read(g_guard_pipe[0], &c, 1);
    if (r == 1 && c == 1) { g_guard_state = 1; return; } // attach 完成，守护存活
    if (r == 0) { g_guard_state = 0; return; }           // EOF = 守护退出（attach 前死/被杀）
    // EAGAIN = 守护还没 attach 完（宽限，保持 -1）
}

void start_guard_process() {
    if (!g_cfg.enable_guard) return;
    if (pipe(g_guard_pipe) != 0) { g_guard_state = -2; return; }
    pid_t main_pid = getpid();
    pid_t pid = fork();
    if (pid < 0) {
        close(g_guard_pipe[0]); close(g_guard_pipe[1]);
        g_guard_state = -2; return;
    }
    if (pid == 0) {
        // ---- 守护进程（子）----
        close(g_guard_pipe[0]);
        // 审查修复（N1/N6）：主进程被 kill → 守护自杀（PDEATHSIG）
        ::prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(50000); // 等主进程 fork 返回并继续运行
        if (kill(main_pid, 0) == -1) _exit(0); // 主进程已死 → 退出
        // PTRACE_SEIZE：不注入 SIGSTOP（无 stop/CONT 竞态——实测 ATTACH 与主进程 fork/ptrace
        // 操作交叉会概率性卡 tracing stop / 误杀）；seize 后 TracerPid=守护，占位生效。
        // PTRACE_O_EXITKILL：主进程死 → 守护被 SIGKILL（自动清理，无僵尸残留）。
        if (ptrace(PTRACE_SEIZE, main_pid, 0, PTRACE_O_EXITKILL) == -1) _exit(0);
        char ok = 1;
        ssize_t w = ::write(g_guard_pipe[1], &ok, 1); (void)w;
        close(g_guard_pipe[1]);
        // 事件循环替代 kill+usleep 轮询（审查修复 N1）：
        //   - 被 trace 进程的每个信号都先产生 signal-delivery-stop，tracer 不 continue
        //     信号就不会投递（kill -TERM 会永远卡住）→ 必须 waitpid + 转发；
        //   - 主进程 fork 的子进程（继承 trace）也归本循环放行/收尸；
        //   - 主进程 exit 事件同样在此收割。
        for (;;) {
            int st = 0;
            pid_t r = waitpid(-1, &st, __WALL);
            if (r < 0) {
                if (errno == EINTR) continue;
                _exit(0); // ECHILD 等：没有可 wait 的进程 → 主进程已死
            }
            if (r == main_pid && (WIFEXITED(st) || WIFSIGNALED(st)))
                _exit(0); // 主进程退出 → 守护退出
            if (WIFSTOPPED(st)) {
                int sig = WSTOPSIG(st);
                if (sig == SIGTRAP || sig == SIGSTOP || sig == SIGCONT || sig == SIGSEGV)
                    sig = 0; // 内部/伪装事件不透传
                ptrace(PTRACE_CONT, r, 0, sig); // 其余信号原样转发（含 SIGTERM/SIGINT）
            } else if (WIFEXITED(st) || WIFSIGNALED(st)) {
                // 继承 trace 的子进程退出 → 放行收尸（父进程可正常 wait）
                ptrace(PTRACE_CONT, r, 0, 0);
            }
        }
    }
    // ---- 主进程（父）----
    close(g_guard_pipe[1]);
    g_guard_pid = pid;
    g_guard_state = -1; // attach 中
    int fl = fcntl(g_guard_pipe[0], F_GETFL, 0);
    fcntl(g_guard_pipe[0], F_SETFL, fl | O_NONBLOCK);
}

// ---------- L1.29: maps 可执行段数突变检测 ----------
// 原理：注入必在 /proc/self/maps 新增**可执行**映射段（agent 代码段——注入器的 payload 一定是 x）。
// 历史 max 基线：正常运行新增映射（渲染资源、线程栈、Vulkan 管线缓冲）是**非执行数据段**，
// 且渐进扩展（每次刷新 max）→ 不判；只有"历史 max 稳定后瞬时新增 x 段且持续"
// （注入特征——frida agent 一次性建多个 x 段）→ 连续 2 次超阈值 → 检出。
// 审查修复（B2+B2回归+B9v4）：① 原顺序导致第二条永不可达（L1.29 恒不触发）；
//   ② 修复后全段计数在 Vulkan 初始化（一次性建大量 rw 段）时误杀 → 只统计可执行段；
//   ③ **B9v4 回归修正（真机实锤）**：重启后 Vulkan/驱动初始化一次性新建多个"系统库可执行段"
//      （/system /vendor /apex 等），hist_max 来不及爬升 → 连续 2 次超 +6 → 仍误杀
//      （SEC_MAPWATCH=0 即活、开即死的二分证据）。
//      → 改为**只统计"非白名单/非自身/非 [vdso]"的可执行段**（复用 injected_check 判据）：
//      系统库/驱动无论怎么加载都不计数（零误杀面），注入 agent（/data/local/tmp/xxx.so、
//      memfd、匿名 x 段）必计数；阈值收紧到 +3（注入至少新增 1 个 x 段，防瞬时抖动取 3）。
AMICE_FLATTEN_H /*L2AMICE*/
bool maps_spike_check() {
    if (!g_cfg.enable_mapwatch) return true;
    std::string data;
    if (!syscall_read_proc("/proc/self/maps", data)) { // 审查修复（B12）：连续失败=防线被破坏
        if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
        return true;
    }
    g_proc_read_fail.store(0);
    char selfpath[512];
    ssize_t sn = readlink("/proc/self/exe", selfpath, sizeof(selfpath) - 1);
    std::string self;
    if (sn > 0) { selfpath[sn] = '\0'; self.assign(selfpath, static_cast<size_t>(sn)); }
    size_t count = 0;
    std::istringstream ms(data);
    std::string line;
    while (std::getline(ms, line)) {
        size_t p1 = line.find(' ');
        if (p1 == std::string::npos) continue;
        size_t p2 = line.find(' ', p1 + 1);
        if (p2 == std::string::npos) continue;
        std::string perms = line.substr(p1 + 1, p2 - p1 - 1);
        if (perms.find('x') == std::string::npos) continue; // 只数可执行段
        // 解析 pathname（第 6 列起，跳对齐空格）
        size_t p3 = line.find(' ', p2 + 1);
        if (p3 == std::string::npos) continue;
        size_t p4 = line.find(' ', p3 + 1);
        if (p4 == std::string::npos) continue;
        size_t p5 = line.find(' ', p4 + 1);
        if (p5 == std::string::npos) continue;
        size_t pb = line.find_first_not_of(" \t", p5 + 1);
        if (pb == std::string::npos) continue; // 真匿名 x 段 → 计入（注入特征）
        std::string path = line.substr(pb);
        if (path == "[vdso]") continue;
        if (!self.empty() && path == self) continue;
        // 白名单长度用 sizeof 推导（防增删前缀后遍历越界/漏判）
        constexpr size_t kWP = sizeof(kSystemWhitePrefixes) / sizeof(kSystemWhitePrefixes[0]);
        bool sys = false;
        for (size_t i = 0; i < kWP; ++i) {
            if (starts_with(path, kSystemWhitePrefixes[i])) { sys = true; break; }
        }
        if (sys) continue; // 系统库/驱动不参与计数（零误杀）
        ++count;           // 非白名单 x 段（注入特征）
    }
    static size_t hist_max = 0;
    static int spike_hits = 0;
    // 审查修复（本轮 bugscan）：阈值 +3 对"零基线"不友好——常态 count=0（白名单全覆盖）
    // 时 hist_max 恒 0，注入 1~3 个非白名单 x 段（frida agent 常见）不超 0+3 → 漏检。
    // 修正：阈值收紧到 +1（正常环境非白名单 x 段不存在，count 从 0→1 即异常特征）；
    //       连续 2 次 + 渐进基线（Vulkan 若有偶发非白名单 x 段会先爬升 hist_max 适应）。
    // count<1（常态）时也走刷新逻辑（hist_max 保持 0），不再提前 return。
    if (hist_max > 0 && count > hist_max + 1) { // 阈值 +1（注入新增 ≥1 非白名单 x 段即超）
        if (++spike_hits >= 2) return false;     // 连续 2 次超阈值 = 注入（防瞬时抖动）
    } else {
        spike_hits = 0;
    }
    if (count > hist_max) hist_max = count; // 渐进扩展：刷新基线（含 count=0 常态：hist_max 保持 0）
    return true;
}

// ---------- TracerPid 周期轮询 ----------
// ptrace attach 后 /proc/self/status 的 TracerPid != 0（补充 GhostTrace 周期复检）
AMICE_FLATTEN_H /*L2AMICE*/
bool tracerpid_check() {
    // 审查修复（B8/N3）：guard_poll() 必须在 enable_tracerpid 开关判断之前——
    // 否则 SEC_TRACER=0 时守护死亡检测被短路（守护被 kill 后防线静默失效）。
    if (g_cfg.enable_guard && g_guard_pid > 0)
        guard_poll();
    if (!g_cfg.enable_tracerpid) return true;
    std::string data;
    if (!syscall_read_proc("/proc/self/status", data)) { // 审查修复（B12）：连续失败=防线被破坏
        if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
        return true;
    }
    g_proc_read_fail.store(0);
    std::istringstream st(data);
    std::string line;
    int tracer_pid = 0;
    while (std::getline(st, line)) {
        // 审查修复（B9v3）：line.compare(0,9) + atoi(line+9) 解析 bug——
        // "TracerPid:" 是 10 个字符，line+9 指向 ':'，atoi 遇非数字恒返 0 →
        // tracer_pid 永远=0 → return (0==guard_pid) 必误杀（真机 40~90s 延迟退出实锤）。
        // 修正：比较 10 字符 + 从 line+10 跳过 ": " 解析（与 ghosttrace Method2 一致）。
        if (line.size() >= 10 && line.compare(0, 10, "TracerPid:") == 0) {
            const char* v = line.c_str() + 10;
            while (*v == ' ' || *v == '\t') ++v;
            tracer_pid = atoi(v);
            break;
        }
    }
    // L1.28: 守护占位后 TracerPid 常态 = 守护 pid（非 0），须白名单；
    //        守护死（EOF）或 TracerPid 变 0/第三方 → 检出。
    if (g_cfg.enable_guard && g_guard_pid > 0) {
        if (g_guard_state == 0) return false;                              // 守护已死
        if (g_guard_state == 1) return (tracer_pid == (int)g_guard_pid);   // 必须 == 守护
        // attach 中：放行（TracerPid 可能是 0=未attach，也可能是守护=已attach但pipe未到；
        // 第三方 attach 由 GhostTrace Method2 兜底——TracerPid 非 0 且非守护即检出）
        return true;
    }
    return (tracer_pid == 0); // 未启用守护：老逻辑
}

// ---------- L1.23: RELRO/GOT 段权限检测（防 PLT hook 企图） ----------
// 编译已带 -z,relro,-z,now（full RELRO）→ GOT 只读，字节跳动 bhook 类 PLT hook 写 GOT 会失败。
// 攻击者要 PLT hook 必须先 mprotect 解除 RELRO 只读 → 本检测抓"RELRO 段被降级为可写"。
// 实现：从磁盘 /proc/self/exe 解析 PT_GNU_RELRO 段（静态信息，无运行时竞态）；
//       周期比对 maps 中该范围权限——出现 'w' = RELRO 被解除 = hook 企图。
AMICE_FLATTEN_H /*L2AMICE*/
bool relro_check() {
    // 快照：自身路径 + 磁盘解析出的 RELRO 运行地址范围（首次调用建立，之后复用）
    static std::string relro_self;
    static uintptr_t relro_start = 0;
    static size_t relro_len = 0;
    static bool parsed = false;

    if (!parsed) {
        char selfpath[512];
        ssize_t n = readlink("/proc/self/exe", selfpath, sizeof(selfpath) - 1);
        if (n <= 0) return true;
        selfpath[n] = '\0';
        relro_self.assign(selfpath);
        std::string self_base;
        size_t slash = relro_self.rfind('/');
        if (slash != std::string::npos) self_base = relro_self.substr(slash + 1);
        else self_base = relro_self;

        std::string exe;
        if (!syscall_read_proc("/proc/self/exe", exe)) { // 审查修复（B12）：连续失败=防线被破坏
            if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
            return true;
        }
        g_proc_read_fail.store(0);
        if (exe.size() < 64) return true;
        // ELF64 header: e_phoff@0x20(8) e_phentsize@0x36(2) e_phnum@0x38(2)
        const unsigned char* h = reinterpret_cast<const unsigned char*>(exe.data());
        uint64_t phoff = 0; for (int i = 0; i < 8; ++i) phoff |= static_cast<uint64_t>(h[0x20 + i]) << (8 * i);
        unsigned phent = h[0x36] | (h[0x37] << 8);
        unsigned phnum = h[0x38] | (h[0x39] << 8);
        uint64_t relro_vaddr = 0, relro_memsz = 0;
        for (unsigned i = 0; i < phnum; ++i) {
            size_t off = static_cast<size_t>(phoff + i * phent);
            if (off + 48 > exe.size()) break;
            const unsigned char* ph = reinterpret_cast<const unsigned char*>(exe.data() + off);
            uint32_t ptype = ph[0] | (ph[1] << 8) | (ph[2] << 16) | (ph[3] << 24);
            if (ptype == 0x6474e552u) { // PT_GNU_RELRO
                for (int k = 0; k < 8; ++k) {
                    relro_vaddr |= static_cast<uint64_t>(ph[16 + k]) << (8 * k);
                    relro_memsz |= static_cast<uint64_t>(ph[40 + k]) << (8 * k);
                }
                break;
            }
        }
        if (relro_memsz == 0) return true; // 无 RELRO（理论上不该发生，防御性放行）

        // PIE 基址 = maps 中自身映射段的最小 start（仅当该段 offset==0 且路径匹配）
        std::string maps;
        if (!syscall_read_proc("/proc/self/maps", maps)) { // 审查修复（B12）：连续失败=防线被破坏
            if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
            return true;
        }
        g_proc_read_fail.store(0);
        uintptr_t base = 0;
        std::istringstream mss(maps);
        std::string line;
        while (std::getline(mss, line)) {
            size_t p0 = line.find('-');
            if (p0 == std::string::npos) continue;
            size_t p1 = line.find(' ', p0);
            size_t p2 = line.find(' ', p1 + 1);
            if (p2 == std::string::npos) continue;
            std::string perms = line.substr(p1 + 1, p2 - p1 - 1);
            size_t p3 = line.find(' ', p2 + 1);
            if (p3 == std::string::npos) continue;
            uint64_t off = strtoull(line.substr(p2 + 1, p3 - p2 - 1).c_str(), nullptr, 16);
            if (off != 0) continue; // 只认文件偏移 0 的基址段
            size_t p4 = line.find(' ', p3 + 1), p5 = line.find(' ', p4 + 1);
            if (p5 == std::string::npos) continue;
            std::string path;
            if (p5 + 1 < line.size()) path = line.substr(p5 + 1);
            size_t pb = path.find_first_not_of(" \t");
            if (pb == std::string::npos) continue;
            path = path.substr(pb);
            if (path.empty()) continue;
            bool match = (path == relro_self);
            if (!match) {
                size_t lp = path.rfind('/');
                std::string pb2 = (lp == std::string::npos) ? path : path.substr(lp + 1);
                if (pb2 == self_base) match = true;
            }
            if (!match) continue;
            base = strtoull(line.substr(0, p0).c_str(), nullptr, 16);
            break;
        }
        if (base == 0) return true;

        relro_start = base + (relro_vaddr & ~(uint64_t)0xfffULL);
        // 审查修复（B14）：PT_GNU_RELRO 末页若与可写 .data 同页，maps 该行带 w →
        // 用原 memsz 会误判"RELRO 被解除"。relro_len 对齐上取整到完整覆盖页。
        uint64_t relro_vaddr_end = (relro_vaddr + relro_memsz + 0xfffULL) & ~(uint64_t)0xfffULL;
        relro_len = static_cast<size_t>(relro_vaddr_end - relro_vaddr);
        parsed = true;
    }

    // 周期比对：maps 中覆盖 RELRO 范围的段是否被降级为可写
    std::string maps;
    if (!syscall_read_proc("/proc/self/maps", maps)) { // 审查修复（B12）：连续失败=防线被破坏
        if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
        return true;
    }
    g_proc_read_fail.store(0);
    std::istringstream mss(maps);
    std::string line;
    uintptr_t relro_end = relro_start + relro_len;
    while (std::getline(mss, line)) {
        size_t p0 = line.find('-');
        if (p0 == std::string::npos) continue;
        size_t p1 = line.find(' ', p0);
        if (p1 == std::string::npos) continue;
        uintptr_t start = strtoull(line.substr(0, p0).c_str(), nullptr, 16);
        uintptr_t end = strtoull(line.substr(p0 + 1, p1 - p0 - 1).c_str(), nullptr, 16);
        // 只关心自身映射（RELRO 属于本程序）——地址重叠即可（maps 仅本进程，重叠必属自身）
        if (end <= relro_start || start >= relro_end) continue;
        // 审查修复（B14）：find 返回 npos 时 substr 长度会是巨大数（语义错）——显式截断
        size_t pe = line.find(' ', p1 + 1);
        std::string perms = (pe == std::string::npos)
            ? line.substr(p1 + 1)
            : line.substr(p1 + 1, pe - p1 - 1);
        if (perms.find('w') != std::string::npos)
            return false; // RELRO 只读段被解除为可写 = PLT hook 企图
    }
    return true;
}

// ---------- L1.24: seccomp-bpf 禁危险 syscall（防注入路径 + 限制被注入后 agent 能力） ----------
// 参考 Android zygote seccomp policy / MSeccomp 思路：
//   - memfd_create(319): frida agent 在本进程内建 memfd 可执行映射的路径。
//     禁掉后 frida 只能 fallback tmpfile+dlopen → 非白名单可执行段 → injected_check 双保险。
//   - process_vm_readv(270)/writev(271): 远程读写本进程内存（gdb/注入器常用）。
//   - perf_event_open(241): 侧信道采样。
//   - bpf(280): root 攻击者 eBPF/kprobe 挂探测路径。
//   - open_by_handle_at(265): root 绕过路径限制打开任意文件句柄。
//   - userfaultfd(282): 注入器常用（信号注入/内存同步）。
// 注意：不禁 ptrace（GhostTrace 的 PTRACE_TRACEME 自占位 / PEEKDATA 反调试需要）。
// 审查修复（B1）：号表必须用 __NR_*（此前 319/304/272 是 x86_64 号——arm64 的
//   memfd_create=279、open_by_handle_at=265、272=kcmp；memfd 注入路径实际没关）。
// 失败/未开启 → 放行（保守，不阻断启动）。
void apply_seccomp_filter() {
#ifdef __aarch64__
    if (!g_cfg.enable_seccomp) return;
    // 编译期断言：arm64 号表与预期一致（防未来内核号表漂移）
    static_assert(__NR_memfd_create == 279, "arm64 memfd_create != 279");
    static_assert(__NR_process_vm_readv == 270, "arm64 process_vm_readv != 270");
    static_assert(__NR_process_vm_writev == 271, "arm64 process_vm_writev != 271");
    static_assert(__NR_perf_event_open == 241, "arm64 perf_event_open != 241");
    static_assert(__NR_bpf == 280, "arm64 bpf != 280");
    static_assert(__NR_open_by_handle_at == 265, "arm64 open_by_handle_at != 265");
    static_assert(__NR_userfaultfd == 282, "arm64 userfaultfd != 282");
#define SECCOMP_DENY(nr_) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr_), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
    struct sock_filter filter[] = {
        // 加载系统调用号
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        // memfd_create：frida agent 在本进程内建 memfd 可执行映射的路径
        SECCOMP_DENY(__NR_memfd_create),
        // process_vm_readv/writev：远程读写本进程内存（gdb/注入器常用）
        SECCOMP_DENY(__NR_process_vm_readv),
        SECCOMP_DENY(__NR_process_vm_writev),
        // perf_event_open：侧信道采样
        SECCOMP_DENY(__NR_perf_event_open),
        // bpf：eBPF 挂探测路径
        SECCOMP_DENY(__NR_bpf),
        // open_by_handle_at：绕过路径限制
        SECCOMP_DENY(__NR_open_by_handle_at),
        // userfaultfd：注入器常用
        SECCOMP_DENY(__NR_userfaultfd),
        // 其余放行
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
#undef SECCOMP_DENY
    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0]));
    prog.filter = filter;
    // PR_SET_NO_NEW_PRIVS 必须在 PR_SET_SECCOMP 前设置
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return;
    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) return;
#endif
}

// ---------- L1.25: libc inline-hook 检测 ----------
// 参考 TUGOhost/anti_Android：frida 的 hook 核心是对目标 libc 的 mmap/dlopen/dlsym 等
// 做 inline hook（改函数头为跳转）。完整性自检只管自身 .text，libc 被 hook 是盲区。
// 检测：运行时读 libc 函数头 8 字节 vs 磁盘 /system/lib64/libc.so 对应偏移原始值。
// 手写逐字节比较（不依赖 libc memcmp——自身可能被 hook）。
namespace {
struct LibcFnSnap {
    uintptr_t run_addr;   // 运行时函数地址（dlsym）
    uintptr_t seg_base;   // 所在 libc 段运行起始
    uint64_t  seg_file_off;
    unsigned char disk[8]; // 磁盘原始 8 字节
};
std::vector<LibcFnSnap> g_libc_snap;
bool g_libc_parsed = false;

static bool read_mem_bytes(uintptr_t addr, unsigned char out[8]) {
    // 手写逐字节读（绕过可能被 hook 的 libc memcpy）
    volatile const unsigned char* p = reinterpret_cast<volatile const unsigned char*>(addr);
    for (int i = 0; i < 8; ++i) out[i] = p[i];
    return true;
}
static bool bytes_equal(const unsigned char a[8], const unsigned char b[8]) {
    for (int i = 0; i < 8; ++i) if (a[i] != b[i]) return false;
    return true;
}
} // namespace

AMICE_FLATTEN_H /*L2AMICE*/
bool libc_hook_check() {
    if (!g_cfg.enable_libc) return true;
    if (!g_libc_parsed) {
        // 首次：定位 libc.so 各段 + 目标函数运行时地址
        const char* kFns[] = { "open", "read", "fopen", "ioctl", "mmap", "mprotect" };
        std::string data;
        if (!syscall_read_proc("/proc/self/maps", data)) { // 审查修复（B12）：连续失败=防线被破坏
            if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
            return true;
        }
        g_proc_read_fail.store(0);
        std::istringstream mss(data);
        std::string line;
        struct SegInfo { uintptr_t start, end; uint64_t file_off; };
        std::vector<SegInfo> libc_segs;
        while (std::getline(mss, line)) {
            size_t p0 = line.find('-');
            if (p0 == std::string::npos) continue;
            size_t p1 = line.find(' ', p0);
            if (p1 == std::string::npos) continue;
            size_t p2 = line.find(' ', p1 + 1);
            if (p2 == std::string::npos) continue;
            std::string perms = line.substr(p1 + 1, p2 - p1 - 1);
            if (perms.find('x') == std::string::npos) continue; // 只要可执行段
            size_t p3 = line.find(' ', p2 + 1);
            if (p3 == std::string::npos) continue;
            uint64_t off = strtoull(line.substr(p2 + 1, p3 - p2 - 1).c_str(), nullptr, 16);
            size_t p4 = line.find(' ', p3 + 1), p5 = line.find(' ', p4 + 1);
            if (p5 == std::string::npos) continue;
            std::string path;
            if (p5 + 1 < line.size()) path = line.substr(p5 + 1);
            size_t pb = path.find_first_not_of(" \t");
            if (pb == std::string::npos) continue;
            path = path.substr(pb);
            if (path.find("libc.so") == std::string::npos) continue;
            uintptr_t start = strtoull(line.substr(0, p0).c_str(), nullptr, 16);
            uintptr_t end = strtoull(line.substr(p0 + 1, p1 - p0 - 1).c_str(), nullptr, 16);
            libc_segs.push_back({start, end, off});
        }
        if (libc_segs.empty()) return true;

        // 磁盘 libc 文件 fd（定向读各偏移原始字节）
        std::string libc_path;
        {
            std::string data2;
            if (!syscall_read_proc("/proc/self/maps", data2)) { // 审查修复（B12）：连续失败=防线被破坏
                if (g_proc_read_fail.fetch_add(1) + 1 >= 3) arm_detected();
                return true;
            }
            g_proc_read_fail.store(0);
            std::istringstream m2(data2);
            while (std::getline(m2, line)) {
                if (line.find("libc.so") == std::string::npos) continue;
                size_t pb = line.find_last_of(' ');
                if (pb == std::string::npos) continue;
                std::string p = line.substr(pb + 1);
                size_t q = p.find_first_not_of(" \t");
                if (q != std::string::npos) p = p.substr(q);
                if (!p.empty()) { libc_path = p; break; }
            }
        }
        if (libc_path.empty()) return true;
        int fdf = ::open(libc_path.c_str(), O_RDONLY);
        if (fdf < 0) return true;

        bool ok = true;
        for (const char* fn : kFns) {
            void* sym = dlsym(RTLD_DEFAULT, fn);
            if (!sym) continue;
            uintptr_t addr = reinterpret_cast<uintptr_t>(sym);
            // 找 addr 所在 libc 段
            const SegInfo* hit = nullptr;
            for (const auto& s : libc_segs) {
                if (addr >= s.start && addr < s.end) { hit = &s; break; }
            }
            if (!hit) continue;
            uint64_t disk_off = hit->file_off + (addr - hit->start);
            unsigned char disk[8] = {0};
            if (::lseek(fdf, static_cast<off_t>(disk_off), SEEK_SET) < 0) { ok = false; break; }
            size_t got = 0;
            while (got < 8) {
                ssize_t r = ::read(fdf, disk + got, 8 - got);
                if (r <= 0) { ok = false; break; }
                got += static_cast<size_t>(r);
            }
            if (!ok) break;
            g_libc_snap.push_back({addr, hit->start, hit->file_off, {disk[0],disk[1],disk[2],disk[3],disk[4],disk[5],disk[6],disk[7]}});
        }
        ::close(fdf);
        if (!ok || g_libc_snap.empty()) return true;
        g_libc_parsed = true;
        return true; // 首次调用只建快照（不判）
    }

    // 周期比对：内存 prologue vs 磁盘原始
    for (const auto& s : g_libc_snap) {
        unsigned char mem[8] = {0};
        read_mem_bytes(s.run_addr, mem);
        if (!bytes_equal(mem, s.disk))
            return false; // libc 函数头被改 = inline hook
    }
    return true;
}

// ---------- L1.26: inotify 反内存 dump（移植 TUGOhost/anti_Android anti_mem_dump.cpp） ----------
// PR_SET_DUMPABLE=0（L1.8）拦不住 KernelSU root 读 /proc/pid/mem；
// inotify 监控 mem/pagemap 的 IN_ACCESS|IN_OPEN——任何进程读本进程内存都触发事件（含 root）。
// 独立监控线程（不占检测线程）：阻塞读事件 → arm_detected()（幂等，走延迟退出）。
// 不监控 maps：自身检测自读 maps 会误报；maps 非直接内存 dump 面。
namespace {
static void* mem_watch_thread_fn(void*) {
    if (!g_cfg.enable_memwatch) return nullptr;
    for (;;) {
        long fd = ::syscall(SYS_inotify_init1, 0);
        if (fd < 0) { usleep(3000000); continue; } // init 失败 3s 后重试（保守不报错）

        long wd_self_mem = ::syscall(SYS_inotify_add_watch, fd, "/proc/self/mem", IN_ACCESS | IN_OPEN);
        long wd_self_pm  = ::syscall(SYS_inotify_add_watch, fd, "/proc/self/pagemap", IN_ACCESS | IN_OPEN);
        (void)wd_self_mem; (void)wd_self_pm; // procfs 是否支持 inotify 由真机验证；失败静默继续

        // 线程级 mem/pagemap（/proc/self/task/N/mem）
        DIR* d = opendir("/proc/self/task");
        if (d) {
            struct dirent* e;
            while ((e = readdir(d)) != nullptr) {
                if (e->d_name[0] == '.') continue;
                std::string tp = std::string("/proc/self/task/") + e->d_name;
                ::syscall(SYS_inotify_add_watch, fd, (tp + "/mem").c_str(), IN_ACCESS | IN_OPEN);
                ::syscall(SYS_inotify_add_watch, fd, (tp + "/pagemap").c_str(), IN_ACCESS | IN_OPEN);
            }
            closedir(d);
        }

        // 阻塞读事件：任何进程 open/读 mem|pagemap → 事件 → 武装延迟退出
        char buf[4096];
        long r = ::syscall(SYS_read, fd, buf, sizeof(buf));
        if (r > 0) {
            arm_detected(); // 幂等：内存被 dump → 20~90s 后退出（不立即退，防行为反推）
            ::syscall(SYS_close, fd);
            usleep(100000); // 短暂退避后重建 watch（防 watch 被清理/事件风暴）
        } else {
            ::syscall(SYS_close, fd);
        }
    }
    return nullptr;
}
} // namespace

void start_mem_watch_thread() {
    if (!g_cfg.enable_memwatch) return;
    pthread_t t;
    if (pthread_create(&t, nullptr, mem_watch_thread_fn, nullptr) == 0) {
        pthread_detach(t);
    }
}

// ---------- L1.27: 反 Unicorn 模拟器 ----------
// Unicorn 是基于 QEMU 的 CPU 模拟引擎，攻击者用它"摘出代码段在 PC 上模拟执行"
// 来绕过动态检测 / 逆 T3 验证 / dump 后分析。用户态（EL0）可用的区分点：
//   ① CNTVCT_EL0（虚拟计数器，EL0 可读）：真实硬件每次读取必严格递增；
//      Unicorn 常返回固定/假值 → 两次读取相等 = 假时钟。
//   ② 新 syscall faccessat2(439)/openat2(437)：Android 5.10+ 内核支持；
//      Unicorn 无对应 hook → ENOSYS(-38)。先读内核版本（>=5.10 才判，防老内核误杀）。
// 说明：真机上这两条路径都是正常行为（计数器递增 / syscall 成功）→ 永不误杀；
//       被 Unicorn 模拟时环境异常 → arm_detected 延迟退出。
AMICE_FLATTEN_H /*L2AMICE*/
bool unicorn_check() {
    if (!g_cfg.enable_unicorn) return true;

    // ① CNTVCT_EL0 两次读取相等 → 假时钟（真实硬件不可能相等）
    // 审查修复（B10）：背靠背两次读在低频系统计数器（19.2MHz/1MHz，周期 52ns~1µs）
    // 上可能落在同一 tick 内 → 真机误杀。修正：读间隔内插入忙等（≥4µs，覆盖 1MHz
    // 计数器一个 tick），且只判"连续 N 次背靠背后仍相等"。
    bool clock_stalled = true;
    for (int attempt = 0; attempt < 3; ++attempt) {
        uint64_t t0 = 0, t1 = 0;
        __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(t0));
        volatile uint64_t spin = 0;
        for (int i = 0; i < 4096; ++i) spin += i; // 忙等 ~数 µs（-O3 下编译器不会消除副作用）
        __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(t1));
        if (t0 != t1) { clock_stalled = false; break; }
    }
    if (clock_stalled)
        return false; // 计数器静止 = 模拟时钟（3 次采样间隔 >1µs 仍相等）

    // ③ CTR_EL0 cache 特征寄存器：真机必非零（DminLine/IminLine 等字段指示 cache line 大小），
    //    Unicorn 2.1.4 实测返回 0 → 零值 = 模拟器未实现该寄存器（对新版 Unicorn 有效）
    uint64_t ctr = 0;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr));
    if (ctr == 0)
        return false; // cache 特征为零 = 无真实 cache 语义 = 模拟器

    // ② 内核 >= 5.10 时，faccessat2(439)/openat2(437) 返回 ENOSYS → Unicorn 无 hook
    {
        static int kernel_ok = -1; // -1 未判定, 0 不可用, 1 可用
        if (kernel_ok < 0) {
            kernel_ok = 0;
            char rel[128] = {0};
            std::string kr;
            if (syscall_read_proc("/proc/sys/kernel/osrelease", kr)) {
                // 形如 "5.10.101-android13-..."；取前两段数字
                unsigned maj = 0, min = 0;
                if (sscanf(kr.c_str(), "%u.%u", &maj, &min) == 2)
                    if (maj > 5 || (maj == 5 && min >= 10)) kernel_ok = 1;
            }
        }
        if (kernel_ok == 1) {
            errno = 0;
            long r1 = ::syscall(439, AT_FDCWD, "/", F_OK, 0);          // faccessat2
            if (r1 == -1 && errno == ENOSYS) return false;
            errno = 0;
            long r2 = ::syscall(437, AT_FDCWD, "/", 0, 0);              // openat2
            if (r2 == -1 && errno == ENOSYS) return false;
        }
    }
    return true;
}

// ---------- L1.31: 内核单步过慢检测（第五轮: 对冲 lsdriver 系 stepbp 单步） ----------
// 攻击者用内核 stepbp 逐指令单步跟踪检测函数时, 被步进区域每条指令一次内核往返,
// 实测慢 100x 以上。本检测用固定负载环 + CNTVCT_EL0 计时:
//   - 修复（本轮 bugscan）: 原实现 delta = t - g_slow_base 测的是"两次调用间隔"
//     （快周期 1~2s / 慢周期 4~8s 随机）而不是负载耗时 → 单步 100x 降速被间隔
//     淹没, 检测基本无效（假阴性高）。修正: 负载循环**前后**各读一次 CNTVCT,
//     delta = 循环实际耗时——单步时每条指令一次内核往返 → 放大 100x+。
//   - 首调用记录基线(正常设备频率差异大, 不用常数阈值);
//   - 之后每次与基线比对, 超 ~8x 记一次异常（DVFS ~2-4x / 调度抖动不误杀）;
//   - 连续 3 次异常才判 false —— DVFS 降频单次不误杀, 调度延迟靠连续计数排除。
// 边界: hwbp(断点不停核)不降速——本检测只抓单步/强降速; hwbp 由调用方双路径
// 冗余比对(t3_gate)对冲。基线漂移只升不降, 防攻击者先降频压基线再攻击。
namespace {
thread_local uint64_t g_slow_base = 0;   // 基线(每线程独立, 免跨线程 DVFS 噪声)
thread_local int      g_slow_hits = 0;   // 连续异常计数
} // namespace

AMICE_FLATTEN_H /*L2AMICE*/
bool slowdown_check() {
    uint64_t t0 = 0, t1 = 0;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(t0));
    volatile uint64_t sink = 0;
    for (int i = 0; i < 8192; ++i) sink += static_cast<uint64_t>(i); // 固定负载
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(t1));
    uint64_t delta = t1 - t0;                 // 负载循环实际耗时（时钟周期）
    if (g_slow_base == 0) {                  // 首调用=记录基线
        g_slow_base = delta;
        g_slow_hits = 0;
        return true;
    }
    // 正常波动: DVFS/调度导致单次 2~4x 波动常见 → 阈值 8x（单步 100x 远高于此）
    bool slow = delta > g_slow_base * 8;
    if (!slow && delta > g_slow_base)          // 正常波动: 基线只升不降
        g_slow_base += (delta - g_slow_base) / 2;
    g_slow_hits = slow ? (g_slow_hits + 1) : 0;
    return g_slow_hits < 3;
}

// ---------- L1.30: 命中投毒（反内存 dump） ----------
// 壳厂 anti-dump 惯例：检测命中后向内存撒垃圾——攻击者 dump 到的是毒数据。
// 实现：常驻 64KB 诱饵区（arm 前是伪随机填充，攻击者分析也无用；arm 后再随机化一次）。
// 独立 LCG 随机源（不依赖文件后部的 xorshift32，避免声明顺序耦合）。
// 审查修复（B16）：g_bait_init/g_poison_xs 原为普通变量——memwatch 线程与检测线程
// 同时 arm_detected() 时有数据竞争（同写不同步）。原子化修复；`__builtin___clear_cache`
// 对数据缓冲区无意义（报告指出），移除。
namespace {
uint8_t g_bait[65536];
std::atomic<bool> g_bait_init{false};
std::atomic<uint32_t> g_poison_xs{0x85ebca6bu ^ static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_poison_xs))};
static uint32_t poison_xs() {
    uint32_t x = g_poison_xs.load(std::memory_order_relaxed);
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    g_poison_xs.store(x, std::memory_order_relaxed);
    return x;
}
} // namespace

void poison_memory() {
    if (!g_cfg.enable_poison) return;
    if (!g_bait_init.load(std::memory_order_relaxed)) {
        for (size_t i = 0; i < sizeof(g_bait); ++i) g_bait[i] = static_cast<uint8_t>(poison_xs());
        g_bait_init.store(true, std::memory_order_relaxed);
    }
    // 每次命中都重新随机化诱饵区（多线程并发 arm 时重复填充无害——同一随机源最终一致）
    for (size_t i = 0; i < sizeof(g_bait); ++i) g_bait[i] = static_cast<uint8_t>(poison_xs());
}

// ---------- L1.16: 检测规则数据自校验 ----------
// 对白名单前缀表等关键常量做哈希；首次记录基线，周期重算比对。
// 防攻击者"往白名单加前缀/改规则"绕过行为型检测（patch 判断逻辑改 .text 抓不到，
// 但改规则常量 .rodata 必被抓——提高绕过成本）。
namespace {
static const char* kSelfCheckRegions[] = {
    reinterpret_cast<const char*>(kSystemWhitePrefixes),
    nullptr, // 结束标记
};
static uint64_t fnv1a_bytes(const void* data, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    const unsigned char* p = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}
static uint64_t rules_hash() {
    // 白名单前缀表原始字节（含全部指针 + 各字符串）
    uint64_t h = fnv1a_bytes(kSystemWhitePrefixes, sizeof(kSystemWhitePrefixes));
    for (auto* p : kSystemWhitePrefixes)
        h = fnv1a_bytes(p, strlen(p)) ^ (h * 0x100000001b3ULL);
    return h;
}
std::atomic<uint64_t> g_rules_hash_base{0};
} // namespace

AMICE_FLATTEN_H /*L2AMICE*/
bool rules_selfcheck() {
    if (!g_cfg.enable_selfcheck) return true;
    uint64_t h = rules_hash();
    uint64_t base = g_rules_hash_base.load(std::memory_order_relaxed);
    if (base == 0) {
        g_rules_hash_base.store(h, std::memory_order_relaxed); // 首次记录基线
        return true;
    }
    return h == base; // 规则数据被改 → false
}

// ---------- L1.14: 延迟退出（防行为反推） ----------
// 检测命中 → arm_detected()：记录退出时刻 = now + 随机(20~90s)，幂等。
// 渲染主循环每帧调 should_exit()，倒计时到才 _exit(0)（审计 P2③: 统一退出码）。
// 目的：攻击者"改一字节 → 观察是否退出"来反推检测点时，看到的是
//       进程照常运行 → 无法定位检测点；随后进程随机延迟退出。
namespace {
std::atomic<uint64_t> g_exit_deadline_ms{0};

// 轻量线程安全随机源（thread_local xorshift，避免 rand 竞争）
static thread_local uint32_t g_xs = 0x9e3779b9u ^ static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_xs));

static uint32_t xorshift32() {
    uint32_t x = g_xs;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    g_xs = x;
    return x;
}

static uint64_t steady_ms() {
    return static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count() / 1000000);
}
} // namespace

// 审查修复（B11）：退出判定加盐存储——攻击者把 deadline 写 0 会得到盐值 ≠0 → 不免疫；
// 加"退出线程"冗余路径——不依赖 should_exit（被 patch 也照样退）。
static const uint64_t kExitSalt = 0x9e3779b97f4a7c15ULL;

void arm_detected() {
    // 幂等：已武装不再重置（保证最终一定退出）
    if (g_exit_deadline_ms.load(std::memory_order_relaxed) != 0) return;
    const SecurityConfig& c = g_cfg;
    int lo = c.delay_min, hi = c.delay_max;
    if (hi < lo) hi = lo;
    uint32_t delay_ms = static_cast<uint32_t>(lo) * 1000u +
                        (xorshift32() % (static_cast<uint32_t>(hi - lo + 1) * 1000u));
    g_exit_deadline_ms.store((steady_ms() + delay_ms) ^ kExitSalt, std::memory_order_relaxed);
    freeze_detectors(); // L1.18: 武装后冻结检测函数页，防延迟窗口内被 patch 绕过
    poison_memory();    // L1.30: 命中投毒（诱饵区随机化，反 dump）
    // 冗余退出路径：独立一次性线程 sleep 后 _exit(0)——should_exit 被 patch/主循环卡死也必退
    uintptr_t sleep_ms = delay_ms;
    pthread_t exit_thr;
    if (pthread_create(&exit_thr, nullptr, [](void* p) -> void* {
            usleep(static_cast<useconds_t>(reinterpret_cast<uintptr_t>(p)) * 1000u);
            _exit(0); // 审计 P2③: 统一退出码, 不给"哪条防线打中"的指纹
        }, reinterpret_cast<void*>(sleep_ms)) == 0) {
        pthread_detach(exit_thr);
    }
}

bool should_exit() {
    uint64_t d = g_exit_deadline_ms.load(std::memory_order_relaxed);
    if (d == 0) return false;
    return steady_ms() >= (d ^ kExitSalt);
}

// ---------- L1.21: 检测线程心跳监控 ----------
// 检测线程每周期 ping；主循环查超时——检测线程被 kill 后防线不会"静默失效"。
namespace {
std::atomic<uint64_t> g_hb_ts_ms{0};
static int hb_timeout_ms() {
    const char* v = ::getenv("SEC_HB_TIMEOUT");
    int t = (v && *v) ? atoi(v) : 10;
    if (t < 3) t = 3; // 下限 3s（检测周期 2~6s 的 2 倍余量）
    return t * 1000;
}
} // namespace

void heartbeat_ping() {
    g_hb_ts_ms.store(steady_ms(), std::memory_order_relaxed);
}

bool heartbeat_expired() {
    uint64_t ts = g_hb_ts_ms.load(std::memory_order_relaxed);
    if (ts == 0) return false; // 检测线程尚未首跑（渲染循环开始时已 ping 过，正常不会为 0）
    return (steady_ms() - ts) > static_cast<uint64_t>(hb_timeout_ms());
}

// ---------- L1.18: armed 后冻结检测函数 ----------
// 参考 protect_memory_segments（关键代码段只读）：延迟退出窗口内，
// 检测函数所在页 mprotect(PROT_READ|PROT_EXEC)——攻击者无法 inline-patch
// "最终必退"判定（要 patch 必须先改页权限，mprotect 动作本身可被监控/提高成本）。
void freeze_detectors() {
    static std::atomic<bool> done{false};
    if (done.exchange(true)) return; // 只冻结一次（幂等）
    uintptr_t addrs[] = {
        reinterpret_cast<uintptr_t>(&integrity_check),
        reinterpret_cast<uintptr_t>(&injected_check),
        reinterpret_cast<uintptr_t>(&thread_spike_check),
        reinterpret_cast<uintptr_t>(&tracerpid_check),
        reinterpret_cast<uintptr_t>(&rules_selfcheck),
        reinterpret_cast<uintptr_t>(&frida_extra_check),
        // 审查修复（B11）："最终必退"判定函数也进冻结列表——攻击者 patch should_exit
        // 头 4 字节 = 免疫延迟退出；arm 后这些页 RX 只读，patch 需先改页权限。
        reinterpret_cast<uintptr_t>(&should_exit),
        reinterpret_cast<uintptr_t>(&arm_detected),
        reinterpret_cast<uintptr_t>(&maps_spike_check),
        reinterpret_cast<uintptr_t>(&libc_hook_check),
        reinterpret_cast<uintptr_t>(&unicorn_check),
        reinterpret_cast<uintptr_t>(&relro_check),
    };
    uintptr_t last_page = 0;
    for (uintptr_t a : addrs) {
        uintptr_t page = a & ~(uintptr_t)0xfffULL;
        if (page == 0 || page == last_page) continue;
        last_page = page;
        ::mprotect(reinterpret_cast<void*>(page), 4096, PROT_READ | PROT_EXEC);
    }
}

// ---------- E3: Frida 随机端口 D-Bus AUTH 探测（Sentry 方案） ----------
// frida 16+ server 端口可随机（默认 27042 可改）；固定端口检测失效。
// D-Bus AUTH 协议是强特征：对 127.0.0.1/0.0.0.0 的全部 LISTEN 端口发短
// "AUTH" 探测，frida server 回 REJECTED/ERROR（普通 TCP 服务不回 D-Bus 响应）。
// 只扫本机回环/任意监听端口（不触外部网络）；每次 150ms 超时；上限 20 端口防阻塞。
namespace {
// 对单个端口发 D-Bus AUTH 探测。返回 true=命中 frida 特征。
static bool dbus_probe_port(int port) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return false;
    // 非阻塞 connect + poll 短超时
    int fl = ::fcntl(s, F_GETFL, 0);
    ::fcntl(s, F_SETFL, fl | O_NONBLOCK);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 只探 127.0.0.1
    int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof(a));
    if (r != 0 && errno != EINPROGRESS) { ::close(s); return false; }
    struct pollfd pfd;
    pfd.fd = s; pfd.events = POLLOUT; pfd.revents = 0;
    r = ::poll(&pfd, 1, 150);
    if (r <= 0 || (pfd.revents & POLLOUT) == 0) { ::close(s); return false; }
    // 已连上 → 发 D-Bus AUTH（协议首字节 0x00 + "AUTH\r\n"）
    static const unsigned char auth[] = { 0x00, 'A','U','T','H','\r','\n' };
    (void)::send(s, auth, sizeof(auth), MSG_NOSIGNAL);
    // 读响应（150ms）
    char buf[256];
    ssize_t n = 0;
    for (int i = 0; i < 3; ++i) {
        struct pollfd in;
        in.fd = s; in.events = POLLIN; in.revents = 0;
        r = ::poll(&in, 1, 150);
        if (r <= 0 || (in.revents & POLLIN) == 0) break;
        ssize_t m = ::recv(s, buf + n, sizeof(buf) - 1 - static_cast<size_t>(n), MSG_NOSIGNAL);
        if (m <= 0) break;
        n += m;
        if (n >= static_cast<ssize_t>(sizeof(buf)) - 1) break;
    }
    ::close(s);
    if (n <= 0) return false;
    buf[n] = '\0';
    // frida D-Bus 响应强特征：REJECTED / ERROR（D-Bus 协议握手失败应答）
    if (strstr(buf, "REJECTED") || strstr(buf, "ERROR")) return true;
    return false;
}
} // namespace

bool frida_dbus_probe() {
    if (!g_cfg.enable_dbus) return true;
    std::string data;
    if (!syscall_read_proc("/proc/net/tcp", data)) return true; // 读失败放行（保守）
    std::vector<int> ports;
    std::istringstream ss(data);
    std::string line;
    std::getline(ss, line); // 跳 header
    while (std::getline(ss, line) && static_cast<int>(ports.size()) < 20) {
        // 字段: sl local_address rem_address st ...
        std::istringstream ls(line);
        std::string f0, f1, f2, f3;
        ls >> f0 >> f1 >> f2 >> f3;
        if (f3 != "0A") continue; // 仅 LISTEN
        size_t colon = f1.find(':');
        if (colon == std::string::npos) continue;
        std::string ip = f1.substr(0, colon);
        if (ip != "0100007F" && ip != "00000000") continue; // 仅回环/任意监听
        int port = 0;
        std::istringstream hs(f1.substr(colon + 1));
        hs >> std::hex >> port;
        if (port > 0 && port < 65536) ports.push_back(port);
    }
    for (int port : ports) {
        if (dbus_probe_port(port)) return false; // 命中 frida
    }
    return true;
}

// ---------- E2: SIGTRAP Hook 陷阱（Sentry 方案） ----------
// 专用 pthread 安装 SIGTRAP handler；周期性 tgkill 只向本线程发 SIGTRAP；
// handler 内设标志 + siglongjmp 跳回循环。若 Frida 的 signal chaining 吞掉/重排
// 信号（handler 未执行 → longjmp 未发生）→ 标志不置位 → 判定信号链被篡改。
// siglongjmp 从 handler 跳回（防 SIGTRAP 默认动作终止进程），与 Sentry 一致。
namespace {
volatile sig_atomic_t g_sigtrap_hit = 0;
static jmp_buf g_sigtrap_jb;

static void sigtrap_handler(int) {
    g_sigtrap_hit = 1;
    siglongjmp(g_sigtrap_jb, 1); // 跳回陷阱线程主循环（同线程，安全）
}

static void* sigtrap_thread_fn(void*) {
    if (!g_cfg.enable_sigtrap) return nullptr;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigtrap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // 不设 SA_RESTART：重排/吞信号场景更明显
    if (::sigaction(SIGTRAP, &sa, nullptr) != 0) return nullptr; // 装不上就放弃
    // 随机周期 3~6s
    uint32_t xs = static_cast<uint32_t>(steady_ms()) ^ 0x9e3779b9u;
    for (;;) {
        xs ^= xs << 13; xs ^= xs >> 17; xs ^= xs << 5;
        useconds_t w = 3000000u + (xs % 3000000u);
        ::usleep(w);
        g_sigtrap_hit = 0;
        // 预置跳回点（必须在 tgkill 前）
        if (sigsetjmp(g_sigtrap_jb, 1) == 0) {
            pid_t tid = static_cast<pid_t>(::syscall(SYS_gettid));
            ::syscall(SYS_tgkill, ::getpid(), tid, SIGTRAP);
            // 正常路径：handler 已 siglongjmp 回来，这里不会执行到；
            // 若 handler 被吞（未 longjmp）→ tgkill 后 SIGTRAP 默认动作=终止进程
            ::usleep(500000); // 冗余等待（防信号延迟）
        }
        if (g_sigtrap_hit == 0) arm_detected(); // handler 未执行 = 信号链被篡改
    }
    return nullptr;
}
} // namespace

bool sigtrap_trap_check() {
    // 单次检查语义：陷阱线程持续运行，此处返回 true（干净）——
    // 命中由陷阱线程内部 arm_detected() 处理（长期运行型防线）。
    return true;
}

void start_sigtrap_thread() {
    pthread_t t;
    if (::pthread_create(&t, nullptr, sigtrap_thread_fn, nullptr) == 0) {
        ::pthread_detach(t);
    }
}

// ---------- E1: pagemap soft-dirty (bit 55) 脏页检测（Sentry 方案） ----------
// 内核维护 soft-dirty：页被写则置位，用户态无法伪造（比用户态自校验更强）。
// 检测 libc fork 函数所在页——frida inline hook libc 导出函数后该页被写
// （mprotect RW + patch → COW → soft-dirty=1）；正常共享只读代码段不被写。
// 注意：pagemap 在 untrusted_app 上由内核策略返回 0 化页表（Sentry spec 注明）——
// 我们是 KernelSU root 裸 ELF，可读。soft-dirty 是累计位（一旦被写持久为 1），
// 语义 = "该页曾被写"（hook 历史或现在）；对 libc 关键函数页，正常必须为 0。
bool pagemap_dirty_check() {
    if (!g_cfg.enable_pagemap) return true;
    void* fn = ::dlsym(RTLD_DEFAULT, "fork");
    if (!fn) return true; // 取不到函数就放行（保守）
    long psz = ::sysconf(_SC_PAGESIZE);
    if (psz <= 0) return true;
    uintptr_t page = reinterpret_cast<uintptr_t>(fn) & ~(static_cast<uintptr_t>(psz) - 1);
    long fd = ::syscall(SYS_openat, AT_FDCWD, "/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return true; // 读不到放行（权限受限场景不误杀）
    uint64_t entry = 0;
    uint64_t idx = static_cast<uint64_t>(page) / static_cast<uint64_t>(psz);
    ssize_t r = ::syscall(SYS_pread64, fd, &entry, 8, static_cast<off_t>(idx * 8));
    ::syscall(SYS_close, fd);
    if (r != 8) return true;
    // bit55 = soft-dirty（Sentry 注释强调：不要用 bit 61——文件映射恒为 1 会误报）
    return (entry & (1ULL << 55)) == 0; // true=干净；false=该页被写过（代码被 hook）
}

// ---------- F1: smaps 可执行段 Private_Dirty 检测（Sentry 通道一） ----------
// 原理：系统库代码段是文件映射、多进程只读共享，正常 Private_Dirty 应为 0。
// frida inline hook libc/libart 等 → COW 私有副本 → 该可执行段 Private_Dirty>0。
// 防误杀：① 白名单路径放行（code_cache/JIT 等正常 COW 场景）；② 连续 2 次检测
// 都命中才 arm（瞬态/系统偶发写不误杀）。
static int g_smaps_hit = 0;
bool smaps_dirty_check() {
    if (!g_cfg.enable_smaps) return true;
    std::string data;
    if (!syscall_read_proc("/proc/self/smaps", data)) return true; // 读失败放行
    bool suspicious = false;
    const char* p = data.c_str();
    bool in_exec = false;
    const char* mapping_path = nullptr;
    size_t mapping_path_len = 0;
    while (*p) {
        const char* eol = strchr(p, '\n');
        size_t len = eol ? static_cast<size_t>(eol - p) : strlen(p);
        if (len >= 4 && (memmem(p, len, "r-xp", 4) || memmem(p, len, "r-x ", 4))) {
            // 映射行：找路径（行尾空格后）
            in_exec = true;
            mapping_path = nullptr; mapping_path_len = 0;
            const char* sp = p;
            const char* last_space = nullptr;
            for (size_t i = 0; i < len; i++) { if (sp[i] == ' ') last_space = sp + i; }
            if (last_space) {
                const char* path = last_space + 1;
                while (*path == ' ') path++;
                mapping_path = path;
                mapping_path_len = static_cast<size_t>(eol - path);
            }
        } else if (in_exec && len >= 12 && memmem(p, len, "Private_Dirty:", 14)) {
            long kb = 0;
            if (sscanf(p, "Private_Dirty: %ld kB", &kb) == 1 && kb > 0) {
                // 白名单：JIT/code_cache 等正常私有脏页
                bool whitelisted = false;
                const char* wl[] = { "code_cache", "libstagefright", "[anon:libc_malloc]", "app_jit" };
                for (auto* w : wl) {
                    if (mapping_path && memmem(mapping_path, mapping_path_len, w, strlen(w))) { whitelisted = true; break; }
                }
                if (!whitelisted && mapping_path) {
                    // 仅对可疑系统库/自身路径判脏（匿名或普通路径不判，降低误杀）
                    const char* su[] = { "/system/", "/vendor/", "/apex/", "/odm/", "/product/",
                                         "/system_ext/", "/data/app/", "/linkerconfig/",
                                         "/data/local/tmp/", "AndroidSurfaceImguiEnhanced" };
                    bool system_map = false;
                    for (auto* s : su) {
                        if (memmem(mapping_path, mapping_path_len, s, strlen(s))) { system_map = true; break; }
                    }
                    if (system_map) suspicious = true;
                }
            }
            in_exec = false; // 一个段只统计一次
        } else if (*p == '-' || *p == 'S' || *p == 'N') {
            // 新映射行复位（权限行后跟的统计行之间可能没有 r-x 前缀）
            if (!(len >= 4 && (memmem(p, len, "r-xp", 4) || memmem(p, len, "r-x ", 4)))) in_exec = false;
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (suspicious) {
        if (++g_smaps_hit >= 2) { g_smaps_hit = 0; return false; } // 连续 2 次命中才 arm
    } else {
        g_smaps_hit = 0; // 干净则清零（防一次误触持续生效）
    }
    return true;
}

// ---------- F2: ARM64 trampoline 模式扫描（OWASP MASTG / Sentry） ----------
// frida Interceptor 的典型 inline hook 尾部（ARM64）：
//   LDR X16, [PC, #8]   = 50 00 00 58
//   BR  X16             = 00 02 1F D6
// 注意：此模式在正常 PLT veneer / 长跳转 stub 中同样常见（libc 导出函数解析到
// PLT 后头部就含它）——所以【不能扫函数头部】（实测必误报）。
// 只扫【纯匿名可执行段】（无路径、无 [anon 标记）——正常 Android 环境此类段
// 几乎不存在（vdso 带 [vdso] 标记，JIT/GPU 代码带 [anon:dalvik-jit / kgsl 等标记），
// frida memfd/裸 mmap 注入的 agent 代码恰落在这里。≥3 命中才 arm 降误报。
static bool scan_trampoline_region(const unsigned char* base, size_t len) {
    static const unsigned char pat[8] = { 0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6 };
    int hits = 0;
    if (len < 8) return false;
    for (size_t i = 0; i + 8 <= len; i += 4) { // 指令对齐步进
        if (memcmp(base + i, pat, 8) == 0) {
            if (++hits >= 3) return true; // 三处以上典型 trampoline = 注入
        }
    }
    return false;
}
bool trampoline_scan_check() {
    if (!g_cfg.enable_tramp) return true;
    std::string maps;
    if (!syscall_read_proc("/proc/self/maps", maps)) return true;
    size_t pos = 0;
    while (pos < maps.size()) {
        size_t eol = maps.find('\n', pos);
        if (eol == std::string::npos) eol = maps.size();
        std::string line = maps.substr(pos, eol - pos);
        pos = eol + 1;
        if (line.find("r-xp") == std::string::npos && line.find("r-x ") == std::string::npos) continue;
        size_t sp = line.rfind(' ');
        std::string path = (sp == std::string::npos) ? "" : line.substr(sp + 1);
        // 只扫纯匿名段：路径为空且无 [ 前缀标记（vdso/[anon:*] 都带标记，跳过）
        if (!path.empty()) continue;
        unsigned long long start = 0, end = 0;
        if (sscanf(line.c_str(), "%llx-%llx", &start, &end) != 2) continue;
        size_t len = static_cast<size_t>(end - start);
        if (len < 8 || len > (32u << 20)) continue; // 限 32MB 内
        const unsigned char* mem = reinterpret_cast<const unsigned char*>(start);
        if (scan_trampoline_region(mem, len)) return false;
    }
    return true;
}

// ---------- F3: GOT/PLT 劫持检测（OWASP MASTG） ----------
// dlsym 解析的关键函数地址若落在"匿名可执行段/非系统库文件映射"内 → GOT/PLT 被劫持
// （xHook 类工具把 PLT 条目改到注入代码）。正常 libc 函数地址在 libc.so 的 r-xp 段。
bool got_hook_check() {
    if (!g_cfg.enable_got) return true;
    std::string maps;
    if (!syscall_read_proc("/proc/self/maps", maps)) return true;
    const char* names[] = { "open", "read", "write", "close", "fork", "ptrace", "connect", "recvfrom" };
    for (auto* n : names) {
        void* fn = ::dlsym(RTLD_DEFAULT, n);
        if (!fn) continue;
        uintptr_t addr = reinterpret_cast<uintptr_t>(fn);
        // 在 maps 中找地址所在映射
        size_t pos = 0;
        bool in_legit = false;
        while (pos < maps.size()) {
            size_t eol = maps.find('\n', pos);
            if (eol == std::string::npos) eol = maps.size();
            std::string line = maps.substr(pos, eol - pos);
            pos = eol + 1;
            unsigned long long start = 0, end = 0;
            if (sscanf(line.c_str(), "%llx-%llx", &start, &end) != 2) continue;
            if (addr >= start && addr < end) {
                // 权限必须含 x 且路径是系统库（.so 文件映射）
                bool exec = line.find("r-xp") != std::string::npos || line.find("r-x ") != std::string::npos;
                size_t sp = line.rfind(' ');
                std::string path = (sp == std::string::npos) ? "" : line.substr(sp + 1);
                if (exec && (path.find(".so") != std::string::npos &&
                             (path.find("/system/") == 0 || path.find("/apex/") == 0 ||
                              path.find("/vendor/") == 0 || path.find("/odm/") == 0 ||
                              path.find("/product/") == 0 || path.find("/linkerconfig/") == 0))) {
                    in_legit = true;
                }
                break;
            }
        }
        if (!in_legit) return false; // 关键函数不在合法系统库映射内 = GOT/PLT 劫持
    }
    return true;
}

// ---------- G1: libc 关键函数页 disk-vs-memory 比对（MASTG-KNOW-0032 / RiskEngine） ----------
// 直接字节比对，不依赖 trampoline 模式/脏页语义：任何 inline hook（无论跳板形态）
// 都会改内存字节 → memcmp 不等 → arm。dlsym 地址 → 页对齐 → 由 maps 文件 offset
// 推算磁盘偏移 → pread 磁盘页 vs 内存页。连续 2 次命中才 arm 防误报。
static int g_libctxt_hit = 0;
bool libc_text_check() {
    if (!g_cfg.enable_libctxt) return true;
    std::string maps;
    if (!syscall_read_proc("/proc/self/maps", maps)) return true; // 读失败放行
    long psz = ::sysconf(_SC_PAGESIZE);
    if (psz <= 0) return true;
    const char* names[] = { "fork", "open", "read", "write", "close",
                            "ptrace", "connect", "recvfrom", "signal", "mmap" };
    bool suspicious = false;
    for (auto* n : names) {
        void* fn = ::dlsym(RTLD_DEFAULT, n);
        if (!fn) continue; // 取不到放行（保守）
        uintptr_t addr = reinterpret_cast<uintptr_t>(fn);
        uintptr_t vpage = addr & ~(static_cast<uintptr_t>(psz) - 1);
        // 在 maps 中找地址所在文件映射（r-x .so）——path 拷贝到独立 string 防悬垂
        std::string libpath;
        uintptr_t seg_start = 0;
        unsigned long long file_off = 0;
        size_t pos = 0;
        while (pos < maps.size()) {
            size_t eol = maps.find('\n', pos);
            if (eol == std::string::npos) eol = maps.size();
            std::string line = maps.substr(pos, eol - pos);
            pos = eol + 1;
            unsigned long long start = 0, end = 0, off = 0;
            if (sscanf(line.c_str(), "%llx-%llx %*s %llx", &start, &end, &off) != 3) continue;
            if (addr < start || addr >= end) continue;
            if (line.find("r-xp") == std::string::npos && line.find("r-x ") == std::string::npos) break;
            size_t sp = line.rfind(' ');
            std::string path = (sp == std::string::npos) ? "" : line.substr(sp + 1);
            if (path.find(".so") == std::string::npos) break;
            // 页须整体落在段内（防页跨越段边界时 offset 错位）
            uintptr_t seg_end_page = static_cast<uintptr_t>(end) & ~(static_cast<uintptr_t>(psz) - 1);
            if (vpage < start || vpage >= seg_end_page) break;
            // 私有文件映射（frida 注入的 .so 也带路径）——进一步要求系统库前缀
            if (!(path.find("/system/") == 0 || path.find("/apex/") == 0 ||
                  path.find("/vendor/") == 0 || path.find("/odm/") == 0 ||
                  path.find("/product/") == 0 || path.find("/linkerconfig/") == 0)) break;
            libpath = path; // 拷贝（line 是循环局部变量，不能持有其 c_str）
            seg_start = static_cast<uintptr_t>(start);
            file_off = off;
            break;
        }
        if (libpath.empty()) continue; // 不在系统库 r-x 段（F3 已管 GOT 落点；此处放行）
        // 磁盘偏移 = 段文件 offset + (页虚拟地址 - 段起始虚拟地址)
        uintptr_t rel = vpage - seg_start;
        off_t foff = static_cast<off_t>(file_off) + static_cast<off_t>(rel);
        // 打开磁盘文件（syscall 直读，抗 libc hook 干扰本检测）
        int fd = static_cast<int>(::syscall(SYS_openat, AT_FDCWD, libpath.c_str(), O_RDONLY));
        if (fd < 0) continue; // 打不开放行（保守）
        unsigned char disk[16384];
        ssize_t r = ::syscall(SYS_pread64, fd, disk, static_cast<size_t>(psz), foff);
        ::syscall(SYS_close, fd);
        if (r != static_cast<ssize_t>(psz)) continue;
        // 内存页 vs 磁盘页
        const volatile unsigned char* mem = reinterpret_cast<const volatile unsigned char*>(vpage);
        bool diff = false;
        for (long i = 0; i < psz; i++) {
            if (mem[i] != disk[i]) { diff = true; break; }
        }
        if (diff) { suspicious = true; break; } // 任一关键函数页被改 = hook
    }
    if (suspicious) {
        if (++g_libctxt_hit >= 2) { g_libctxt_hit = 0; return false; } // 连续 2 次命中才 arm
    } else {
        g_libctxt_hit = 0;
    }
    return true;
}

} // namespace anti_extra
