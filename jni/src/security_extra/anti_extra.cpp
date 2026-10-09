// anti_extra.cpp
// 动态防逆向增强实现（L1.6 完整性自检 / L1.8 dumpable / L1.9 反Frida多向量）
#include "amice_annotate.h"   //L2: amice 混淆注解
#include "anti_extra.h"
#include "obfuscate.h" // 检测特征串加密，避免静态暴露检测点

#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
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

SecurityConfig& sec_cfg() { return g_cfg; }

void load_sec_cfg_from_env() {
    if (g_cfg_loaded.load(std::memory_order_relaxed)) return;
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
bool frida_extra_check() {
    if (scan_maps_frida()) return false;
    if (scan_threads_frida()) return false;
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
    "/system_ext/", "/data/app/", "/data/user_de/", "/data/user/0/",
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
    if (!syscall_read_proc("/proc/self/maps", data)) return true; // 读不到就放行（保守）
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
        if (pb == std::string::npos) continue;
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
        if (starts_with(path, kSystemWhitePrefixes[0]) ||
            starts_with(path, kSystemWhitePrefixes[1]) ||
            starts_with(path, kSystemWhitePrefixes[2]) ||
            starts_with(path, kSystemWhitePrefixes[3]) ||
            starts_with(path, kSystemWhitePrefixes[4]) ||
            starts_with(path, kSystemWhitePrefixes[5]) ||
            starts_with(path, kSystemWhitePrefixes[6]) ||
            starts_with(path, kSystemWhitePrefixes[7]) ||
            starts_with(path, kSystemWhitePrefixes[8]) ||
            starts_with(path, kSystemWhitePrefixes[9]))
            continue;

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
    if (g_cfg.thread_baseline < 0) {
        g_cfg.thread_baseline = count; // 首个周期设基线
        return true;
    }
    if (count > g_cfg.thread_baseline + g_cfg.thread_threshold)
        return false; // 线程数突变 = 注入（agent 线程数躲不掉）
    return true;
}

// ---------- TracerPid 周期轮询 ----------
// ptrace attach 后 /proc/self/status 的 TracerPid != 0（补充 GhostTrace 周期复检）
AMICE_FLATTEN_H /*L2AMICE*/
bool tracerpid_check() {
    if (!g_cfg.enable_tracerpid) return true;
    std::string data;
    if (!syscall_read_proc("/proc/self/status", data)) return true; // 读不到就放行（保守）
    std::istringstream st(data);
    std::string line;
    while (std::getline(st, line)) {
        if (line.size() >= 9 && line.compare(0, 9, "TracerPid:") == 0) {
            const char* v = line.c_str() + 9;
            while (*v == ' ' || *v == '\t') ++v;
            if (*v != '0') return false; // 被 ptrace attach
            return true;
        }
    }
    return true; // 读不到也放行（保守）
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
        if (!syscall_read_proc("/proc/self/exe", exe)) return true;
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
        if (!syscall_read_proc("/proc/self/maps", maps)) return true;
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
        relro_len = static_cast<size_t>(relro_memsz);
        parsed = true;
    }

    // 周期比对：maps 中覆盖 RELRO 范围的段是否被降级为可写
    std::string maps;
    if (!syscall_read_proc("/proc/self/maps", maps)) return true;
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
        std::string perms = line.substr(p1 + 1, line.find(' ', p1 + 1) - p1 - 1);
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
// 注意：不禁 ptrace（GhostTrace 的 PTRACE_TRACEME 自占位 / PEEKDATA 反调试需要）。
// 失败/未开启 → 放行（保守，不阻断启动）。
void apply_seccomp_filter() {
#ifdef __aarch64__
    if (!g_cfg.enable_seccomp) return;
    struct sock_filter filter[] = {
        // 加载系统调用号
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        // memfd_create
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 319, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        // process_vm_readv
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 270, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        // process_vm_writev
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 271, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        // perf_event_open
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 241, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        // 其余放行
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
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
        if (!syscall_read_proc("/proc/self/maps", data)) return true;
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
            if (!syscall_read_proc("/proc/self/maps", data2)) return true;
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
    uint64_t t0 = 0, t1 = 0;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(t0));
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(t1));
    if (t0 == t1)
        return false; // 计数器静止 = 模拟时钟

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
// 渲染主循环每帧调 should_exit()，倒计时到才 _exit(42)。
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

void arm_detected() {
    // 幂等：已武装不再重置（保证最终一定退出）
    if (g_exit_deadline_ms.load(std::memory_order_relaxed) != 0) return;
    const SecurityConfig& c = g_cfg;
    int lo = c.delay_min, hi = c.delay_max;
    if (hi < lo) hi = lo;
    uint32_t delay_ms = static_cast<uint32_t>(lo) * 1000u +
                        (xorshift32() % (static_cast<uint32_t>(hi - lo + 1) * 1000u));
    g_exit_deadline_ms.store(steady_ms() + delay_ms, std::memory_order_relaxed);
    freeze_detectors(); // L1.18: 武装后冻结检测函数页，防延迟窗口内被 patch 绕过
}

bool should_exit() {
    uint64_t d = g_exit_deadline_ms.load(std::memory_order_relaxed);
    if (d == 0) return false;
    return steady_ms() >= d;
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
    };
    uintptr_t last_page = 0;
    for (uintptr_t a : addrs) {
        uintptr_t page = a & ~(uintptr_t)0xfffULL;
        if (page == 0 || page == last_page) continue;
        last_page = page;
        ::mprotect(reinterpret_cast<void*>(page), 4096, PROT_READ | PROT_EXEC);
    }
}

} // namespace anti_extra
