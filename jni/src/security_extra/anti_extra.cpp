// anti_extra.cpp
// 动态防逆向增强实现（L1.6 完整性自检 / L1.8 dumpable / L1.9 反Frida多向量）
#include "amice_annotate.h"   //L2: amice 混淆注解
#include "anti_extra.h"
#include "obfuscate.h" // 检测特征串加密，避免静态暴露检测点

#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include <fstream>
#include <string>
#include <vector>

namespace anti_extra {

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

    std::ifstream maps("/proc/self/maps");
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
    std::ifstream maps("/proc/self/maps");
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
        std::ifstream f(comm_path);
        std::string name;
        if (std::getline(f, name)) {
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

} // namespace anti_extra
