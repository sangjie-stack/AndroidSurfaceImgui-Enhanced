// anti_extra.cpp
// 动态防逆向增强实现（L1.6 完整性自检 / L1.8 dumpable / L1.9 反Frida多向量）
#include "amice_annotate.h"   //L2: amice 混淆注解
#include "anti_extra.h"
#include "obfuscate.h" // 检测特征串加密，避免静态暴露检测点

#include <sys/prctl.h>
#include <unistd.h>
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
        if (path != self_path) continue;        // 只比对自身

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
    if (!collect_text_segs(self, segs)) return true; // 解析不到也放行

    std::ifstream disk("/proc/self/exe", std::ios::binary);
    if (!disk) return true;

    for (const auto& seg : segs) {
        std::vector<char> buf(seg.size);
        disk.clear();
        disk.seekg(static_cast<std::streamoff>(seg.file_off));
        if (!disk.read(buf.data(), static_cast<std::streamsize>(seg.size)))
            continue; // 读不到完整段（异常情况）放行该段
        if (memcmp(reinterpret_cast<const void*>(seg.start), buf.data(), seg.size) != 0)
            return false; // 内存被篡改！
    }
    return true;
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
