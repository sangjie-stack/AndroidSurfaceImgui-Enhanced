// T3卡密验证门禁实现 —— 官方示例流程的加密落地
// 阻塞: 版本检查 -> 公告 -> 本地卡密自动登录 -> 终端手动输入循环
// 成功后: 保存卡密 + 启动60秒心跳线程(连续5次失败exit(1)) -> 返回true
#include "amice_annotate.h"   //L2: amice 混淆注解
#include "t3_gate.h"
#include "t3sdk/t3sdk.h"
#include "obfuscate.h"
#include "anti_extra.h"      //L1: 延迟退出机制(arm_detected) —— 纠缠失败处置复用
#include "entangle_decode.h"   // 服务端密钥纠缠: 解码器(decode/derive)

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <limits.h>
#include <memory>

// 本地程序版本号
static const char* LOCAL_VERSION = "1000";

// ---- 卡密文件: 与可执行文件同目录的 .t3card ----
static std::string card_file_path() {
    char buf[PATH_MAX] = {0};
    ssize_t n = readlink(AY_OBFUSCATE("/proc/self/exe"), buf, sizeof(buf) - 1);
    if (n <= 0) return (const char*)AY_OBFUSCATE(".t3card");
    buf[n] = '\0';
    char* slash = strrchr(buf, '/');
    if (slash) *slash = '\0';
    return std::string(buf) + (const char*)AY_OBFUSCATE("/.t3card");
}

static std::string load_card() {
    std::ifstream ifs(card_file_path());
    if (!ifs.is_open()) return "";
    std::string card;
    std::getline(ifs, card);
    while (!card.empty() && (card.back() == '\n' || card.back() == '\r' || card.back() == ' '))
        card.pop_back();
    return card;
}

static void save_card(const std::string& card) {
    std::ofstream ofs(card_file_path());
    if (ofs.is_open())
        ofs << card;
}

static std::string trim_card(std::string card) {
    while (!card.empty() && (card.front() == ' ' || card.front() == '\t'))
        card.erase(card.begin());
    while (!card.empty() && (card.back() == ' ' || card.back() == '\t'
           || card.back() == '\n' || card.back() == '\r'))
        card.pop_back();
    return card;
}

namespace t3 {

// —— 纠缠状态(仅真实登录路径写入) ——

static uint64_t g_session_key   = 0;   // core 原文派生的候选密钥
static bool     g_session_valid = false;
static uint32_t g_decoded_tick  = 90;
static uint64_t g_session_key_alt     = 0;   // core hex 解码形态的候选密钥
static bool     g_session_key_alt_set = false;
static EntangledCfg g_cfg = {};   // v2: 解码后配置(消费端: 检测节奏/随机源)
static uint64_t g_win_key = 0;    // 实际解开 ENC_CFG 的候选(主或 alt)
static bool     g_win_set = false;

// core 是否全为 hex 数字且偶数长度(T3 平台可能以 hex 编码下发 core)
static bool core_is_hex(const std::string& c) {
    if (c.size() < 2 || (c.size() % 2) != 0) return false;
    for (char ch : c)
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')))
            return false;
    return true;
}

// core -> {原文候选, hex解码候选} 两个会话密钥
AMICE_FLATTEN_H /*L2AMICE*/
static void derive_core_candidates(const std::string& core, const char* appkey,
                                   uint64_t& k0, uint64_t& k1, bool& has_alt) {
    k0 = t3::derive_session_key(core.c_str(), appkey);
    k1 = 0; has_alt = false;
    if (!core_is_hex(core)) return;
    std::string decoded;
    decoded.reserve(core.size() / 2);
    for (size_t i = 0; i + 1 < core.size(); i += 2) {
        auto nib = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            return ch - 'A' + 10;
        };
        decoded.push_back((char)((nib(core[i]) << 4) | nib(core[i + 1])));
    }
    if (!decoded.empty()) {
        k1 = t3::derive_session_key(decoded.c_str(), appkey);
        has_alt = true;
    }
}

// 解码失败处置(审计 P2①): 不再阻塞主线程 3~9 秒——卡死本身就是"纠缠失败"的
// 即时信号。改挂 anti_extra 延迟退出(20~90s 随机, 幂等), 与其他防线行为一致,
// 由主循环 should_exit() 统一执行。
static void entangle_punish() {
    anti_extra::arm_detected();
}

AMICE_FLATTEN_H /*L2AMICE*/
bool verify_and_run() {
    // verify 必须是 shared_ptr 堆对象: 心跳线程(detach)引用它, 函数返回后由引用计数保活, 避免悬垂引用
    auto verify = std::make_shared<T3Verify>();

    std::cout << "========================================" << std::endl;
    std::cout << "            卡密验证系统" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;

    // RSA模式初始化: 调用码/APPKEY/公钥全部编译期加密, 二进制无明文
    if (!verify->initRSA(
        (const char*)AY_OBFUSCATE("76478CC2AC33CB6A"),                          /* 单码登录调用码 */
        (const char*)AY_OBFUSCATE("D13B45357DEAFAB3"),                          /* 获取程序公告调用码 */
        (const char*)AY_OBFUSCATE("3B403E6EC9CA0973"),                          /* 获取程序最新版本号调用码 */
        (const char*)AY_OBFUSCATE("7B117AAE9116EFDA"),                          /* 单码卡密心跳验证调用码 */
        (const char*)AY_OBFUSCATE("fa98f186f0ee325b653331c1fdb02e8f"),          /* 程序密钥APPKEY */
        (const char*)AY_OBFUSCATE("-----BEGIN PUBLIC KEY-----\n"
                     "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+MFUZNtLLLOeHvacXHuoxiqcg\n"
                     "CusS7lVs5AbnBYXYcANbFQy9nNMGb+RJsf+eprWvQlK08+fCP/v78s0w7r3cFRPR\n"
                     "4uVbvWoQPe6pke7SSZQaZPLZWLpglpi0zcw0KMFzA4LitKtep4NhEkTCMFv/wxSF\n"
                     "QyYlwmJKh+4MgRRmcwIDAQAB\n"
                     "-----END PUBLIC KEY-----")                    /* RSA公钥 */
    )) {
        std::cout << "SDK初始化失败!" << std::endl;
        return false;
    }

    // 1. 版本检查: 服务器版本高于本地则拒绝运行
    std::cout << "[版本检查] ";
    auto versionResult = verify->getLatestVersion();
    if (versionResult.success) {
        if (versionResult.version > LOCAL_VERSION) {
            std::cout << "发现新版本: " << versionResult.version
                      << ", 当前版本: " << LOCAL_VERSION
                      << ", 请更新后再使用" << std::endl;
            return false;
        }
        std::cout << "当前已是最新版本 (" << LOCAL_VERSION << ")" << std::endl;
    } else {
        std::cout << "获取版本号失败: " << versionResult.error << std::endl;
    }

    // 2. 公告
    std::cout << std::endl;
    auto noticeResult = verify->getNotice();
    if (noticeResult.success && !noticeResult.notice.empty()) {
        std::cout << "========== 公告 ==========" << std::endl;
        std::cout << noticeResult.notice << std::endl;
        std::cout << "==========================" << std::endl;
    }
    std::cout << std::endl;

    // 3. 登录流程: 先本地卡密自动登录, 失败则终端手动输入
    std::string machineCode = getMachineCode();
    std::string card;
    T3LoginResult loginResult;
    bool loggedIn = false;

    card = load_card();
    if (!card.empty()) {
        std::cout << "[自动登录] 检测到本地保存的卡密, 正在自动登录..." << std::endl;
        loginResult = verify->login(card, machineCode);
        if (loginResult.success) {
            loggedIn = true;
            std::cout << "[自动登录] 登录成功!" << std::endl;
        } else {
            std::cout << "[自动登录] 自动登录失败: " << loginResult.error << std::endl;
            std::cout << "[自动登录] 请手动输入卡密" << std::endl << std::endl;
            card.clear();
        }
    }

    while (!loggedIn) {
        std::cout << "请输入卡密: ";
        std::getline(std::cin, card);
        card = trim_card(card);

        if (card.empty()) {
            std::cout << "卡密不能为空, 请重新输入" << std::endl;
            continue;
        }

        std::cout << "[登录中] 正在验证卡密..." << std::endl;
        loginResult = verify->login(card, machineCode);
        if (loginResult.success) {
            loggedIn = true;
            std::cout << "[登录成功]" << std::endl;
        } else {
            std::cout << "[登录失败] " << loginResult.error << std::endl;
            std::cout << "请重新输入卡密" << std::endl << std::endl;
        }
    }

    // 4. 账号信息 + 保存卡密
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  登录成功!" << std::endl;
    std::cout << "  到期时间: " << loginResult.end_time << std::endl;
    std::cout << "  卡密时长: " << loginResult.amount << std::endl;
    std::cout << "  剩余时间: " << loginResult.available << "秒" << std::endl;
    std::cout << "  绑定设备: " << (loginResult.imei.empty() ? "无" : loginResult.imei) << std::endl;
    std::cout << "  解绑次数: " << loginResult.change << std::endl;
    // 审计 P1-2: 不再打印核心数据——core 是纠缠方案的共享秘密, 打印等于把
    // 会话密钥的原料送到每个付费客户眼前
    std::cout << "========================================" << std::endl;
    save_card(card);

    // 5. 心跳线程: 每60秒一次, 连续失败5次强制退出
    // 必须值捕获(verify shared_ptr 保活 + card/statecode 值拷贝): 原 [&] 引用捕获悬垂, 60秒后首次心跳
    // 访问已销毁栈对象 → string 读垃圾长度 → std::bad_alloc 崩溃(真机两次复现)
    std::string hbCard = card;
    std::string hbStatecode = loginResult.statecode;
    std::thread heartbeatThread([verify, hbCard, hbStatecode]() {
        int failCount = 0;
        const int MAX_FAIL = 5;
        const int INTERVAL = 60;

        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(INTERVAL));
            auto hbResult = verify->heartbeat(hbCard, hbStatecode);
            if (hbResult.success) {
                failCount = 0;
                // 远程总闸(审计优化项): 官方心跳响应不带 core, 周期调专用接口
                // getCoreByKami 重取。服务器改一次控制台 core 即可吊销所有旧二进制。
                // 保守判定: 仅当取回成功且 core 非空且双候选均解不开时才武装退出;
                // 接口失败/字段缺失不判(防网络抖动误杀)。
                auto coreResult = verify->getCoreByKami(hbCard);
                if (coreResult.success && !coreResult.core.empty()) {
                    const char* appkey = (const char*)AY_OBFUSCATE("fa98f186f0ee325b653331c1fdb02e8f");
                    uint64_t k0 = 0, k1 = 0;
                    bool has_alt = false;
                    derive_core_candidates(coreResult.core, appkey, k0, k1, has_alt);
                    EntangledCfg cfg;
                    if (!t3::entangle_decode(k0, &cfg) &&
                        !(has_alt && t3::entangle_decode(k1, &cfg)))
                        entangle_punish();   // 幂等武装, 不阻塞心跳循环
                }
            } else {
                failCount++;
                std::cout << "[心跳] 验证失败 (" << failCount << "/" << MAX_FAIL
                          << "): " << hbResult.error << std::endl;
                if (failCount >= MAX_FAIL) {
                    std::cout << "[心跳] 连续失败 " << MAX_FAIL << " 次, 程序强制退出!" << std::endl;
                    std::exit(1);
                }
            }
        }
    });
    heartbeatThread.detach();

    // —— 服务端密钥纠缠: 由真实登录才拿得到的 core 派生会话密钥 ——
    // 门禁被 patch 跳过时 g_session_valid 永远是 false (core 只有服务器会发)
    // T3 平台可能以 hex 编码下发 core: 派生 原文/hex解码 两个候选密钥,
    // 解码时按序尝试 (entangle_or_die), 任一解开即通过
    {
        const char* appkey = (const char*)AY_OBFUSCATE("fa98f186f0ee325b653331c1fdb02e8f");
        bool has_alt = false;
        derive_core_candidates(loginResult.core, appkey,
                               g_session_key, g_session_key_alt, has_alt);
        g_session_key_alt_set = has_alt;
        g_session_valid = !loginResult.core.empty();
    }

    return true;
}

// —— 纠缠接口实现 ——————————————————————————————

// v2(审计 P2②): 返回"实际解开 ENC_CFG 的候选"(主或 hex-alt),
// 避免 hex 下发 core 的部署拿到错密钥。仅在 entangle_or_die() 解码成功后有效。
AMICE_FLATTEN_H /*L2AMICE*/
bool session_key(uint64_t* out) {
    if (!g_win_set) return false;
    if (out) *out = g_win_key;
    return true;
}

// v2(审计 P0-1/P2①): 解码失败不再返回 false——武装延迟退出并返回 true 伪装
// 通过, 垃圾配置流入消费端(检测节奏/随机源)使行为悄悄劣化, 20~90s 后由主循环
// should_exit() 统一静默退出。不给"改这里就过了"的即时反馈。
AMICE_FLATTEN_H /*L2AMICE*/
bool entangle_or_die() {
    EntangledCfg cfg;
    uint64_t win = 0;
    bool ok = false;
    if (g_session_valid && t3::entangle_decode(g_session_key, &cfg)) {
        win = g_session_key; ok = true;
    } else if (g_session_key_alt_set && t3::entangle_decode(g_session_key_alt, &cfg)) {
        win = g_session_key_alt; ok = true;
    }
    if (!ok) {
        entangle_punish();
        return true;   // 伪装通过; 延迟退出已武装
    }
    g_win_key = win;
    g_win_set = true;
    g_cfg = cfg;
    g_decoded_tick = cfg.security_tick ? cfg.security_tick : 90;
    return true;
}

AMICE_FLATTEN_H /*L2AMICE*/
uint32_t entangled_security_tick() { return g_decoded_tick; }

// v2(审计 P0-1): 解码配置的消费者接口——检测线程随机源种子混合(flags/spare)与
// 慢周期调制(tick)。垃圾解密 => 检测节奏与随机行为悄悄劣化, 而非单点 bool 失效。
AMICE_FLATTEN_H /*L2AMICE*/
uint32_t entangled_flags() { return g_win_set ? g_cfg.draw_flags : 0; }

AMICE_FLATTEN_H /*L2AMICE*/
uint32_t entangled_spare() { return g_win_set ? g_cfg.spare : 0; }

} // namespace t3
