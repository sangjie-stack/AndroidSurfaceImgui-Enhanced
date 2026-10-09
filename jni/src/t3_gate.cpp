// T3卡密验证门禁实现 —— 官方示例流程的加密落地
// 阻塞: 版本检查 -> 公告 -> 本地卡密自动登录 -> 终端手动输入循环
// 成功后: 保存卡密 + 启动60秒心跳线程(连续5次失败exit(1)) -> 返回true
#include "amice_annotate.h"   //L2: amice 混淆注解
#include "t3_gate.h"
#include "t3sdk/t3sdk.h"
#include "obfuscate.h"
#include "entangle_decode.h"   // 服务端密钥纠缠: 解码器(punish/decode/derive)

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

// 解码器声明放头文件会被 main 引用; entangle_decode.cpp 里已含 entangled_cfg.h

static uint64_t g_session_key   = 0;
static bool     g_session_valid = false;
static uint32_t g_decoded_tick  = 90;

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
    std::cout << "  核心数据: " << loginResult.core << std::endl;
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
    g_session_key   = t3::derive_session_key(loginResult.core.c_str(),
                                             (const char*)AY_OBFUSCATE("fa98f186f0ee325b653331c1fdb02e8f"));
    g_session_valid = !loginResult.core.empty();

    return true;
}

// —— 纠缠接口实现 ——————————————————————————————
static const uint64_t kZeroKey = 0;

bool session_key(uint64_t* out) {
    if (!g_session_valid) return false;
    if (out) *out = g_session_key;
    return true;
}

bool entangle_or_die() {
    uint64_t k = 0;
    if (!session_key(&k)) { t3::entangle_punish(); return false; }
    EntangledCfg cfg;
    if (!entangle_decode(k, &cfg)) { t3::entangle_punish(); return false; }
    g_decoded_tick = cfg.security_tick ? cfg.security_tick : 90;
    return true;
}

uint32_t entangled_security_tick() { return g_decoded_tick; }

} // namespace t3
