#include "amice_annotate.h"   //L2: amice 混淆注解
#include "draw.h"    //绘制套
#include "AndroidImgui.h"     //创建绘制套
#include "GraphicsManager.h" //获取 当前渲染模式
#include "obfuscate.h"       //L1: 编译期字符串加密 (adamyaxley/Obfuscate, Unlicense)
#include "anti_extra.h"      //L1.6/1.8/1.9/1.13/1.14/1.15: 动态防线全套
#include "t3_gate.h"         //T3卡密验证门禁(终端流程, 官方示例一致)
#include <pthread.h>
#include <unistd.h>
#include <chrono>
extern "C" {
#include "ghosttrace.h"      //L3: 反调试/反Frida/反Xposed (GhostTrace, MIT)
}

// 毫秒时钟（检测线程分层计时用）
static uint64_t ms_now() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// 轻量随机源（线程局部 xorshift，避免 rand 竞争）
static thread_local uint32_t g_tick_xs = 0x2545f491u ^ static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_tick_xs));
static uint32_t tick_xorshift() {
    uint32_t x = g_tick_xs;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    g_tick_xs = x;
    return x;
}

// 启动一次性安全检查：检出立即失败（环境脏，不伪装）
// 每项检测受环境变量开关控制（见 anti_extra.h SecurityConfig 注释）
AMICE_FLATTEN_H /*L2AMICE*/
static bool startup_security_check() {
    if (gt_detect_ptrace() != GT_SUCCESS) return false;
    if (gt_detect_android_frida() != GT_SUCCESS) return false;
    if (gt_detect_android_xposed() != GT_SUCCESS) return false;
    // L1.9: 反Frida多向量增强（maps 注入特征 + 线程名特征）
    if (!anti_extra::frida_extra_check()) return false;
    // L1.13: 行为型注入检测（匿名/非白名单可执行段 + memfd/deleted 精确规则）
    if (!anti_extra::injected_check()) return false;
    // L1.17: 线程突变（启动期调用=记录基线；不判）
    if (!anti_extra::thread_spike_check()) return false;
    // TracerPid：启动期 TracerPid 必须为 0
    if (!anti_extra::tracerpid_check()) return false;
    // L1.16: 规则数据自校验（启动期调用=记录基线哈希；不判）
    if (!anti_extra::rules_selfcheck()) return false;
    // L1.23: RELRO 段权限（启动期解析快照；不判）
    if (!anti_extra::relro_check()) return false;
    // L1.6: ELF 完整性自检（内存 vs 磁盘原始字节，防 patch/inline hook）
    if (!anti_extra::integrity_check()) return false;
    return true;
}

// 快周期轻检测（注入面）：高频率抓"瞬态注入"（注入后很快分离的 agent，
// 慢周期会错过窗口——实测 kxmwp 短暂注入 t+5.3s 自动分离）
AMICE_FLATTEN_H /*L2AMICE*/
static void fast_security_check() {
    if (gt_detect_ptrace() != GT_SUCCESS) { anti_extra::arm_detected(); return; }
    if (gt_detect_android_frida() != GT_SUCCESS) { anti_extra::arm_detected(); return; }
    if (gt_detect_android_xposed() != GT_SUCCESS) { anti_extra::arm_detected(); return; }
    if (!anti_extra::frida_extra_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::injected_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::thread_spike_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::tracerpid_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::maps_spike_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::relro_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::libc_hook_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::unicorn_check()) { anti_extra::arm_detected(); return; }
    // L1.31(第五轮): 内核单步过慢检测——对冲 lsdriver 系 stepbp 逐指令跟踪
    if (!anti_extra::slowdown_check()) { anti_extra::arm_detected(); return; }
}

// 慢周期重检测（开销大：完整性自检读磁盘 ~2.9MB 逐段 memcmp；规则哈希重算）
AMICE_FLATTEN_H /*L2AMICE*/
static void slow_security_check() {
    if (!anti_extra::rules_selfcheck()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::integrity_check()) { anti_extra::arm_detected(); return; }
}

// L1.15: 独立检测线程——时序分层（环境变量 SEC_FAST_INTV / SEC_SLOW_INTV 可调）：
//   快周期 1~2s：注入面轻检测（maps/status/线程数，开销小）→ 瞬态注入必命中；
//   慢周期 4~8s：完整性自检 + 规则自校验（开销大，低频率）。
// 与渲染循环解耦（单点被 patch 不影响另一触发点）；检测线程自身也是退出执行者
AMICE_FLATTEN_H /*L2AMICE*/
static void* security_thread_fn(void*) {
    const anti_extra::SecurityConfig& c = anti_extra::sec_cfg();
    uint64_t next_slow = 0; // 首轮快检测后立即跑一次慢检测
    for (;;) {
        // 审计 P0-1: 纠缠解密值消费——draw_flags/spare 混入检测随机源种子,
        // 垃圾解密 => 检测节奏与随机行为悄悄劣化(而非单点 bool 失效)
        g_tick_xs ^= t3::entangled_flags() ^ t3::entangled_spare();
        useconds_t wait_us = static_cast<useconds_t>(c.fast_interval_min) * 1000000u +
            (tick_xorshift() % (static_cast<useconds_t>(c.fast_interval_max - c.fast_interval_min + 1) * 1000000u));
        usleep(wait_us);
        anti_extra::heartbeat_ping(); // L1.21: 检测线程存活心跳
        fast_security_check();
        if (anti_extra::should_exit())
            _exit(0); // 审计 P2③: 所有静默防线统一退出码 0, 不给"哪条防线打中"的指纹

        uint64_t now = ms_now();
        if (now >= next_slow) {
            slow_security_check();
            if (anti_extra::should_exit())
                _exit(0); // 同上: 统一退出码
            useconds_t sw = static_cast<useconds_t>(c.slow_interval_min) * 1000000u +
                (tick_xorshift() % (static_cast<useconds_t>(c.slow_interval_max - c.slow_interval_min + 1) * 1000000u));
            // 审计 P0-1: security_tick(帧)调制慢周期——解密配置真正参与检测节奏
            next_slow = now + static_cast<uint64_t>(sw / 1000u) + t3::entangled_security_tick();
        }
    }
    return nullptr;
}

int main(int argc, char *argv[]) {
    // 配置：读环境变量开关（须最早，供后续所有检测读取）
    anti_extra::load_sec_cfg_from_env();
    // L1.28: 守护进程 ptrace 占位（须最早——抢占 ptrace 槽位，防攻击者 attach；
    //         须在 startup_security_check / 检测线程之前，确保 TracerPid 白名单就位）
    anti_extra::start_guard_process();
    // L1.8: 禁止其他进程读取本进程内存（须在一切初始化之前）
    anti_extra::set_dumpable();
    // L1.24: seccomp-bpf 禁危险 syscall（须早期：memfd 注入路径关闭/限制 agent 能力）
    anti_extra::apply_seccomp_filter();
    // L3: 反调试/反Frida 初始化（配置保持最小化，检测由下方显式调用）
    gt_config_t gt_cfg = {}; // C++ 聚合初始化（含枚举成员，不能用 {0}）
    gt_cfg.stealth_mode = 1; // 静默模式：不打印 GhostTrace 自身标识
    gt_init(&gt_cfg);
    // 审查修复（B18）：启动期检测命中不再立即 return 0——秒级"启动即退"会让攻击者
    // 快速二分定位启动期检测点。统一走 arm_detected() 延迟退出（20~90s 随机静默退出），
    // 启动期与运行期迷惑性一致。
    if (!startup_security_check())
        anti_extra::arm_detected();

    // L1.15: 启动独立检测线程（须在 T3 门禁之前——卡密输入/心跳期间同样处于受保护状态）
    pthread_t security_thread;
    // 审查修复（B13）：线程创建失败 → 防线缺失即退出（否则心跳恒 0、无人告警）
    if (pthread_create(&security_thread, nullptr, security_thread_fn, nullptr) != 0)
        _exit(0); // 审计 P2③: 统一退出码 0
    // L1.26: inotify 反内存 dump 监控线程（独立线程，不占检测线程）
    anti_extra::start_mem_watch_thread();

    // T3卡密验证（阻塞终端流程：版本检查/公告/自动登录/手动输入循环）
    // 验证通过后心跳线程已在后台运行；失败直接退出，不进入绘制业务
    if (!t3::verify_and_run())
        return 0;

    // 服务端密钥纠缠: 门禁通过后必须用服务器下发的 core 解密业务配置。
    // patch 掉上面的门禁(或控制台未配 core) => 这里解出垃圾 => 延迟静默退出
    if (!t3::entangle_or_die())
        return 0;

    ::graphics = GraphicsManager::getGraphicsInterface(GraphicsManager::VULKAN);

    //获取屏幕信息    
    ::screen_config(); 

    ::native_window_screen_x = (::displayInfo.height > ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);
    ::native_window_screen_y = (::displayInfo.height < ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);
    ::abs_ScreenX = (::displayInfo.height > ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);
    ::abs_ScreenY = (::displayInfo.height < ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);

    // L1: 窗口名加密，二进制中不再出现明文 "AImGui"
    ::window = android::ANativeWindowCreator::Create(AY_OBFUSCATE("AImGui"), native_window_screen_x, native_window_screen_y, permeate_record);
    graphics->Init_Render(::window, native_window_screen_x, native_window_screen_y);
    
    Touch::Init({(float)::abs_ScreenX, (float)::abs_ScreenY}, false); //最后一个参数改成true 只监听
    Touch::setOrientation(displayInfo.orientation);

    
    ::init_My_drawdata(); //初始化绘制数据

    static bool flag = true;
    while (flag) {
        // L1.14: 每帧检查延迟退出倒计时——检测命中后 20~90 秒内静默 _exit(0)
        // (统一退出码, 见审计 P2③; 含纠缠失败武装的延迟退出)
        if (anti_extra::should_exit())
            _exit(0);
        // L1.21: 检测线程心跳超时（被 kill/卡死）→ 立即退出（防线不静默失效）
        if (anti_extra::heartbeat_expired())
            _exit(0);

        drawBegin();
        if (permeate_record == false) {
            android::ANativeWindowCreator::ProcessMirrorDisplay();
        }
        graphics->NewFrame();
        
        Layout_tick_UI(&flag);

        graphics->EndFrame();        
    }
    
    // graphics->DeleteTexture(image);
    graphics->Shutdown();
    android::ANativeWindowCreator::Destroy(::window);
    return 0;
}
