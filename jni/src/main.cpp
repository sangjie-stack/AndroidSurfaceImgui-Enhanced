#include "amice_annotate.h"   //L2: amice 混淆注解
#include "draw.h"    //绘制套
#include "AndroidImgui.h"     //创建绘制套
#include "GraphicsManager.h" //获取 当前渲染模式
#include "obfuscate.h"       //L1: 编译期字符串加密 (adamyaxley/Obfuscate, Unlicense)
#include "anti_extra.h"      //L1.6/1.8/1.9/1.13/1.14/1.15: 动态防线全套
#include "t3_gate.h"         //T3卡密验证门禁(终端流程, 官方示例一致)
#include <pthread.h>
#include <unistd.h>
extern "C" {
#include "ghosttrace.h"      //L3: 反调试/反Frida/反Xposed (GhostTrace, MIT)
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
    // L1.6: ELF 完整性自检（内存 vs 磁盘原始字节，防 patch/inline hook）
    if (!anti_extra::integrity_check()) return false;
    return true;
}

// 周期安全检查：检出 → 武装延迟退出（伪装正常，防行为反推）
AMICE_FLATTEN_H /*L2AMICE*/
static void periodic_security_check() {
    if (gt_detect_ptrace() != GT_SUCCESS) { anti_extra::arm_detected(); return; }
    if (gt_detect_android_frida() != GT_SUCCESS) { anti_extra::arm_detected(); return; }
    if (gt_detect_android_xposed() != GT_SUCCESS) { anti_extra::arm_detected(); return; }
    if (!anti_extra::frida_extra_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::injected_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::thread_spike_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::tracerpid_check()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::rules_selfcheck()) { anti_extra::arm_detected(); return; }
    if (!anti_extra::integrity_check()) { anti_extra::arm_detected(); return; }
}

// L1.15: 独立检测线程——随机周期 2~5 秒（环境变量 SEC_INTV 可调），防攻击者摸清检测节奏；
//        与渲染循环解耦（单点被 patch 不影响另一触发点）；
//        检测线程自身也是退出执行者（主循环被卡/被 patch 时 2~5s 内必然退出）
static void* security_thread_fn(void*) {
    for (;;) {
        const anti_extra::SecurityConfig& c = anti_extra::sec_cfg();
        useconds_t wait_us = static_cast<useconds_t>(c.interval_min) * 1000000u +
            (tick_xorshift() % (static_cast<useconds_t>(c.interval_max - c.interval_min + 1) * 1000000u));
        usleep(wait_us);
        periodic_security_check();
        if (anti_extra::should_exit())
            _exit(42);
    }
    return nullptr;
}

int main(int argc, char *argv[]) {
    // 配置：读环境变量开关（须最早，供后续所有检测读取）
    anti_extra::load_sec_cfg_from_env();
    // L1.8: 禁止其他进程读取本进程内存（须在一切初始化之前）
    anti_extra::set_dumpable();
    // L3: 反调试/反Frida 初始化（配置保持最小化，检测由下方显式调用）
    gt_config_t gt_cfg = {}; // C++ 聚合初始化（含枚举成员，不能用 {0}）
    gt_cfg.stealth_mode = 1; // 静默模式：不打印 GhostTrace 自身标识
    gt_init(&gt_cfg);
    if (!startup_security_check())
        return 0; // 启动期检测到调试/注入环境，直接退出

    // L1.15: 启动独立检测线程（须在 T3 门禁之前——卡密输入/心跳期间同样处于受保护状态）
    pthread_t security_thread;
    pthread_create(&security_thread, nullptr, security_thread_fn, nullptr);

    // T3卡密验证（阻塞终端流程：版本检查/公告/自动登录/手动输入循环）
    // 验证通过后心跳线程已在后台运行；失败直接退出，不进入绘制业务
    if (!t3::verify_and_run())
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
        // L1.14: 每帧检查延迟退出倒计时——检测命中后 20~90 秒内静默 _exit(42)
        if (anti_extra::should_exit())
            _exit(42);

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
