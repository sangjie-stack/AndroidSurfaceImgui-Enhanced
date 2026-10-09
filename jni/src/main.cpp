#include "draw.h"    //绘制套
#include "AndroidImgui.h"     //创建绘制套
#include "GraphicsManager.h" //获取 当前渲染模式
#include "obfuscate.h"       //L1: 编译期字符串加密 (adamyaxley/Obfuscate, Unlicense)
#include "anti_extra.h"      //L1.6/L1.8/L1.9: 完整性自检 + dumpable + 反Frida多向量
#include "t3_gate.h"         //T3卡密验证门禁(终端流程, 官方示例一致)
extern "C" {
#include "ghosttrace.h"      //L3: 反调试/反Frida/反Xposed (GhostTrace, MIT)
}

// 运行级安全自检：检测到调试器 / Frida / Xposed 时返回 false
// 注意：不做 root 检测——本程序本身就需要 root 运行
static bool security_ok() {
    if (gt_detect_ptrace() != GT_SUCCESS) return false;
    if (gt_detect_android_frida() != GT_SUCCESS) return false;
    if (gt_detect_android_xposed() != GT_SUCCESS) return false;
    // L1.9: 反Frida多向量增强（maps 注入特征 + 线程名特征）
    if (!anti_extra::frida_extra_check()) return false;
    // L1.6: ELF 完整性自检（内存 vs 磁盘原始字节，防 patch/inline hook）
    if (!anti_extra::integrity_check()) _exit(42); // 专用退出码，静默退出
    return true;
}

int main(int argc, char *argv[]) {
    // L1.8: 禁止其他进程读取本进程内存（须在一切初始化之前）
    anti_extra::set_dumpable();
    // L3: 反调试/反Frida 初始化（配置保持最小化，检测由下方显式调用）
    gt_config_t gt_cfg = {}; // C++ 聚合初始化（含枚举成员，不能用 {0}）
    gt_cfg.stealth_mode = 1; // 静默模式：不打印 GhostTrace 自身标识
    gt_init(&gt_cfg);
    if (!security_ok())
        return 0; // 检测到调试环境，直接退出

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
    static int security_tick = 0;
    while (flag) {
        // L3: 周期性复检（约每90帧一次），发现调试器/Frida/Xposed 即退出
        if ((++security_tick % 90) == 0 && !security_ok())
            break;

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
