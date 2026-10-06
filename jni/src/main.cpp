#include "draw.h"    //绘制套
#include "AndroidImgui.h"     //创建绘制套
#include "GraphicsManager.h" //获取 当前渲染模式
#include "obfuscate.h"       //L1: 编译期字符串加密 (adamyaxley/Obfuscate, Unlicense)
extern "C" {
#include "ghosttrace.h"      //L3: 反调试/反Frida/反Xposed (GhostTrace, MIT)
}

// 运行级安全自检：检测到调试器 / Frida / Xposed 时返回 false
// 注意：不做 root 检测——本程序本身就需要 root 运行
static bool security_ok() {
    if (gt_detect_ptrace() != GT_SUCCESS) return false;
    if (gt_detect_android_frida() != GT_SUCCESS) return false;
    if (gt_detect_android_xposed() != GT_SUCCESS) return false;
    return true;
}

int main(int argc, char *argv[]) {
    // L3: 反调试/反Frida 初始化（配置保持最小化，检测由下方显式调用）
    gt_config_t gt_cfg = {}; // C++ 聚合初始化（含枚举成员，不能用 {0}）
    gt_cfg.stealth_mode = 1; // 静默模式：不打印 GhostTrace 自身标识
    gt_init(&gt_cfg);
    if (!security_ok())
        return 0; // 检测到调试环境，直接退出

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
