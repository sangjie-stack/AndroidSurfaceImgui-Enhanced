LOCAL_PATH := $(call my-dir)


# 引入freetype静态库 #
include $(CLEAR_VARS)
LOCAL_MODULE := lib_git_freetype
LOCAL_SRC_FILES := src/ImGui/misc/git_freetype/$(TARGET_ARCH_ABI)/libfreetype.a
include $(PREBUILT_STATIC_LIBRARY)


# =============================================================================
#  [L3-tls] mbedTLS 静态库 (TLS 传输层)
# =============================================================================
#  用途: t3sdk.cpp 的 httpPostRaw 原为裸 socket 明文 HTTP(且把 https 降到 80 端口),
#        现改由 src/t3sdk/tls_transport.cpp 走 mbedTLS 真 TLS。
#  选型: mbedTLS 3.6.4 LTS / Apache-2.0 / 纯 C 零异常(与全局 -fno-exceptions 兼容)。
#  产物来源: tools/build_mbedtls_arm64.sh 在 Ubuntu 上交叉编译 (NDK r30, API 22)。
#  注意: 预编译静态库不会像源码模块那样把 C++ feature(exceptions) 传播到主模块,
#        所以这里安全 —— 这也是不能用"源码子模块"方式引入的原因(见上方接线说明)。
include $(CLEAR_VARS)
LOCAL_MODULE := lib_mbedtls
LOCAL_SRC_FILES := prebuilt/mbedtls/$(TARGET_ARCH_ABI)/libmbedtls.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_mbedx509
LOCAL_SRC_FILES := prebuilt/mbedtls/$(TARGET_ARCH_ABI)/libmbedx509.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_mbedcrypto
LOCAL_SRC_FILES := prebuilt/mbedtls/$(TARGET_ARCH_ABI)/libmbedcrypto.a
include $(PREBUILT_STATIC_LIBRARY)


# =============================================================================
#  [L2-amice] 接线说明
# =============================================================================
#  AMICE_PLUGIN_FLAG   命令行注入 -fpass-plugin=<bundle>/amice/lib/libamice.so
#  AMICE_NO_EXCEPTIONS 1 = 关闭 C++ 异常（amice VMP/Flatten 的前置条件）
#  AMICE_DROP_DEMO     1 = -DIMGUI_DISABLE_DEMO_WINDOWS（剥离 imgui_demo 死代码指纹）
#
#  为什么必须 -fno-exceptions（2026-10-09 实测证据，日志 results/*.log）：
#    含非平凡局部对象（std::string/vector）的函数，在 -fexceptions 下每个跨函数调用
#    都是 invoke + landingpad（为异常时跑析构），而 amice 两个关键 Pass 都明确拒绝：
#      (VmVirtualize) skip function "...": invoke exception edges are not supported by vm_virtualize
#      (flatten-enhanced) function "..." has exception handling instructions, skipping
#    实测全局 -fexceptions 时 login / initRSA / decodeResponse / getMachineCode /
#    t3::verify_and_run / ANativeWindowCreator::Create / anti_extra::integrity_check
#    【全部】被跳过 —— 敏感函数一个都没混淆，只有 ImGui 被混淆（体积白涨）。
#
#  注意：不要用"把 t3sdk.cpp 拆成独立静态库"的办法来隔离异常——ndk-build 会把
#  依赖模块的 C++ feature（exceptions）传播到主模块，在编译命令【末尾】追加
#  -fexceptions，反而让主模块的 -fno-exceptions 失效（实测复现）。所以 t3sdk.cpp
#  本身必须是异常自由的（错误码 + 显式检查），全工程统一 -fno-exceptions。
# =============================================================================


include $(CLEAR_VARS)
LOCAL_MODULE := AndroidSurfaceImguiEnhanced

LOCAL_CFLAGS := -std=c17
LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_CFLAGS += -O3 -ffunction-sections -fdata-sections -fno-ident #L0加固: 优化/裁剪/去编译器标识
LOCAL_CFLAGS += -fstack-protector-strong #L0加固: 栈溢出保护
LOCAL_CFLAGS += -mbranch-protection=standard #L0加固: arm64 BTI/PAC 防 ROP/跳转注入
LOCAL_CFLAGS += -DPLATFORM_ANDROID=1 -DARCH_ARM64=1 #GhostTrace平台选择

LOCAL_CPPFLAGS := -std=c++17
LOCAL_CPPFLAGS += -fvisibility=hidden
LOCAL_CPPFLAGS += -O3 -ffunction-sections -fdata-sections -fno-ident #L0加固: 优化/裁剪/去编译器标识
LOCAL_CPPFLAGS += -fstack-protector-strong #L0加固: 栈溢出保护
LOCAL_CPPFLAGS += -mbranch-protection=standard #L0加固: arm64 BTI/PAC
LOCAL_CPPFLAGS += -DPLATFORM_ANDROID=1 -DARCH_ARM64=1 #GhostTrace平台选择

LOCAL_CPPFLAGS += -DVK_USE_PLATFORM_ANDROID_KHR
LOCAL_CPPFLAGS += -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES
LOCAL_CPPFLAGS += -DIMGUI_DISABLE_DEBUG_TOOLS #禁用imgui调试工具
LOCAL_CPPFLAGS += -DIMGUI_ENABLE_FREETYPE     #启用imgui的freetype支持
# L3-tls: mbedTLS 裁剪配置头 (由 tools/build_mbedtls_arm64.sh 生成, 见 include/mbedtls_config_android.h)
LOCAL_CFLAGS   += -DMBEDTLS_CONFIG_FILE='"mbedtls_config_android.h"'
LOCAL_CPPFLAGS += -DMBEDTLS_CONFIG_FILE='"mbedtls_config_android.h"'
ifeq ($(AMICE_DROP_DEMO),1)
  LOCAL_CPPFLAGS += -DIMGUI_DISABLE_DEMO_WINDOWS #L2: 剥离 imgui_demo 死代码指纹
endif

# [L2-amice] 关异常：amice VMP/Flatten 前置条件（源码 0 处 try/catch/throw）
#   命令行注入 AMICE_NO_EXCEPTIONS=1 打开；不注入时保持原构建行为
ifeq ($(AMICE_NO_EXCEPTIONS),1)
  LOCAL_CPPFLAGS += -fno-exceptions
else
  LOCAL_CPPFLAGS += -fexceptions
endif

# [L2-amice] 插件注入
LOCAL_CFLAGS   += $(AMICE_PLUGIN_FLAG)
LOCAL_CPPFLAGS += $(AMICE_PLUGIN_FLAG)

#引入头文件到全局#
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_draw
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_Graphics
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_my_imgui
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_touch
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/My_Utils
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ghosttrace
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui/backends
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui/misc/freetype
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui/misc/git_freetype
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/t3sdk
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/native_surface
LOCAL_C_INCLUDES += $(LOCAL_PATH)/src/Android_verify   # t3_gate.h 所在目录（main.cpp 依赖）
LOCAL_C_INCLUDES += $(LOCAL_PATH)/src/entangle       # 纠缠解码器



LOCAL_SRC_FILES := src/main.cpp
LOCAL_SRC_FILES += src/Android_draw/draw_Gui.cpp
LOCAL_SRC_FILES += src/Android_touch/TouchHelperA.cpp
LOCAL_SRC_FILES += src/Android_Graphics/GraphicsManager.cpp
LOCAL_SRC_FILES += src/Android_Graphics/OpenGLGraphics.cpp
LOCAL_SRC_FILES += src/Android_Graphics/VulkanGraphics.cpp 
LOCAL_SRC_FILES += src/Android_Graphics/vulkan_wrapper.cpp
LOCAL_SRC_FILES += src/Android_my_imgui/AndroidImgui.cpp
LOCAL_SRC_FILES += src/Android_my_imgui/my_imgui.cpp
LOCAL_SRC_FILES += src/Android_my_imgui/my_imgui_impl_android.cpp
LOCAL_SRC_FILES += src/ImGui/imgui.cpp
LOCAL_SRC_FILES += src/ImGui/imgui_demo.cpp
LOCAL_SRC_FILES += src/ImGui/imgui_draw.cpp
LOCAL_SRC_FILES += src/ImGui/imgui_tables.cpp
LOCAL_SRC_FILES += src/ImGui/imgui_widgets.cpp
LOCAL_SRC_FILES += src/ImGui/backends/imgui_impl_android.cpp
LOCAL_SRC_FILES += src/ImGui/backends/imgui_impl_opengl3.cpp
LOCAL_SRC_FILES += src/ImGui/backends/imgui_impl_vulkan.cpp
LOCAL_SRC_FILES += src/ImGui/misc/freetype/imgui_freetype.cpp
LOCAL_SRC_FILES += src/My_Utils/stb_image.cpp
LOCAL_SRC_FILES += src/ghosttrace/ghosttrace_core.c
LOCAL_SRC_FILES += src/ghosttrace/ghosttrace_detection.c
LOCAL_SRC_FILES += src/ghosttrace/ghosttrace_memory.c
LOCAL_SRC_FILES += src/ghosttrace/ghosttrace_process.c
LOCAL_SRC_FILES += src/ghosttrace/ghosttrace_breakpoints.c
LOCAL_SRC_FILES += src/ghosttrace/ghosttrace_android.c
LOCAL_SRC_FILES += src/security_extra/anti_extra.cpp  #L1.6/L1.8/L1.9: 完整性自检+dumpable+反Frida多向量
LOCAL_SRC_FILES += src/t3sdk/t3sdk.cpp               #T3验证SDK(纯C++, 无OpenSSL依赖; L2: 异常自由化)
LOCAL_SRC_FILES += src/t3sdk/tls_transport.cpp       #L3: mbedTLS TLS 传输层(替代裸 socket 明文 HTTP)
LOCAL_SRC_FILES += src/t3_gate.cpp    #T3卡密验证门禁(密钥AY_OBFUSCATE加密)
LOCAL_SRC_FILES += src/entangle/entangle_decode.cpp  #服务端密钥纠缠: core派生key解密业务配置
    



LOCAL_LDLIBS := -llog -landroid -lEGL -lGLESv3
LOCAL_LDLIBS += -lz #freetype需要
LOCAL_LDFLAGS += -Wl,--gc-sections -Wl,-z,relro,-z,now #L0加固: 裁剪未用段/RELRO安全加固
LOCAL_LDFLAGS += -s #L0加固: 链接期 strip 全部符号（去符号表，静态分析难度↑）
LOCAL_STATIC_LIBRARIES := lib_git_freetype
LOCAL_STATIC_LIBRARIES += lib_mbedtls lib_mbedx509 lib_mbedcrypto  #L3: TLS 传输层

include $(BUILD_EXECUTABLE) #可执行文件
