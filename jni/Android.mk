LOCAL_PATH := $(call my-dir)


# 引入freetype静态库 #
include $(CLEAR_VARS)
LOCAL_MODULE := lib_git_freetype
LOCAL_SRC_FILES := src/ImGui/misc/git_freetype/$(TARGET_ARCH_ABI)/libfreetype.a
include $(PREBUILT_STATIC_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE := AndroidSurfaceImguiEnhanced

LOCAL_CFLAGS := -std=c17
LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_CFLAGS += -O3 -ffunction-sections -fdata-sections -fno-ident #L0加固: 优化/裁剪/去编译器标识
LOCAL_CFLAGS += -DPLATFORM_ANDROID=1 -DARCH_ARM64=1 #GhostTrace平台选择
LOCAL_CPPFLAGS := -std=c++17
LOCAL_CPPFLAGS += -fvisibility=hidden
LOCAL_CPPFLAGS += -fexceptions
LOCAL_CPPFLAGS += -O3 -ffunction-sections -fdata-sections -fno-ident #L0加固: 优化/裁剪/去编译器标识
LOCAL_CPPFLAGS += -DPLATFORM_ANDROID=1 -DARCH_ARM64=1 #GhostTrace平台选择

LOCAL_CPPFLAGS += -DVK_USE_PLATFORM_ANDROID_KHR
LOCAL_CPPFLAGS += -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES
LOCAL_CPPFLAGS += -DIMGUI_DISABLE_DEBUG_TOOLS #禁用imgui调试工具
LOCAL_CPPFLAGS += -DIMGUI_ENABLE_FREETYPE     #启用imgui的freetype支持

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
LOCAL_C_INCLUDES += $(LOCAL_PATH)/src/Android_verify   # t3_gate.h 所在目录（main.cpp 依赖）



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
LOCAL_SRC_FILES += src/t3sdk/t3sdk.cpp               #T3验证SDK(纯C++, 无OpenSSL依赖)
LOCAL_SRC_FILES += src/t3_gate.cpp    #T3卡密验证门禁(密钥AY_OBFUSCATE加密)
    


LOCAL_LDLIBS := -llog -landroid -lEGL -lGLESv3
LOCAL_LDLIBS += -lz #freetype需要
LOCAL_LDFLAGS += -Wl,--gc-sections -Wl,-z,relro,-z,now #L0加固: 裁剪未用段/RELRO安全加固
LOCAL_STATIC_LIBRARIES := lib_git_freetype

include $(BUILD_EXECUTABLE) #可执行文件
