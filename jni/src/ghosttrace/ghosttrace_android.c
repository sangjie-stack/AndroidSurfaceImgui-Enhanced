/**
 * CoreGuard - Android-specific Detection Functions
 * 
 * This file implements Android-specific anti-debugging, anti-emulator,
 * and anti-tampering detection techniques.
 */

#include "ghosttrace.h"

#if PLATFORM_ANDROID

#include <dirent.h>
#include <sys/system_properties.h>

/**
 * Check for Android emulator environment
 */
gt_result_t gt_detect_android_emulator(void) {
    GT_LOG_DEBUG("Checking for Android emulator");
    
    /* Check system properties */
    char prop_value[PROP_VALUE_MAX];
    
    /* Check ro.kernel.qemu */
    if (__system_property_get("ro.kernel.qemu", prop_value) > 0) {
        if (strcmp(prop_value, "1") == 0) {
            GT_LOG_WARNING("Android emulator detected via ro.kernel.qemu");
            return GT_ERROR_EMULATOR_DETECTED;
        }
    }
    
    /* Check ro.hardware */
    if (__system_property_get("ro.hardware", prop_value) > 0) {
        GT_STEALTH_STRING(s_goldfish, "\x32\xC5\x39\xCE\x33\xC3\x26\xC2", 8); // goldfish
        GT_STEALTH_STRING(s_ranchu, "\x27\xCB\x3B\xC9\x3D\xDF", 6); // ranchu
        GT_STEALTH_STRING(s_vbox, "\x23\xC8\x3A\xDC", 4); // vbox
        
        if (strstr(prop_value, s_goldfish) || strstr(prop_value, s_ranchu) || 
            strstr(prop_value, s_vbox) || strstr(prop_value, "ttVM")) {
            GT_LOG_WARNING("Android emulator detected via ro.hardware: %s", prop_value);
            return GT_ERROR_EMULATOR_DETECTED;
        }
    }
    
    /* Check ro.product.model */
    if (__system_property_get("ro.product.model", prop_value) > 0) {
        if (strstr(prop_value, "sdk") || strstr(prop_value, "Emulator") ||
            strstr(prop_value, "Android SDK")) {
            GT_LOG_WARNING("Android emulator detected via ro.product.model: %s", prop_value);
            return GT_ERROR_EMULATOR_DETECTED;
        }
    }
    
    /* Check ro.product.manufacturer */
    if (__system_property_get("ro.product.manufacturer", prop_value) > 0) {
        if (strcmp(prop_value, "Genymotion") == 0 || strcmp(prop_value, "unknown") == 0) {
            GT_LOG_WARNING("Android emulator detected via ro.product.manufacturer: %s", prop_value);
            return GT_ERROR_EMULATOR_DETECTED;
        }
    }
    
    /* Check for emulator-specific files */
    const char *emulator_files[] = {
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/proc/tty/drivers", /* Check for goldfish */
        NULL
    };
    
    for (int i = 0; emulator_files[i]; i++) {
        if (access(emulator_files[i], F_OK) == 0) {
            GT_LOG_WARNING("Android emulator detected via file: %s", emulator_files[i]);
            return GT_ERROR_EMULATOR_DETECTED;
        }
    }
    
    /* Check /proc/tty/drivers for goldfish */
    FILE *fp = fopen("/proc/tty/drivers", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "goldfish")) {
                GT_LOG_WARNING("Android emulator detected via /proc/tty/drivers: goldfish");
                fclose(fp);
                return GT_ERROR_EMULATOR_DETECTED;
            }
        }
        fclose(fp);
    }
    
    /* Check CPU info for emulator signatures */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "goldfish") || strstr(line, "ranchu")) {
                GT_LOG_WARNING("Android emulator detected via /proc/cpuinfo");
                fclose(fp);
                return GT_ERROR_EMULATOR_DETECTED;
            }
        }
        fclose(fp);
    }
    
    GT_LOG_DEBUG("No Android emulator detected");
    return GT_SUCCESS;
}

/**
 * Check for root detection on Android
 */
gt_result_t gt_detect_android_root(void) {
    GT_LOG_DEBUG("Checking for Android root");
    
    /* Check for common root binaries */
    const char *root_binaries[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/vendor/bin/su",
        "/system/bin/busybox",
        "/system/xbin/busybox",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        NULL
    };
    
    for (int i = 0; root_binaries[i]; i++) {
        if (access(root_binaries[i], F_OK) == 0) {
            GT_LOG_WARNING("Root binary detected: %s", root_binaries[i]);
            return GT_ERROR_GENERIC;
        }
    }
    
    /* Check for root management apps */
    const char *root_apps[] = {
        "/data/data/com.noshufou.android.su",
        "/data/data/com.thirdparty.superuser",
        "/data/data/eu.chainfire.supersu",
        "/data/data/com.koushikdutta.superuser",
        "/data/data/com.zachspong.temprootremovejb",
        "/data/data/com.ramdroid.appquarantine",
        "/data/data/com.topjohnwu.magisk",
        NULL
    };
    
    for (int i = 0; root_apps[i]; i++) {
        if (access(root_apps[i], F_OK) == 0) {
            GT_LOG_WARNING("Root management app detected: %s", root_apps[i]);
            return GT_ERROR_GENERIC;
        }
    }
    
    /* Check for RW system partition */
    FILE *fp = fopen("/proc/mounts", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "/system") && strstr(line, "rw,")) {
                GT_LOG_WARNING("Root detected: /system mounted as read-write");
                fclose(fp);
                return GT_ERROR_GENERIC;
            }
        }
        fclose(fp);
    }
    
    /* Check build tags */
    char prop_value[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.tags", prop_value) > 0) {
        if (strcmp(prop_value, "test-keys") == 0) {
            GT_LOG_WARNING("Root detected via ro.build.tags: test-keys");
            return GT_ERROR_GENERIC;
        }
    }
    
    /* Modern Root Detection: Magisk/Zygisk */
    /* Check for Magisk-specific mounts */
    FILE *fp_mounts = fopen("/proc/mounts", "r");
    if (fp_mounts) {
        char line[512];
        while (fgets(line, sizeof(line), fp_mounts)) {
            GT_STEALTH_STRING(s_magisk, "\x38\xCB\x32\xC3\x26\xC1", 6); // magisk
            if (strstr(line, s_magisk) || strstr(line, "core/img") || strstr(line, "mirror/bin")) {
                GT_LOG_WARNING("Magisk-specific mount detected");
                fclose(fp_mounts);
                return GT_ERROR_GENERIC;
            }
        }
        fclose(fp_mounts);
    }
    
    /* Check for Zygisk/Magisk files in /data/adb */
    if (access("/data/adb/magisk", F_OK) == 0 || access("/data/adb/modules", F_OK) == 0) {
        GT_LOG_WARNING("Magisk data directory detected");
        return GT_ERROR_GENERIC;
    }

    GT_LOG_DEBUG("No Android root detected");
    return GT_SUCCESS;
}

/**
 * Check for Xposed framework on Android
 */
gt_result_t gt_detect_android_xposed(void) {
    GT_LOG_DEBUG("Checking for Xposed framework");
    
    /* Check for Xposed installer */
    if (access("/data/data/de.robv.android.xposed.installer", F_OK) == 0) {
        GT_LOG_WARNING("Xposed framework detected: installer found");
        return GT_ERROR_GENERIC;
    }
    
    /* Check for Xposed bridge */
    if (access("/system/framework/XposedBridge.jar", F_OK) == 0) {
        GT_LOG_WARNING("Xposed framework detected: bridge found");
        return GT_ERROR_GENERIC;
    }
    
    /* Check for Xposed in /proc/self/maps */
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "XposedBridge") || strstr(line, "xposed")) {
                GT_LOG_WARNING("Xposed framework detected in memory maps");
                fclose(fp);
                return GT_ERROR_GENERIC;
            }
        }
        fclose(fp);
    }
    
    /* Check for Xposed log */
    if (access("/data/data/de.robv.android.xposed.installer/log", F_OK) == 0) {
        GT_LOG_WARNING("Xposed framework detected: log found");
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("No Xposed framework detected");
    return GT_SUCCESS;
}

/**
 * Check for Frida on Android
 */
gt_result_t gt_detect_android_frida(void) {
    GT_LOG_DEBUG("Checking for Frida");
    
    /* Check for Frida server */
    GT_STEALTH_STRING(s_frida_srv, "\x33\xD8\x3C\xCE\x34\x87\x26\xCF\x27\xDC\x30\xD8", 12); // frida-server
    char frida_path[256];
    snprintf(frida_path, sizeof(frida_path), "/data/local/tmp/%s", s_frida_srv);
    if (access(frida_path, F_OK) == 0) {
        GT_LOG_WARNING("Frida detected: server binary found");
        return GT_ERROR_GENERIC;
    }
    
    /* Check for Frida in running processes */
    GT_STEALTH_STRING(s_proc, "\x7A\xDA\x27\xC5\x36", 5); // /proc
    DIR *proc_dir = opendir(s_proc);
    if (proc_dir) {
        struct dirent *entry;
        while ((entry = readdir(proc_dir)) != NULL) {
            if (strspn(entry->d_name, "0123456789") == strlen(entry->d_name)) {
                char cmdline_path[256];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
                
                FILE *fp = fopen(cmdline_path, "r");
                if (fp) {
                    char cmdline[256];
                    if (fgets(cmdline, sizeof(cmdline), fp)) {
                        GT_STEALTH_STRING(s_frida, "\x33\xD8\x3C\xCE\x34", 5); // frida
                        /* C: 其他调试服务器——lldb-server/gdbserver（Android 官方调试服务器）
                           / android_server（IDA 调试服务器，64 位版名含该子串） */
                        GT_STEALTH_STRING(s_lldbsrv, "\x39\xC6\x31\xC8\x78\xD9\x30\xD8\x23\xCF\x27", 11); // lldb-server
                        GT_STEALTH_STRING(s_gdbsrv, "\x32\xCE\x37\xD9\x30\xD8\x23\xCF\x27", 9);          // gdbserver
                        GT_STEALTH_STRING(s_ida_srv, "\x34\xC4\x31\xD8\x3A\xC3\x31\xF5\x26\xCF\x27\xDC\x30\xD8", 14); // android_server
                        if (strstr(cmdline, s_frida) || strstr(cmdline, "gum-js-loop") ||
                            strstr(cmdline, s_lldbsrv) || strstr(cmdline, s_gdbsrv) ||
                            strstr(cmdline, s_ida_srv)) {
                            GT_LOG_WARNING("Debugger server detected in process: %s", cmdline);
                            fclose(fp);
                            closedir(proc_dir);
                            return GT_ERROR_GENERIC;
                        }
                    }
                    fclose(fp);
                }
            }
        }
        closedir(proc_dir);
    }
    
    /* Check for Frida libraries in memory */
    GT_STEALTH_STRING(s_maps, "\x7A\xDA\x27\xC5\x36\x85\x26\xCF\x39\xCC\x7A\xC7\x34\xDA\x26", 15); // /proc/self/maps
    FILE *fp = fopen(s_maps, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            GT_STEALTH_STRING(s_frida_lib, "\x33\xD8\x3C\xCE\x34", 5); // frida
            if (strstr(line, s_frida_lib) || strstr(line, "gum-js") || strstr(line, "frida-agent")) {
                GT_LOG_WARNING("Frida detected in memory maps");
                fclose(fp);
                return GT_ERROR_GENERIC;
            }
        }
        fclose(fp);
    }
    
    /* Check for Frida ports */
    GT_STEALTH_STRING(s_tcp, "\x7A\xDA\x27\xC5\x36\x85\x3B\xCF\x21\x85\x21\xC9\x25", 13); // /proc/net/tcp
    fp = fopen(s_tcp, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            /* Check for default Frida port 27042 (69A2 in hex) */
            if (strstr(line, ":69A2 ")) {
                GT_LOG_WARNING("Frida detected: default port 27042 in use");
                fclose(fp);
                return GT_ERROR_GENERIC;
            }
        }
        fclose(fp);
    }
    
    GT_LOG_DEBUG("No Frida detected");
    return GT_SUCCESS;
}

/**
 * Enhanced Android debugger detection
 */
gt_result_t gt_detect_debugger_android(gt_detection_result_t *result) {
    if (!result) {
        return GT_ERROR_GENERIC;
    }
    
    memset(result, 0, sizeof(gt_detection_result_t));
    result->detection_type = GT_DETECTION_DEBUGGER;
    strcpy(result->details, "No threats detected");
    
    /* Check for emulator */
    if (gt_detect_android_emulator() != GT_SUCCESS) {
        result->detection_type = GT_DETECTION_EMULATOR;
        result->confidence = 90;
        strcpy(result->details, "Android emulator environment detected");
        return GT_ERROR_EMULATOR_DETECTED;
    }
    
    /* Check for root */
    if (gt_detect_android_root() != GT_SUCCESS) {
        result->confidence = 80;
        strcpy(result->details, "Android root access detected");
        return GT_ERROR_GENERIC;
    }
    
    /* Check for Xposed */
    if (gt_detect_android_xposed() != GT_SUCCESS) {
        result->confidence = 85;
        strcpy(result->details, "Xposed framework detected");
        return GT_ERROR_GENERIC;
    }
    
    /* Check for Frida */
    if (gt_detect_android_frida() != GT_SUCCESS) {
        result->confidence = 95;
        strcpy(result->details, "Frida dynamic instrumentation detected");
        return GT_ERROR_GENERIC;
    }
    
    /* Use standard ptrace detection */
    if (gt_detect_ptrace() != GT_SUCCESS) {
        result->confidence = 90;
        strcpy(result->details, "ptrace-based debugger detected");
        return GT_ERROR_DEBUGGER_DETECTED;
    }
    
    return GT_SUCCESS;
}

/**
 * JNI wrapper for Java integration
 */
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jboolean JNICALL
Java_com_ghosttrace_CoreGuard_init(JNIEnv *env, jobject thiz, jint detection_flags, jint action, jboolean stealth) {
    gt_config_t config = {0};
    config.detection_flags = (gt_detection_flags_t)detection_flags;
    config.countermeasure_action = (gt_action_t)action;
    config.stealth_mode = stealth ? 1 : 0;
    config.verbose_logging = stealth ? 0 : 1;
    
    return (gt_init(&config) == GT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_ghosttrace_CoreGuard_cleanup(JNIEnv *env, jobject thiz) {
    gt_cleanup();
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttrace_CoreGuard_detectDebugger(JNIEnv *env, jobject thiz) {
    gt_detection_result_t result;
    return (gt_detect_debugger_android(&result) != GT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttrace_CoreGuard_detectEmulator(JNIEnv *env, jobject thiz) {
    return (gt_detect_android_emulator() != GT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttrace_CoreGuard_detectRoot(JNIEnv *env, jobject thiz) {
    return (gt_detect_android_root() != GT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttrace_CoreGuard_detectXposed(JNIEnv *env, jobject thiz) {
    return (gt_detect_android_xposed() != GT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttrace_CoreGuard_detectFrida(JNIEnv *env, jobject thiz) {
    return (gt_detect_android_frida() != GT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_ANDROID */

