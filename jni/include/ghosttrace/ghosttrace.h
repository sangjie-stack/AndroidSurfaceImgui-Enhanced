/**
 * CoreGuard - Lightweight Anti-Debugger & Memory Trap Toolkit
 * 
 * A comprehensive toolkit implementing modern and legacy anti-debugging,
 * anti-memory dumping, and dynamic analysis environment detection techniques
 * for both macOS and Linux platforms.
 * 
 * Features:
 * - Active debugger detection (ptrace, sysctl, task_info, mach_port on macOS)
 * - Anti-dumping: runtime memory page protection (mprotect)
 * - Self-deletion and process hollowing techniques (Linux)
 * - Hardware/software breakpoint detection and evasion
 * - Cross-platform support (x86_64 and ARM64)
 * - Stealth mode: library (.so/.dylib) or standalone binary
 * 
 * Author: CoreGuard Development Team
 * License: MIT
 * Version: 1.0.0
 */

#ifndef GHOSTTRACE_H
#define GHOSTTRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

/* Visibility attributes for stealth */
#if defined(__GNUC__) || defined(__clang__)
    #define GT_API __attribute__((visibility("default")))
    #define GT_INTERNAL __attribute__((visibility("hidden")))
#else
    #define GT_API
    #define GT_INTERNAL
#endif

/* Default platform definitions */
#ifndef PLATFORM_WINDOWS
#define PLATFORM_WINDOWS 0
#endif
#ifndef PLATFORM_MACOS
#define PLATFORM_MACOS 0
#endif
#ifndef PLATFORM_LINUX
#define PLATFORM_LINUX 0
#endif
#ifndef PLATFORM_ANDROID
#define PLATFORM_ANDROID 0
#endif
#ifndef PLATFORM_IOS
#define PLATFORM_IOS 0
#endif

/* Check for explicit platform flags first */
#if PLATFORM_WINDOWS == 1
    #include <windows.h>
    #include <winternl.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #define PLATFORM_WINDOWS 1
    #define PLATFORM_LINUX 0
    #define PLATFORM_MACOS 0
    #define PLATFORM_ANDROID 0
    #define PLATFORM_IOS 0
#elif PLATFORM_MACOS == 1
    #include <sys/sysctl.h>
    #include <sys/ptrace.h>
    #include <mach/mach.h>
    #include <mach/task.h>
    #include <mach/mach_init.h>
    #include <mach/task_info.h>
    #include <mach/vm_map.h>
    #include <libproc.h>
    #define PLATFORM_MACOS 1
    #define PLATFORM_IOS 0
    #define PLATFORM_LINUX 0
    #define PLATFORM_WINDOWS 0
    #define PLATFORM_ANDROID 0
#elif PLATFORM_LINUX == 1
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <sys/prctl.h>
    #include <sys/mman.h>
    #include <linux/limits.h>
    #define PLATFORM_LINUX 1
    #define PLATFORM_MACOS 0
    #define PLATFORM_WINDOWS 0
    #define PLATFORM_ANDROID 0
    #define PLATFORM_IOS 0
#elif PLATFORM_ANDROID == 1
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <sys/prctl.h>
    #include <sys/mman.h>
    #include <linux/limits.h>
    #include <android/log.h>
    #include <jni.h>
    #define PLATFORM_ANDROID 1
    #define PLATFORM_LINUX 0
    #define PLATFORM_MACOS 0
    #define PLATFORM_WINDOWS 0
    #define PLATFORM_IOS 0
#elif PLATFORM_IOS == 1
    #include <sys/sysctl.h>
    #include <sys/ptrace.h>
    #include <mach/mach.h>
    #include <mach/task.h>
    #include <mach/mach_init.h>
    #include <mach/task_info.h>
    #include <mach/vm_map.h>
    #include <libproc.h>
    #include <Foundation/Foundation.h>
    #include <UIKit/UIKit.h>
    #define PLATFORM_IOS 1
    #define PLATFORM_MACOS 0
    #define PLATFORM_LINUX 0
    #define PLATFORM_WINDOWS 0
    #define PLATFORM_ANDROID 0
/* Fallback to auto-detection if no explicit flags */
#elif defined(_WIN32)
    #include <windows.h>
    #include <winternl.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #define PLATFORM_WINDOWS 1
    #define PLATFORM_LINUX 0
    #define PLATFORM_MACOS 0
    #define PLATFORM_ANDROID 0
    #define PLATFORM_IOS 0
#elif defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IOS
        #include <sys/sysctl.h>
        #include <sys/ptrace.h>
        #include <mach/mach.h>
        #include <mach/task.h>
        #include <mach/mach_init.h>
        #include <mach/task_info.h>
        #include <mach/vm_map.h>
        #include <libproc.h>
        #include <Foundation/Foundation.h>
        #include <UIKit/UIKit.h>
        #define PLATFORM_IOS 1
        #define PLATFORM_MACOS 0
        #define PLATFORM_LINUX 0
        #define PLATFORM_WINDOWS 0
        #define PLATFORM_ANDROID 0
    #else
        #include <sys/sysctl.h>
        #include <sys/ptrace.h>
        #include <mach/mach.h>
        #include <mach/task.h>
        #include <mach/mach_init.h>
        #include <mach/task_info.h>
        #include <mach/vm_map.h>
        #include <libproc.h>
        #define PLATFORM_MACOS 1
        #define PLATFORM_IOS 0
        #define PLATFORM_LINUX 0
        #define PLATFORM_WINDOWS 0
        #define PLATFORM_ANDROID 0
    #endif
#elif defined(__ANDROID__)
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <sys/prctl.h>
    #include <sys/mman.h>
    #include <linux/limits.h>
    #include <android/log.h>
    #include <jni.h>
    #define PLATFORM_ANDROID 1
    #define PLATFORM_LINUX 0
    #define PLATFORM_MACOS 0
    #define PLATFORM_WINDOWS 0
    #define PLATFORM_IOS 0
#elif defined(__linux__)
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <sys/prctl.h>
    #include <sys/mman.h>
    #include <linux/limits.h>
    #define PLATFORM_LINUX 1
    #define PLATFORM_MACOS 0
    #define PLATFORM_WINDOWS 0
    #define PLATFORM_ANDROID 0
    #define PLATFORM_IOS 0
#else
    #error "Unsupported platform"
#endif

#ifdef __x86_64__
    #define ARCH_X86_64 1
#elif __aarch64__
    #define ARCH_ARM64 1
#endif

/* Configuration and feature flags */
#define GHOSTTRACE_VERSION "1.0.0"
#define MAX_PROCESS_NAME 256
#define MAX_PATH_LENGTH 4096
#define MEMORY_TRAP_SIZE 4096

/* Return codes */
typedef enum {
    GT_SUCCESS = 0,
    GT_ERROR_GENERIC = -1,
    GT_ERROR_DEBUGGER_DETECTED = -2,
    GT_ERROR_MEMORY_PROTECTION_FAILED = -3,
    GT_ERROR_BREAKPOINT_DETECTED = -4,
    GT_ERROR_SANDBOX_DETECTED = -5,
    GT_ERROR_EMULATOR_DETECTED = -6,
    GT_ERROR_UNSUPPORTED_PLATFORM = -7,
    GT_ERROR_NOT_INITIALIZED = -8,
    GT_ERROR_INSUFFICIENT_PRIVILEGES = -9,
    GT_ERROR_PRIVILEGE_ESCALATION_FAILED = -10,
    GT_ERROR_PRIVILEGE_DROP_FAILED = -11,
    GT_ERROR_CAPABILITY_RESTRICTED = -12,
    GT_ERROR_USER_DENIED = -13,
    GT_ERROR_INVALID_PARAMETER = -14,
    GT_ERROR_INVALID_CONFIGURATION = -15,
    GT_ERROR_CONFLICTING_CAPABILITIES = -16,
    GT_ERROR_BUFFER_TOO_SMALL = -17,
    GT_ERROR_NETWORK_DEBUGGER_DETECTED = -18,
    GT_ERROR_DEBUGGER_FILE_DETECTED = -19,
    GT_ERROR_NETWORK_ACCESS_FAILED = -20,
    GT_ERROR_NETWORK_FILTER_FAILED = -21,
    GT_ERROR_FILESYSTEM_MONITOR_FAILED = -22,
    GT_ERROR_HARDWARE_ACCESS_FAILED = -23,
    GT_ERROR_JAILBREAK_DETECTED = -24,
    GT_ERROR_FRIDA_DETECTED = -25,
    GT_ERROR_DEBUG_REGISTER_MONITOR_FAILED = -26,
    GT_ERROR_NETWORK_MONITOR_FAILED = -27,
    GT_ERROR_PROCESS_ACCESS_DENIED = -28,
    GT_ERROR_PROCESS_TERMINATION_FAILED = -29,
    GT_ERROR_THREAD_CREATION_FAILED = -30,
    GT_ERROR_NOT_IMPLEMENTED = -31
} gt_result_t;

/* Detection flags */
typedef enum {
    GT_DETECT_NONE = 0x00,
    GT_DETECT_PTRACE = 0x01,
    GT_DETECT_SYSCTL = 0x02,
    GT_DETECT_TASK_INFO = 0x04,
    GT_DETECT_MACH_PORT = 0x08,
    GT_DETECT_BREAKPOINTS = 0x10,
    GT_DETECT_SANDBOX = 0x20,
    GT_DETECT_EMULATOR = 0x40,
    GT_DETECT_ALL = 0xFF
} gt_detection_flags_t;

/* Detection types for results */
typedef enum {
    GT_DETECTION_DEBUGGER = 1,
    GT_DETECTION_SANDBOX = 2,
    GT_DETECTION_EMULATOR = 3,
    GT_DETECTION_BREAKPOINT = 4,
    GT_DETECTION_MEMORY_TAMPERING = 5,
    GT_DETECTION_ROOT_JAILBREAK = 6
} gt_detection_type_t;

/* Countermeasure types */
typedef enum {
    GT_ACTION_NONE = 0,
    GT_ACTION_LOG = 1,
    GT_ACTION_EXIT = 2,
    GT_ACTION_SELF_DELETE = 3,
    GT_ACTION_CORRUPT_MEMORY = 4,
    GT_ACTION_INFINITE_LOOP = 5
} gt_action_t;

/* Configuration structure */
typedef struct {
    gt_detection_flags_t detection_flags;
    int enable_memory_protection;
    int enable_self_deletion;
    int enable_process_hollowing;
    int stealth_mode;
    int verbose_logging;
    char log_file[MAX_PATH_LENGTH];
    gt_action_t countermeasure_action; /* Action to take on detection */
} gt_config_t;

/* Memory protection structure */
typedef struct {
    void *address;
    size_t size;
    int original_protection;
    int is_protected;
} gt_memory_region_t;

/* Process information structure */
typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[MAX_PROCESS_NAME];
    char path[MAX_PATH_LENGTH];
    int is_debugged;
    int is_traced;
} gt_process_info_t;

/* Debugger detection structure */
typedef struct {
    gt_detection_type_t detection_type;
    int confidence;
    char details[256];
    int ptrace_detected;
    int sysctl_detected;
    int task_info_detected;
    int mach_port_detected;
    int breakpoint_detected;
    int sandbox_detected;
    int emulator_detected;
    char detected_debugger[MAX_PROCESS_NAME];
} gt_detection_result_t;

/* Core API Functions */

/**
 * Initialize CoreGuard with specified configuration
 * @param config Configuration structure
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_init(const gt_config_t *config);

/**
 * Execute configured countermeasure
 * @param result Detection result that triggered the action
 */
GT_API void gt_execute_countermeasure(const gt_detection_result_t *result);

/**
 * Cleanup and shutdown CoreGuard
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_cleanup(void);

/**
 * Get current configuration
 * @param config Pointer to store current configuration
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_get_config(gt_config_t *config);

/**
 * Update configuration
 * @param config New configuration
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_set_config(const gt_config_t *config);

/* Debugger Detection Functions */

/**
 * Perform comprehensive debugger detection
 * @param result Pointer to store detection results
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_debugger(gt_detection_result_t *result);

/**
 * Check for ptrace-based debuggers
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_ptrace(void);

/**
 * Check for debuggers using sysctl (macOS)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_sysctl(void);

/**
 * Check for debuggers using task_info (macOS)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_task_info(void);

/**
 * Check for debuggers using mach_port (macOS)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_mach_port(void);

/**
 * Detect network debuggers by checking listening ports
 * @return GT_SUCCESS if no network debuggers found, error code if found
 */
GT_API gt_result_t gt_detect_network_debugger(void);

/**
 * Detect sandbox environments
 * @return GT_SUCCESS if no sandbox detected, GT_ERROR_SANDBOX_DETECTED if found
 */
GT_API gt_result_t gt_detect_sandbox(void);

/**
 * Detect emulator environments
 * @return GT_SUCCESS if no emulator detected, GT_ERROR_EMULATOR_DETECTED if found
 */
GT_API gt_result_t gt_detect_emulator(void);

/* Windows-specific Detection Functions */
#if PLATFORM_WINDOWS == 1
/**
 * Check for debuggers using IsDebuggerPresent (Windows)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_is_debugger_present(void);

/**
 * Check for remote debuggers using CheckRemoteDebuggerPresent (Windows)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_remote_debugger(void);

/**
 * Check for debuggers using NtQueryInformationProcess (Windows)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_nt_query_information(void);

/**
 * Check for debuggers using PEB flags (Windows)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_peb_flags(void);

/**
 * Check for debuggers using heap flags (Windows)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_heap_flags(void);

/**
 * Check for debuggers using ETW Monitoring (Windows)
 * @return GT_SUCCESS if no debugger detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_detect_etw_monitoring(void);
#endif

/* Android-specific Detection Functions */
#if PLATFORM_ANDROID
/**
 * Check for Android emulator environment
 * @return GT_SUCCESS if no emulator detected, GT_ERROR_EMULATOR_DETECTED if found
 */
GT_API gt_result_t gt_detect_android_emulator(void);

/**
 * Check for root detection on Android
 * @return GT_SUCCESS if no root detected, GT_ERROR_GENERIC if found
 */
GT_API gt_result_t gt_detect_android_root(void);

/**
 * Check for Xposed framework on Android
 * @return GT_SUCCESS if no Xposed detected, GT_ERROR_GENERIC if found
 */
GT_API gt_result_t gt_detect_android_xposed(void);

/**
 * Check for Frida on Android
 * @return GT_SUCCESS if no Frida detected, GT_ERROR_GENERIC if found
 */
GT_API gt_result_t gt_detect_android_frida(void);
#endif

/* Memory Protection Functions */

/**
 * Protect memory region from dumping
 * @param address Start address of memory region
 * @param size Size of memory region
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_protect_memory(void *address, size_t size);

/**
 * Unprotect previously protected memory region
 * @param address Start address of memory region
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_unprotect_memory(void *address);

/**
 * Create memory trap that triggers on access
 * @param address Address to create trap at
 * @param size Size of trap region
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_create_memory_trap(void *address, size_t size);

/**
 * Remove memory trap
 * @param address Address of trap to remove
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_remove_memory_trap(void *address);

/**
 * Obfuscate memory region using XOR
 * @param address Address to obfuscate
 * @param size Size of region to obfuscate
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_obfuscate_memory(void *address, size_t size);

/**
 * Deobfuscate memory region
 * @param address Address to deobfuscate
 * @param size Size of region to deobfuscate
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_deobfuscate_memory(void *address, size_t size);

/**
 * Enable advanced anti-dumping protection
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_enable_anti_dumping(void);

/**
 * Disable anti-dumping protection
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_disable_anti_dumping(void);

/* Breakpoint Detection Functions */

/**
 * Detect software breakpoints (INT3)
 * @param address Address to check
 * @param size Size of region to check
 * @return GT_SUCCESS if no breakpoints found, GT_ERROR_BREAKPOINT_DETECTED if found
 */
GT_API gt_result_t gt_detect_software_breakpoints(void *address, size_t size);

/**
 * Detect hardware breakpoints (DR registers)
 * @return GT_SUCCESS if no breakpoints found, GT_ERROR_BREAKPOINT_DETECTED if found
 */
GT_API gt_result_t gt_detect_hardware_breakpoints(void);

/**
 * Clear detected breakpoints
 * @param address Address of breakpoint to clear
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_clear_breakpoint(void *address);

/* Process Manipulation Functions */

/**
 * Perform self-deletion (Linux only)
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_self_delete(void);

/**
 * Perform process hollowing
 * @param target_path Path to target process
 * @param payload_data Payload data to inject
 * @param payload_size Size of payload
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_process_hollowing(const char *target_path, const void *payload_data, size_t payload_size);

/**
 * Get current process information
 * @param info Pointer to store process information
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_get_process_info(gt_process_info_t *info);

/**
 * Monitor process integrity for injection attempts
 * @return GT_SUCCESS if no injection detected, GT_ERROR_DEBUGGER_DETECTED if found
 */
GT_API gt_result_t gt_monitor_process_integrity(void);

/**
 * Enable anti-injection protection
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_enable_anti_injection(void);

/**
 * Disable anti-injection protection
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_disable_anti_injection(void);

/**
 * Check if process is being traced
 * @return GT_SUCCESS if not traced, GT_ERROR_DEBUGGER_DETECTED if traced
 */
GT_API gt_result_t gt_check_trace_status(void);

/**
 * Obfuscate sensitive data region (Dynamic Memory Obfuscation)
 * @param address Data to obfuscate
 * @param size Size of data
 * @return GT_SUCCESS on success
 */
GT_API gt_result_t gt_memory_obfuscate_dynamic(void *address, size_t size);

/**
 * Access obfuscated data (temporarily deobfuscates)
 * @param address Data to access
 * @param size Size of data
 * @param callback Callback to use the deobfuscated data
 * @param user_data User data for callback
 * @return GT_SUCCESS on success
 */
typedef void (*gt_memory_access_cb_t)(void *deobfuscated_data, size_t size, void *user_data);
GT_API gt_result_t gt_memory_access_obfuscated(void *address, size_t size, gt_memory_access_cb_t callback, void *user_data);

/* Utility Functions */

/**
 * Get error message for result code
 * @param result Result code
 * @return Human-readable error message
 */
GT_API const char* gt_get_error_message(gt_result_t result);

/**
 * Enable or disable verbose logging
 * @param enable 1 to enable, 0 to disable
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_set_verbose_logging(int enable);

/**
 * Log message to configured log file or stdout
 * @param level Log level (0=error, 1=warning, 2=info, 3=debug)
 * @param format Printf-style format string
 * @param ... Format arguments
 */
GT_API void gt_log(int level, const char *format, ...);

/**
 * Get platform information
 * @param platform_name Buffer to store platform name
 * @param arch_name Buffer to store architecture name
 * @param name_size Size of name buffers
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_get_platform_info(char *platform_name, char *arch_name, size_t name_size);

/* Platform-specific Comprehensive Detection */
#if PLATFORM_WINDOWS
GT_API gt_result_t gt_detect_debugger_windows(gt_detection_result_t *result);
#elif PLATFORM_ANDROID
GT_API gt_result_t gt_detect_debugger_android(gt_detection_result_t *result);
#elif PLATFORM_IOS
GT_API gt_result_t gt_ios_comprehensive_security_check(void);
#endif

/* Stealth Mode Functions */

/**
 * Enable stealth mode (minimal footprint)
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_enable_stealth_mode(void);

/**
 * Disable stealth mode
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_disable_stealth_mode(void);

/**
 * Check if running in stealth mode
 * @return 1 if stealth mode enabled, 0 otherwise
 */
GT_API int gt_is_stealth_mode(void);

/**
 * Internal utility for string deobfuscation
 * @param input Obfuscated string
 * @param length Length of the string
 * @param output Buffer to store deobfuscated string
 */
GT_API void gt_stealth_deobfuscate_string(const unsigned char *input, size_t length, char *output);

/* Macros for stealth strings */
#define GT_STEALTH_STRING(name, data, len) \
    static char name[len + 1]; \
    do { \
        gt_stealth_deobfuscate_string((const unsigned char*)data, len, name); \
    } while(0)

/* Callback Functions */

/**
 * Callback function type for debugger detection
 * @param result Detection result
 * @param user_data User-provided data
 */
typedef void (*gt_detection_callback_t)(const gt_detection_result_t *result, void *user_data);

/**
 * Set callback for debugger detection events
 * @param callback Callback function
 * @param user_data User data to pass to callback
 * @return GT_SUCCESS on success, error code on failure
 */
GT_API gt_result_t gt_set_detection_callback(gt_detection_callback_t callback, void *user_data);

/* Macros for convenience */
#define GT_CHECK_RESULT(result) \
    do { \
        if ((result) != GT_SUCCESS) { \
            gt_log(0, "Error at %s:%d: %s", __FILE__, __LINE__, gt_get_error_message(result)); \
            return (result); \
        } \
    } while(0)

#define GT_LOG_DEBUG(fmt, ...) gt_log(3, "[DEBUG] " fmt, ##__VA_ARGS__)
#define GT_LOG_INFO(fmt, ...) gt_log(2, "[INFO] " fmt, ##__VA_ARGS__)
#define GT_LOG_WARNING(fmt, ...) gt_log(1, "[WARNING] " fmt, ##__VA_ARGS__)
#define GT_LOG_ERROR(fmt, ...) gt_log(0, "[ERROR] " fmt, ##__VA_ARGS__)

#endif /* GHOSTTRACE_H */

