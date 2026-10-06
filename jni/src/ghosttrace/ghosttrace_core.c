/**
 * CoreGuard Core Implementation
 * 
 * Core functionality and utility functions for the CoreGuard toolkit.
 * This file contains the main initialization, configuration management,
 * and utility functions used throughout the toolkit.
 */

#define _GNU_SOURCE
#include "ghosttrace.h"
#include <stdarg.h>
#include <time.h>

#if PLATFORM_MACOS
#include <libproc.h>
#include <sys/sysctl.h>
#endif

/* Global configuration */
static gt_config_t g_config = {0};
static int g_initialized = 0;
static FILE *g_log_file = NULL;
static gt_detection_callback_t g_detection_callback = NULL;
static void *g_callback_user_data = NULL;

/* Platform detection */
static const char* get_platform_name(void) {
#if PLATFORM_MACOS
    return "macOS";
#elif PLATFORM_LINUX
    return "Linux";
#elif PLATFORM_WINDOWS
    return "Windows";
#elif PLATFORM_ANDROID
    return "Android";
#else
    return "Unknown";
#endif
}

static const char* get_architecture_name(void) {
#if ARCH_X86_64
    return "x86_64";
#elif ARCH_ARM64
    return "ARM64";
#else
    return "Unknown";
#endif
}

/* Error message mapping */
const char* gt_get_error_message(gt_result_t result) {
    switch (result) {
        case GT_SUCCESS:
            return "Success";
        case GT_ERROR_GENERIC:
            return "Generic error";
        case GT_ERROR_DEBUGGER_DETECTED:
            return "Debugger detected";
        case GT_ERROR_MEMORY_PROTECTION_FAILED:
            return "Memory protection failed";
        case GT_ERROR_BREAKPOINT_DETECTED:
            return "Breakpoint detected";
        case GT_ERROR_SANDBOX_DETECTED:
            return "Sandbox environment detected";
        case GT_ERROR_EMULATOR_DETECTED:
            return "Emulator environment detected";
        case GT_ERROR_UNSUPPORTED_PLATFORM:
            return "Unsupported platform";
        default:
            return "Unknown error";
    }
}

/* Logging functionality */
void gt_log(int level, const char *format, ...) {
    if (!g_initialized && level > 0) {
        return; /* Only log errors if not initialized */
    }
    
    if (!g_config.verbose_logging && level > 1) {
        return; /* Skip debug/info messages if verbose logging disabled */
    }
    
    va_list args;
    va_start(args, format);
    
    /* Get current timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Determine log level string */
    const char *level_str;
    switch (level) {
        case 0: level_str = "ERROR"; break;
        case 1: level_str = "WARN"; break;
        case 2: level_str = "INFO"; break;
        case 3: level_str = "DEBUG"; break;
        default: level_str = "UNKNOWN"; break;
    }
    
    /* Log to file if configured */
    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%s] ", timestamp, level_str);
        vfprintf(g_log_file, format, args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }
    
    /* Also log to stderr for errors and warnings, or if no log file */
    if (level <= 1 || !g_log_file) {
        fprintf(stderr, "[%s] [%s] ", timestamp, level_str);
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
    }
    
    va_end(args);
}

/* Configuration management */
GT_API gt_result_t gt_init(const gt_config_t *config) {
    if (g_initialized) {
        GT_LOG_WARNING("CoreGuard already initialized");
        return GT_SUCCESS;
    }
    
    /* Set default configuration if none provided */
    if (config) {
        memcpy(&g_config, config, sizeof(gt_config_t));
    } else {
        /* Default configuration */
        g_config.detection_flags = GT_DETECT_ALL;
        g_config.enable_memory_protection = 1;
        g_config.enable_self_deletion = 0;
        g_config.enable_process_hollowing = 0;
        g_config.stealth_mode = 0;
        g_config.verbose_logging = 0;
        strcpy(g_config.log_file, "");
    }
    
    /* Open log file if specified */
    if (strlen(g_config.log_file) > 0) {
        g_log_file = fopen(g_config.log_file, "a");
        if (!g_log_file) {
            fprintf(stderr, "Warning: Could not open log file %s\n", g_config.log_file);
        }
    }
    
    g_initialized = 1;
    
    if (!g_config.stealth_mode) {
        GT_LOG_INFO("CoreGuard v%s initialized on %s %s", 
                    GHOSTTRACE_VERSION, get_platform_name(), get_architecture_name());
        GT_LOG_DEBUG("Detection flags: 0x%02X", g_config.detection_flags);
        GT_LOG_DEBUG("Memory protection: %s", g_config.enable_memory_protection ? "enabled" : "disabled");
        GT_LOG_DEBUG("Stealth mode: %s", g_config.stealth_mode ? "enabled" : "disabled");
    }
    
    return GT_SUCCESS;
}

GT_API gt_result_t gt_cleanup(void) {
    if (!g_initialized) {
        return GT_SUCCESS;
    }
    
    if (!g_config.stealth_mode) {
        GT_LOG_INFO("Shutting down CoreGuard");
    }
    
    /* Close log file */
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    /* Reset global state */
    memset(&g_config, 0, sizeof(gt_config_t));
    g_detection_callback = NULL;
    g_callback_user_data = NULL;
    g_initialized = 0;
    
    return GT_SUCCESS;
}

GT_API void gt_execute_countermeasure(const gt_detection_result_t *result) {
    if (!g_initialized) return;
    
    gt_action_t action = g_config.countermeasure_action;
    if (action == GT_ACTION_NONE) return;
    
    GT_LOG_ERROR("Executing countermeasure action %d for threat: %s", action, result ? result->details : "Unknown");
    
    switch (action) {
        case GT_ACTION_LOG:
            /* Already logged above */
            break;
            
        case GT_ACTION_EXIT:
            GT_LOG_ERROR("Terminating process due to security threat");
            exit(1);
            break;
            
        case GT_ACTION_SELF_DELETE:
            GT_LOG_ERROR("Initiating self-destruction");
            gt_self_delete();
            exit(1);
            break;
            
        case GT_ACTION_CORRUPT_MEMORY:
            GT_LOG_ERROR("Corrupting memory to prevent analysis");
            /* Overwrite some critical regions or simply crash with invalid access */
            {
                volatile char *p = (char *)0x12345678;
                *p = 0;
            }
            break;
            
        case GT_ACTION_INFINITE_LOOP:
            GT_LOG_ERROR("Entering infinite loop to stall analysis");
            while(1) {
                usleep(100000);
            }
            break;
            
        default:
            break;
    }
}

gt_result_t gt_get_config(gt_config_t *config) {
    if (!config) {
        return GT_ERROR_GENERIC;
    }
    
    if (!g_initialized) {
        return GT_ERROR_GENERIC;
    }
    
    memcpy(config, &g_config, sizeof(gt_config_t));
    return GT_SUCCESS;
}

gt_result_t gt_set_config(const gt_config_t *config) {
    if (!config) {
        return GT_ERROR_GENERIC;
    }
    
    if (!g_initialized) {
        return GT_ERROR_GENERIC;
    }
    
    /* Close existing log file if changing */
    if (strcmp(g_config.log_file, config->log_file) != 0) {
        if (g_log_file) {
            fclose(g_log_file);
            g_log_file = NULL;
        }
        
        /* Open new log file if specified */
        if (strlen(config->log_file) > 0) {
            g_log_file = fopen(config->log_file, "a");
            if (!g_log_file) {
                GT_LOG_ERROR("Could not open log file %s", config->log_file);
            }
        }
    }
    
    memcpy(&g_config, config, sizeof(gt_config_t));
    
    GT_LOG_INFO("Configuration updated");
    return GT_SUCCESS;
}

/* Utility functions */
gt_result_t gt_set_verbose_logging(int enable) {
    if (!g_initialized) {
        return GT_ERROR_GENERIC;
    }
    
    g_config.verbose_logging = enable ? 1 : 0;
    GT_LOG_INFO("Verbose logging %s", enable ? "enabled" : "disabled");
    
    return GT_SUCCESS;
}

gt_result_t gt_get_platform_info(char *platform_name, char *arch_name, size_t name_size) {
    if (!platform_name || !arch_name || name_size == 0) {
        return GT_ERROR_GENERIC;
    }
    
    strncpy(platform_name, get_platform_name(), name_size - 1);
    platform_name[name_size - 1] = '\0';
    
    strncpy(arch_name, get_architecture_name(), name_size - 1);
    arch_name[name_size - 1] = '\0';
    
    return GT_SUCCESS;
}

/* Stealth mode functions */
gt_result_t gt_enable_stealth_mode(void) {
    if (!g_initialized) {
        return GT_ERROR_GENERIC;
    }
    
    g_config.stealth_mode = 1;
    g_config.verbose_logging = 0; /* Disable verbose logging in stealth mode */
    
    /* Close log file in stealth mode */
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    return GT_SUCCESS;
}

gt_result_t gt_disable_stealth_mode(void) {
    if (!g_initialized) {
        return GT_ERROR_GENERIC;
    }
    
    g_config.stealth_mode = 0;
    
    /* Reopen log file if configured */
    if (strlen(g_config.log_file) > 0) {
        g_log_file = fopen(g_config.log_file, "a");
    }
    
    GT_LOG_INFO("Stealth mode disabled");
    return GT_SUCCESS;
}

int gt_is_stealth_mode(void) {
    return g_initialized ? g_config.stealth_mode : 0;
}

/* Stealth string deobfuscation utility */
void gt_stealth_deobfuscate_string(const unsigned char *input, size_t length, char *output) {
    if (!input || !output || length == 0) return;
    
    unsigned char key = 0x55; /* Static XOR key for strings */
    for (size_t i = 0; i < length; i++) {
        output[i] = (char)(input[i] ^ key);
        key = (unsigned char)((key << 1) | (key >> 7)); /* Rotate key */
    }
    output[length] = '\0';
}

/* Callback management */
gt_result_t gt_set_detection_callback(gt_detection_callback_t callback, void *user_data) {
    if (!g_initialized) {
        return GT_ERROR_GENERIC;
    }
    
    g_detection_callback = callback;
    g_callback_user_data = user_data;
    
    GT_LOG_DEBUG("Detection callback %s", callback ? "set" : "cleared");
    return GT_SUCCESS;
}

/* Internal function to trigger callback */
void gt_trigger_detection_callback(const gt_detection_result_t *result) {
    if (g_detection_callback && result) {
        g_detection_callback(result, g_callback_user_data);
    }
}