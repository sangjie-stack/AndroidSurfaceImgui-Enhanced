/**
 * CoreGuard Debugger Detection Implementation
 * 
 * This file contains all debugger detection mechanisms for both macOS and Linux.
 * Implements various techniques to detect active debuggers, sandbox environments,
 * and emulated execution environments.
 */

#define _GNU_SOURCE
#include "ghosttrace.h"

#if PLATFORM_LINUX
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <sys/syscall.h>
#endif

#if PLATFORM_MACOS
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/task_info.h>
#include <mach/vm_map.h>
#include <libproc.h>
#include <ctype.h>
#include <time.h>
#include <sys/syscall.h>
#endif

/* Forward declarations for internal functions */
static int check_debugger_processes(void);
static int check_environment_variables(void);
static int check_timing_attacks(void);
static int check_vm_artifacts(void);

/* External callback trigger function */
extern void gt_trigger_detection_callback(const gt_detection_result_t *result);

/**
 * Comprehensive debugger detection orchestrator
 */
gt_result_t gt_detect_debugger(gt_detection_result_t *result) {
    if (!result) {
        return GT_ERROR_GENERIC;
    }
    
    /* Initialize result structure */
    memset(result, 0, sizeof(gt_detection_result_t));
    
    /* Initialize default values */
    result->detection_type = GT_DETECTION_DEBUGGER;
    result->confidence = 0;
    strcpy(result->details, "No threats detected");
    
    GT_LOG_DEBUG("Starting comprehensive debugger detection");
    
    /* Perform individual detection checks */
    if (gt_detect_ptrace() != GT_SUCCESS) {
        result->ptrace_detected = 1;
        result->confidence = 95;
        strcpy(result->details, "ptrace-based debugger detected");
        GT_LOG_WARNING("ptrace-based debugger detected");
    }
    
#if PLATFORM_MACOS
    if (gt_detect_sysctl() != GT_SUCCESS) {
        result->sysctl_detected = 1;
        result->confidence = 90;
        strcpy(result->details, "sysctl-based debugger detected (macOS)");
        GT_LOG_WARNING("sysctl-based debugger detected");
    }
    
    if (gt_detect_task_info() != GT_SUCCESS) {
        result->task_info_detected = 1;
        result->confidence = 85;
        strcpy(result->details, "task_info-based debugger detected (macOS)");
        GT_LOG_WARNING("task_info-based debugger detected");
    }
    
    if (gt_detect_mach_port() != GT_SUCCESS) {
        result->mach_port_detected = 1;
        result->confidence = 80;
        strcpy(result->details, "mach_port-based debugger detected (macOS)");
        GT_LOG_WARNING("mach_port-based debugger detected");
    }
#endif
    
    if (gt_detect_sandbox() != GT_SUCCESS) {
        result->sandbox_detected = 1;
        result->detection_type = GT_DETECTION_SANDBOX;
        result->confidence = 75;
        strcpy(result->details, "Sandbox environment detected");
        GT_LOG_WARNING("Sandbox environment detected");
    }
    
    if (gt_detect_emulator() != GT_SUCCESS) {
        result->emulator_detected = 1;
        result->detection_type = GT_DETECTION_EMULATOR;
        result->confidence = 70;
        strcpy(result->details, "Emulator environment detected");
        GT_LOG_WARNING("Emulator environment detected");
    }
    
    if (gt_detect_network_debugger() != GT_SUCCESS) {
        result->confidence = 80;
        strcpy(result->details, "Network debugger detected");
        GT_LOG_WARNING("Network debugger detected");
    }
    
#if PLATFORM_WINDOWS
    /* Windows-specific detection */
    if (gt_detect_debugger_windows(result) != GT_SUCCESS) {
        GT_LOG_WARNING("Windows debugger detected");
        gt_trigger_detection_callback(result);
        return GT_ERROR_DEBUGGER_DETECTED;
    }
#elif PLATFORM_ANDROID
    /* Android-specific detection */
    if (gt_detect_debugger_android(result) != GT_SUCCESS) {
        GT_LOG_WARNING("Android analysis tool detected");
        gt_trigger_detection_callback(result);
        return GT_ERROR_DEBUGGER_DETECTED;
    }
#elif PLATFORM_IOS
    /* iOS-specific detection */
    if (gt_ios_comprehensive_security_check() != GT_SUCCESS) {
        result->confidence = 90;
        strcpy(result->details, "iOS security threats detected");
        GT_LOG_WARNING("iOS security threats detected");
        gt_trigger_detection_callback(result);
        return GT_ERROR_DEBUGGER_DETECTED;
    }
#endif
    
    /* Check for any detection */
    int detected = result->ptrace_detected || result->sysctl_detected || 
                   result->task_info_detected || result->mach_port_detected ||
                   result->breakpoint_detected || result->sandbox_detected ||
                   result->emulator_detected;
    
    if (detected) {
        GT_LOG_ERROR("Debugger or analysis environment detected!");
        
        /* Trigger callback if set */
        gt_trigger_detection_callback(result);
        
        /* Execute configured countermeasure */
        gt_execute_countermeasure(result);
        
        return GT_ERROR_DEBUGGER_DETECTED;
    }
    
    GT_LOG_INFO("No debugger or analysis environment detected");
    return GT_SUCCESS;
}

/**
 * ptrace-based debugger detection
 * Works on both Linux and macOS
 */
/* L1.28: 守护进程 ptrace 占位 pid（anti_extra.cpp 提供，未启用返回 -1） */
extern int gt_guard_pid(void);

gt_result_t gt_detect_ptrace(void) {
    GT_LOG_DEBUG("Checking for ptrace-based debuggers");
    
#if PLATFORM_LINUX
    /* Method 1: Try to ptrace ourselves using direct syscall for stealth */
    /* L1.28: 守护进程 SEIZE 占位启用时跳过本探测——主进程已被跟踪，fork 的子进程会继承
       跟踪状态，其 TRACEME 触发 syscall-stop 卡死；占位本身已挡第三方 attach（EPERM）。 */
    if (gt_guard_pid() <= 0) {
    pid_t child = fork();
    if (child == 0) {
        /* Child process */
        if (syscall(SYS_ptrace, PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            /* L1.28: 守护进程 attach 后 fork 的子进程继承 ptrace 状态——TRACEME 必然失败。
               此时读自身 TracerPid：若 == 守护 pid → 继承自守护，放行（exit 0）。 */
            int tp = 0;
            const char* sp = "/proc/self/status";
            FILE* f = fopen(sp, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    if (strncmp(line, "TracerPid:", 10) == 0) { tp = atoi(line + 10); break; }
                }
                fclose(f);
            }
            if (tp == gt_guard_pid()) _exit(0);
            /* ptrace failed, likely already being traced */
            _exit(1);
        }
        _exit(0);
    } else if (child > 0) {
        /* Parent process */
        int status;
        waitpid(child, &status, 0);
        if (WEXITSTATUS(status) == 1) {
            GT_LOG_WARNING("ptrace detection: already being traced");
            return GT_ERROR_DEBUGGER_DETECTED;
        }
    }
    }
    
    /* Method 2: Check /proc/self/status for TracerPid */
    /* Deobfuscate /proc/self/status path for stealth */
    GT_STEALTH_STRING(s_proc_status, "\x2A\xCF\x2A\xCB\x2A\xD2\x20\xC7\x2B\xC3\x2E\xDE\x21\xC2\x31\xD2\x36\xD0", 18); // /proc/self/status
    FILE *status_file = fopen(s_proc_status, "r");
    if (status_file) {
        char line[256];
        /* Deobfuscate TracerPid key */
        GT_STEALTH_STRING(s_tracer_pid, "\x01\xD3\x24\xC8\x20\xD9\x15\xC2\x21", 9); // TracerPid
        while (fgets(line, sizeof(line), status_file)) {
            if (strncmp(line, s_tracer_pid, 9) == 0) {
                int tracer_pid = atoi(line + 10);
                fclose(status_file);
                /* L1.28 白名单：守护进程 ptrace 占位后 TracerPid 常态 = 守护 pid（非 0） */
                if (tracer_pid != 0 && tracer_pid != gt_guard_pid()) {
                    GT_LOG_WARNING("ptrace detection: TracerPid = %d", tracer_pid);
                    return GT_ERROR_DEBUGGER_DETECTED;
                }
                break;
            }
        }
        fclose(status_file);
    }
    
    /* Method 3: Check for debugger processes */
    if (check_debugger_processes()) {
        GT_LOG_WARNING("ptrace detection: debugger process found");
        return GT_ERROR_DEBUGGER_DETECTED;
    }
    
#elif PLATFORM_ANDROID
    /* Android ptrace detection - similar to Linux but with Android-specific checks */
    /* L1.28: 守护进程 SEIZE 占位启用时跳过本探测（同 Linux 分支理由） */
    if (gt_guard_pid() <= 0) {
    pid_t child = fork();
    if (child == 0) {
        /* Child process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            /* L1.28: 守护进程 attach 后 fork 的子进程继承 ptrace 状态——TRACEME 必然失败。
               此时读自身 TracerPid：若 == 守护 pid → 继承自守护，放行（exit 0）。 */
            int tp = 0;
            const char* sp = "/proc/self/status";
            FILE* f = fopen(sp, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    if (strncmp(line, "TracerPid:", 10) == 0) { tp = atoi(line + 10); break; }
                }
                fclose(f);
            }
            if (tp == gt_guard_pid()) _exit(0);
            /* ptrace failed, likely already being traced */
            _exit(1);
        }
        _exit(0);
    } else if (child > 0) {
        /* Parent process */
        int status;
        waitpid(child, &status, 0);
        if (WEXITSTATUS(status) == 1) {
            GT_LOG_WARNING("ptrace detection: already being traced");
            return GT_ERROR_DEBUGGER_DETECTED;
        }
    }
    }
    
#elif PLATFORM_MACOS
    /* macOS ptrace detection */
    /* PT_DENY_ATTACH might not be available on all macOS versions */
    #ifdef PT_DENY_ATTACH
    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
        GT_LOG_WARNING("ptrace detection: PT_DENY_ATTACH failed");
        return GT_ERROR_DEBUGGER_DETECTED;
    }
    #else
    /* Alternative method: try to trace ourselves */
    if (ptrace(PT_TRACE_ME, 0, 0, 0) == -1) {
        GT_LOG_WARNING("ptrace detection: PT_TRACE_ME failed");
        return GT_ERROR_DEBUGGER_DETECTED;
    }
    #endif
    
    /* Check for debugger processes on macOS */
    if (check_debugger_processes()) {
        GT_LOG_WARNING("ptrace detection: debugger process found");
        return GT_ERROR_DEBUGGER_DETECTED;
    }
#endif
    
    GT_LOG_DEBUG("ptrace detection: no debugger found");
    return GT_SUCCESS;
}

/**
 * sysctl-based debugger detection (macOS only)
 */
gt_result_t gt_detect_sysctl(void) {
#if PLATFORM_MACOS
    GT_LOG_DEBUG("Checking for debuggers using sysctl");
    
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    
    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == 0) {
        /* Check if P_TRACED flag is set */
        if (info.kp_proc.p_flag & P_TRACED) {
            GT_LOG_WARNING("sysctl detection: P_TRACED flag set");
            return GT_ERROR_DEBUGGER_DETECTED;
        }
    }
    
    GT_LOG_DEBUG("sysctl detection: no debugger found");
    return GT_SUCCESS;
#else
    GT_LOG_DEBUG("sysctl detection: not supported on this platform");
    return GT_SUCCESS;
#endif
}

/**
 * task_info-based debugger detection (macOS only)
 */
gt_result_t gt_detect_task_info(void) {
#if PLATFORM_MACOS
    GT_LOG_DEBUG("Checking for debuggers using task_info");
    
    /* Use task_basic_info to get basic task information */
    struct task_basic_info info;
    mach_msg_type_number_t info_count = TASK_BASIC_INFO_COUNT;
    
    kern_return_t kr = task_info(mach_task_self(), TASK_BASIC_INFO,
                                (task_info_t)&info, &info_count);
    
    if (kr == KERN_SUCCESS) {
        /* Check for unusual suspend count that might indicate debugging */
        if (info.suspend_count > 0) {
            GT_LOG_WARNING("task_info detection: suspicious suspend count: %d", info.suspend_count);
            return GT_ERROR_DEBUGGER_DETECTED;
        }
        
        /* Check for unusual virtual memory size patterns */
        if (info.virtual_size > 0x100000000ULL) { /* 4GB threshold */
            GT_LOG_DEBUG("task_info detection: large virtual memory size: %llu", info.virtual_size);
        }
    } else {
        GT_LOG_DEBUG("task_info failed with error: %d", kr);
    }
    
    GT_LOG_DEBUG("task_info detection: no debugger found");
    return GT_SUCCESS;
#else
    GT_LOG_DEBUG("task_info detection: not supported on this platform");
    return GT_SUCCESS;
#endif
}

/**
 * mach_port-based debugger detection (macOS only)
 */
gt_result_t gt_detect_mach_port(void) {
#if PLATFORM_MACOS
    GT_LOG_DEBUG("Checking for debuggers using mach_port");
    
    mach_port_t exception_port;
    exception_mask_t mask;
    mach_msg_type_number_t count = 1;
    exception_behavior_t behavior;
    thread_state_flavor_t flavor;
    
    kern_return_t kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL,
                                               &mask, &count, &exception_port,
                                               &behavior, &flavor);
    
    if (kr == KERN_SUCCESS && count > 0) {
        /* Check if exception port is set (might indicate debugger) */
        if (exception_port != MACH_PORT_NULL) {
            GT_LOG_WARNING("mach_port detection: exception port set");
            return GT_ERROR_DEBUGGER_DETECTED;
        }
    }
    
    GT_LOG_DEBUG("mach_port detection: no debugger found");
    return GT_SUCCESS;
#else
    GT_LOG_DEBUG("mach_port detection: not supported on this platform");
    return GT_SUCCESS;
#endif
}

/**
 * Detect network debuggers by checking common ports
 */
gt_result_t gt_detect_network_debugger(void) {
    GT_LOG_DEBUG("Checking for network debuggers");
    
    int ports[] = {
        23946, /* IDA Pro default */
        1234,  /* GDB default */
        5037,  /* ADB */
        27042, /* Frida default */
        0
    };
    
#if PLATFORM_LINUX || PLATFORM_ANDROID
    /* On Linux/Android, scan /proc/net/tcp */
    GT_STEALTH_STRING(s_tcp, "\x7A\xDA\x27\xC5\x36\x85\x3B\xCF\x21\x85\x21\xC9\x25", 13); // /proc/net/tcp
    FILE *fp = fopen(s_tcp, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            for (int i = 0; ports[i] != 0; i++) {
                char hex_port[8];
                snprintf(hex_port, sizeof(hex_port), ":%04X ", ports[i]);
                if (strstr(line, hex_port)) {
                    GT_LOG_WARNING("Network debugger port detected: %d", ports[i]);
                    fclose(fp);
                    return GT_ERROR_NETWORK_DEBUGGER_DETECTED;
                }
            }
        }
        fclose(fp);
    }
#endif

    GT_LOG_DEBUG("No network debuggers found");
    return GT_SUCCESS;
}

/**
 * Sandbox environment detection
 */
gt_result_t gt_detect_sandbox(void) {
    GT_LOG_DEBUG("Checking for sandbox environment");
    
    /* Check environment variables */
    if (check_environment_variables()) {
        GT_LOG_WARNING("Sandbox detection: suspicious environment variables");
        return GT_ERROR_SANDBOX_DETECTED;
    }
    
    /* Check timing attacks */
    if (check_timing_attacks()) {
        GT_LOG_WARNING("Sandbox detection: timing anomalies detected");
        return GT_ERROR_SANDBOX_DETECTED;
    }
    
#if PLATFORM_LINUX
    /* Check for sandbox-specific files */
    const char *sandbox_files[] = {
        "/proc/self/cgroup",
        "/proc/version",
        "/sys/class/dmi/id/product_name",
        NULL
    };
    
    for (int i = 0; sandbox_files[i]; i++) {
        FILE *f = fopen(sandbox_files[i], "r");
        if (f) {
            char buffer[256];
            if (fgets(buffer, sizeof(buffer), f)) {
                /* Check for sandbox indicators */
                if (strstr(buffer, "docker") || strstr(buffer, "lxc") ||
                    strstr(buffer, "sandbox") || strstr(buffer, "qemu") ||
                    strstr(buffer, "vmware") || strstr(buffer, "virtualbox")) {
                    fclose(f);
                    GT_LOG_WARNING("Sandbox detection: found in %s", sandbox_files[i]);
                    return GT_ERROR_SANDBOX_DETECTED;
                }
            }
            fclose(f);
        }
    }
#endif
    
    GT_LOG_DEBUG("Sandbox detection: no sandbox found");
    return GT_SUCCESS;
}

/**
 * Emulator environment detection
 */
gt_result_t gt_detect_emulator(void) {
    GT_LOG_DEBUG("Checking for emulator environment");
    
    /* Check for VM artifacts */
    if (check_vm_artifacts()) {
        GT_LOG_WARNING("Emulator detection: VM artifacts found");
        return GT_ERROR_EMULATOR_DETECTED;
    }
    
#if ARCH_X86_64
    /* Check CPUID for hypervisor bit */
    unsigned int eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1));
    
    if (ecx & (1 << 31)) {
        GT_LOG_WARNING("Emulator detection: hypervisor bit set in CPUID");
        return GT_ERROR_EMULATOR_DETECTED;
    }
    
    /* Check for VM vendor strings */
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(0x40000000));
    
    char vendor[13] = {0};
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    
    if (strstr(vendor, "VMware") || strstr(vendor, "VBoxVBox") ||
        strstr(vendor, "KVMKVMKVM") || strstr(vendor, "Microsoft Hv")) {
        GT_LOG_WARNING("Emulator detection: VM vendor string found: %s", vendor);
        return GT_ERROR_EMULATOR_DETECTED;
    }
#endif
    
    GT_LOG_DEBUG("Emulator detection: no emulator found");
    return GT_SUCCESS;
}

/* Internal helper functions */

/**
 * Check for known debugger processes
 */
static int check_debugger_processes(void) {
#if PLATFORM_LINUX
    GT_STEALTH_STRING(s_gdb, "\x32\xCE\x37", 3);
    GT_STEALTH_STRING(s_lldb, "\x39\xC6\x31\xC8", 4);
    GT_STEALTH_STRING(s_strace, "\x26\xDE\x27\xCB\x36\xCF", 6);
    GT_STEALTH_STRING(s_ltrace, "\x39\xDE\x27\xCB\x36\xCF", 6);
    GT_STEALTH_STRING(s_ida, "\x3C\xCE\x34", 3);
    GT_STEALTH_STRING(s_frida, "\x33\xD8\x3C\xCE\x34", 5);
    GT_STEALTH_STRING(s_x64dbg, "\x2D\x9C\x61\xCE\x37\xCD", 6);
    GT_STEALTH_STRING(s_r2, "\x27\x98", 2);
    GT_STEALTH_STRING(s_radare2, "\x27\xCB\x31\xCB\x27\xCF\x67", 7);

    const char *debugger_names[] = {
        s_gdb, s_lldb, s_strace, s_ltrace, s_ida, s_frida, s_x64dbg, s_r2, s_radare2,
        NULL
    };
    
    GT_STEALTH_STRING(s_proc, "\x7A\xDA\x27\xC5\x36", 5); // /proc
    DIR *proc_dir = opendir(s_proc);
    if (!proc_dir) return 0;
    
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        
        char comm_path[64];
        GT_STEALTH_STRING(s_proc_comm, "\x7A\xDA\x27\xC5\x36\x85\x70\xD9\x7A\xC9\x3A\xC7\x38", 13); // /proc/%s/comm
        snprintf(comm_path, sizeof(comm_path), s_proc_comm, entry->d_name);
        
        FILE *comm_file = fopen(comm_path, "r");
        if (comm_file) {
            char comm[256];
            if (fgets(comm, sizeof(comm), comm_file)) {
                /* Remove newline */
                char *newline = strchr(comm, '\n');
                if (newline) *newline = '\0';
                
                /* Check against known debugger names */
                for (int i = 0; debugger_names[i]; i++) {
                    if (strcmp(comm, debugger_names[i]) == 0) {
                        fclose(comm_file);
                        closedir(proc_dir);
                        return 1;
                    }
                }
            }
            fclose(comm_file);
        }
    }
    closedir(proc_dir);
#elif PLATFORM_MACOS
    /* macOS implementation using proc_listpids */
    int num_pids = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (num_pids <= 0) {
        GT_LOG_WARNING("Failed to get process count");
        return -1;
    }
    
    pid_t *pids = malloc(num_pids * sizeof(pid_t));
    if (!pids) {
        GT_LOG_ERROR("Failed to allocate memory for process list");
        return -1;
    }
    
    int actual_count = proc_listpids(PROC_ALL_PIDS, 0, pids, num_pids * sizeof(pid_t));
    if (actual_count <= 0) {
        GT_LOG_WARNING("Failed to get process list");
        free(pids);
        return -1;
    }
    
    int process_count = actual_count / sizeof(pid_t);
    GT_LOG_DEBUG("Scanning %d processes", process_count);
    
    /* Obfuscated debugger names for macOS */
    GT_STEALTH_STRING(s_lldb_mac, "\x39\xC6\x31\xC8", 4);
    GT_STEALTH_STRING(s_gdb_mac, "\x32\xCE\x37", 3);
    GT_STEALTH_STRING(s_xcode, "\x0D\xC9\x3A\xCE\x30", 5);
    GT_STEALTH_STRING(s_debugserver, "\x31\xCF\x37\xDF\x32\xD9\x30\xD8\x23\xCF\x27", 11);
    GT_STEALTH_STRING(s_dtrace, "\x31\xDE\x27\xCB\x36\xCF", 6);
    GT_STEALTH_STRING(s_instruments, "\x3C\xC4\x26\xDE\x27\xDF\x38\xCF\x3B\xDE\x26", 11);

    for (int i = 0; i < process_count; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        int ret = proc_pidpath(pids[i], path, sizeof(path));
        if (ret > 0) {
            /* Check for debugger-related processes */
            if (strstr(path, s_lldb_mac) || strstr(path, s_gdb_mac) || 
                strstr(path, s_xcode) || strstr(path, s_debugserver) ||
                strstr(path, s_dtrace) || strstr(path, s_instruments)) {
                
                char details[256];
                snprintf(details, sizeof(details), 
                        "Suspicious process detected: %s (PID: %d)", path, pids[i]);
                GT_LOG_WARNING("Suspicious process detected: %s (PID: %d)", path, pids[i]);
            }
        }
    }
    
    free(pids);
#endif
    
    return 0;
}

/**
 * Check for suspicious environment variables
 */
static int check_environment_variables(void) {
    const char *suspicious_vars[] = {
        "DOCKER_CONTAINER", "container", "KUBERNETES_SERVICE_HOST",
        "SANDBOX", "QEMU", "VMWARE", "VBOX", "HYPERVISOR",
        NULL
    };
    
    for (int i = 0; suspicious_vars[i]; i++) {
        if (getenv(suspicious_vars[i])) {
            return 1;
        }
    }
    
    return 0;
}

/**
 * Check for timing anomalies that might indicate sandbox/emulation
 * Uses hardware cycle counters for high precision detection.
 */
static int check_timing_attacks(void) {
    uint64_t start = 0, end = 0;
    
#if ARCH_X86_64
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    start = ((uint64_t)hi << 32) | lo;
#elif ARCH_ARM64
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r" (start));
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    start = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
    
    /* Perform some CPU-intensive operation */
    volatile int sum = 0;
    for (int i = 0; i < 500000; i++) {
        sum += i;
    }
    
#if ARCH_X86_64
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    end = ((uint64_t)hi << 32) | lo;
#elif ARCH_ARM64
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r" (end));
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
    end = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
    
    uint64_t elapsed = end - start;
    
    /* Thresholds vary by platform/architecture */
#if ARCH_X86_64 || ARCH_ARM64
    /* Cycle-based thresholds (example: 10M cycles for the loop above) */
    if (elapsed > 20000000ULL) { 
        GT_LOG_WARNING("Timing anomaly detected via CPU counters: %llu cycles", elapsed);
        return 1;
    }
#else
    /* Nanosecond-based threshold */
    if (elapsed > 100000000L) { /* 100ms threshold */
        return 1;
    }
#endif
    
    return 0;
}

/**
 * Check for VM artifacts
 */
static int check_vm_artifacts(void) {
#if PLATFORM_LINUX
    /* Check DMI information */
    const char *dmi_files[] = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/board_vendor",
        NULL
    };
    
    for (int i = 0; dmi_files[i]; i++) {
        FILE *f = fopen(dmi_files[i], "r");
        if (f) {
            char buffer[256];
            if (fgets(buffer, sizeof(buffer), f)) {
                if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox") ||
                    strstr(buffer, "QEMU") || strstr(buffer, "Xen") ||
                    strstr(buffer, "Microsoft Corporation")) {
                    fclose(f);
                    return 1;
                }
            }
            fclose(f);
        }
    }
    
    /* Check for VM-specific devices */
    if (access("/dev/vmware", F_OK) == 0 ||
        access("/dev/vboxguest", F_OK) == 0 ||
        access("/dev/vboxuser", F_OK) == 0) {
        return 1;
    }
#endif
    
    return 0;
}

