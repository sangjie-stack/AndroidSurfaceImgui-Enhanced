/**
 * CoreGuard Breakpoint Detection Implementation
 * 
 * This file contains breakpoint detection and evasion mechanisms.
 * Implements detection for both software (INT3) and hardware (DR registers)
 * breakpoints across x86_64 and ARM64 architectures.
 */

#define _GNU_SOURCE
#include "ghosttrace.h"
#include <sys/ucontext.h>
#include <signal.h>
#include <time.h>

#if PLATFORM_LINUX
#include <sys/user.h>
#include <asm/ptrace.h>
#endif

/* Architecture-specific definitions */
#if ARCH_X86_64
    #define INT3_OPCODE 0xCC
    #define NOP_OPCODE 0x90
    #define DR_ENABLE_MASK 0x000000FF
#elif ARCH_ARM64
    #define BRK_INSTRUCTION 0xD4200000
    #define NOP_INSTRUCTION 0xD503201F
#endif

/* Internal function declarations */
static int scan_memory_for_int3(void *start_addr, size_t size);
static int check_debug_registers(void);
static int check_single_step_flag(void);
static void clear_debug_registers(void);

/**
 * Detect software breakpoints (INT3 instructions)
 */
gt_result_t gt_detect_software_breakpoints(void *address, size_t size) {
    if (!address || size == 0) {
        GT_LOG_ERROR("Invalid parameters for software breakpoint detection");
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("Scanning for software breakpoints at %p, size %zu", address, size);
    
    if (scan_memory_for_int3(address, size)) {
        GT_LOG_WARNING("Software breakpoint detected at %p", address);
        return GT_ERROR_BREAKPOINT_DETECTED;
    }
    
    GT_LOG_DEBUG("No software breakpoints found");
    return GT_SUCCESS;
}

/**
 * Detect hardware breakpoints (debug registers)
 */
gt_result_t gt_detect_hardware_breakpoints(void) {
    GT_LOG_DEBUG("Checking for hardware breakpoints");
    
    if (check_debug_registers()) {
        GT_LOG_WARNING("Hardware breakpoint detected in debug registers");
        return GT_ERROR_BREAKPOINT_DETECTED;
    }
    
    if (check_single_step_flag()) {
        GT_LOG_WARNING("Single-step flag detected");
        return GT_ERROR_BREAKPOINT_DETECTED;
    }
    
    GT_LOG_DEBUG("No hardware breakpoints found");
    return GT_SUCCESS;
}

/**
 * Clear detected breakpoint
 */
gt_result_t gt_clear_breakpoint(void *address) {
    if (!address) {
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("Attempting to clear breakpoint at %p", address);
    
#if ARCH_X86_64
    /* Check if it's an INT3 instruction */
    unsigned char *byte_ptr = (unsigned char *)address;
    if (*byte_ptr == INT3_OPCODE) {
        /* Replace with NOP */
        *byte_ptr = NOP_OPCODE;
        GT_LOG_INFO("Cleared software breakpoint at %p", address);
        return GT_SUCCESS;
    }
#elif ARCH_ARM64
    /* Check if it's a BRK instruction */
    unsigned int *instr_ptr = (unsigned int *)address;
    if ((*instr_ptr & 0xFFE0001F) == BRK_INSTRUCTION) {
        /* Replace with NOP */
        *instr_ptr = NOP_INSTRUCTION;
        GT_LOG_INFO("Cleared software breakpoint at %p", address);
        return GT_SUCCESS;
    }
#endif
    
    /* Try to clear debug registers */
    clear_debug_registers();
    
    GT_LOG_DEBUG("Breakpoint clearing completed");
    return GT_SUCCESS;
}

/* Internal helper functions */

/**
 * Scan memory region for INT3 instructions
 */
static int scan_memory_for_int3(void *start_addr, size_t size) {
    unsigned char *ptr = (unsigned char *)start_addr;
    (void)ptr; // Suppress unused variable warning
    
#if ARCH_X86_64
    for (size_t i = 0; i < size; i++) {
        if (ptr[i] == INT3_OPCODE) {
            GT_LOG_DEBUG("Found INT3 at offset %zu", i);
            return 1;
        }
    }
#elif ARCH_ARM64
    /* ARM64 instructions are 4-byte aligned */
    unsigned int *instr_ptr = (unsigned int *)start_addr;
    size_t num_instructions = size / 4;
    
    for (size_t i = 0; i < num_instructions; i++) {
        /* Check for BRK instruction (bits 31-21 = 11010100001, bits 4-0 = 00000) */
        if ((instr_ptr[i] & 0xFFE0001F) == BRK_INSTRUCTION) {
            GT_LOG_DEBUG("Found BRK instruction at offset %zu", i * 4);
            return 1;
        }
    }
#endif
    
    return 0;
}

/**
 * Check debug registers for hardware breakpoints
 */
static int check_debug_registers(void) {
#if ARCH_X86_64
    unsigned long dr0, dr1, dr2, dr3, dr6, dr7;
    
    /* Read debug registers using inline assembly */
    __asm__ volatile (
        "mov %%dr0, %0\n\t"
        "mov %%dr1, %1\n\t"
        "mov %%dr2, %2\n\t"
        "mov %%dr3, %3\n\t"
        "mov %%dr6, %4\n\t"
        "mov %%dr7, %5\n\t"
        : "=r" (dr0), "=r" (dr1), "=r" (dr2), "=r" (dr3), "=r" (dr6), "=r" (dr7)
    );
    
    /* Check if any debug registers are set */
    if (dr0 || dr1 || dr2 || dr3) {
        GT_LOG_DEBUG("Debug address registers set: DR0=%lx DR1=%lx DR2=%lx DR3=%lx", 
                     dr0, dr1, dr2, dr3);
        return 1;
    }
    
    /* Check if debug control register has breakpoints enabled */
    if (dr7 & DR_ENABLE_MASK) {
        GT_LOG_DEBUG("Debug control register DR7 has breakpoints enabled: %lx", dr7);
        return 1;
    }
    
    /* Check debug status register for breakpoint hits */
    if (dr6 & 0x0F) {
        GT_LOG_DEBUG("Debug status register DR6 shows breakpoint hits: %lx", dr6);
        return 1;
    }
    
#elif ARCH_ARM64
#if PLATFORM_MACOS
    /* On macOS, we can attempt to get the debug state via thread_get_state */
    arm_debug_state64_t debug_state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(mach_thread_self(), ARM_DEBUG_STATE64,
                                       (thread_state_t)&debug_state, &count);
    
    if (kr == KERN_SUCCESS) {
        /* Check if any watchpoints or breakpoints are enabled */
        for (int i = 0; i < 16; i++) {
            if (debug_state.__bcr[i] & 0x1 || debug_state.__wcr[i] & 0x1) {
                GT_LOG_WARNING("ARM64 hardware breakpoint/watchpoint detected via thread_get_state");
                return 1;
            }
        }
    } else {
        GT_LOG_DEBUG("thread_get_state for ARM_DEBUG_STATE64 failed: %d", kr);
    }
    return 0;
#else
    /* ARM64 debug register checking (Linux) */
    /* Note: Direct access to dbgbcr0_el1 is privileged. 
     * In user space, we'd typically use ptrace or check for SIGTRAP anomalies.
     * This implementation is a placeholder for privileged mode. */
    GT_LOG_DEBUG("Hardware breakpoint detection on ARM64 Linux requires ptrace/privileged access");
    return 0;
#endif
#endif
    
    return 0;
}

/**
 * Check for single-step flag in processor flags
 */
static int check_single_step_flag(void) {
#if ARCH_X86_64
    unsigned long flags;
    
    /* Get processor flags */
    __asm__ volatile (
        "pushf\n\t"
        "pop %0\n\t"
        : "=r" (flags)
    );
    
    /* Check trap flag (bit 8) */
    if (flags & 0x100) {
        GT_LOG_DEBUG("Single-step flag (TF) is set in EFLAGS: %lx", flags);
        return 1;
    }
    
#elif ARCH_ARM64
#if PLATFORM_MACOS
    /* On macOS, debug control registers are privileged and cannot be accessed from user space */
    GT_LOG_DEBUG("Single-step flag checking disabled on macOS (requires kernel privileges)");
    return 0;
#else
    unsigned long pstate;
    
    /* Get processor state */
    __asm__ volatile (
        "mrs %0, nzcv\n\t"
        : "=r" (pstate)
    );
    
    /* ARM64 doesn't have a direct single-step flag like x86,
     * but we can check for debug exceptions */
    unsigned long mdscr;
    __asm__ volatile (
        "mrs %0, mdscr_el1\n\t"
        : "=r" (mdscr)
    );
    
    /* Check if single-step is enabled (bit 0) */
    if (mdscr & 0x1) {
        GT_LOG_DEBUG("ARM64 single-step enabled in MDSCR: %lx", mdscr);
        return 1;
    }
#endif
#endif
    
    return 0;
}

/**
 * Clear debug registers
 */
static void clear_debug_registers(void) {
    GT_LOG_DEBUG("Clearing debug registers");
    
#if ARCH_X86_64
    /* Clear all debug registers */
    __asm__ volatile (
        "xor %%rax, %%rax\n\t"
        "mov %%rax, %%dr0\n\t"
        "mov %%rax, %%dr1\n\t"
        "mov %%rax, %%dr2\n\t"
        "mov %%rax, %%dr3\n\t"
        "mov %%rax, %%dr6\n\t"
        "mov %%rax, %%dr7\n\t"
        :
        :
        : "rax"
    );
    
#elif ARCH_ARM64
    /* Clear ARM64 debug registers */
    __asm__ volatile (
        "msr dbgbcr0_el1, xzr\n\t"
        "msr dbgbvr0_el1, xzr\n\t"
        "msr dbgbcr1_el1, xzr\n\t"
        "msr dbgbvr1_el1, xzr\n\t"
        "msr dbgbcr2_el1, xzr\n\t"
        "msr dbgbvr2_el1, xzr\n\t"
        "msr dbgbcr3_el1, xzr\n\t"
        "msr dbgbvr3_el1, xzr\n\t"
    );
#endif
    
    GT_LOG_INFO("Debug registers cleared");
}

/**
 * Advanced breakpoint detection using exception handling
 */
gt_result_t gt_detect_breakpoints_advanced(void) {
    GT_LOG_DEBUG("Performing advanced breakpoint detection");
    
    /* Set up signal handler for SIGTRAP */
    struct sigaction old_action, new_action;
    new_action.sa_handler = SIG_IGN;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;
    
    if (sigaction(SIGTRAP, &new_action, &old_action) != 0) {
        GT_LOG_ERROR("Failed to set SIGTRAP handler");
        return GT_ERROR_GENERIC;
    }
    
    /* Try to trigger a debug exception */
    volatile int test_var = 0;
    
#if ARCH_X86_64
    /* Use INT3 to test for debugger response */
    __asm__ volatile (
        "int3\n\t"
        "nop\n\t"
    );
#elif ARCH_ARM64
    /* Use BRK instruction to test for debugger response */
    __asm__ volatile (
        "brk #0\n\t"
        "nop\n\t"
    );
#endif
    
    test_var = 1; /* This should execute if no debugger caught the exception */
    
    /* Restore original signal handler */
    sigaction(SIGTRAP, &old_action, NULL);
    
    if (test_var == 0) {
        GT_LOG_WARNING("Advanced breakpoint detection: debugger intercepted exception");
        return GT_ERROR_BREAKPOINT_DETECTED;
    }
    
    GT_LOG_DEBUG("Advanced breakpoint detection: no debugger found");
    return GT_SUCCESS;
}

/**
 * Anti-stepping protection
 */
gt_result_t gt_anti_stepping_protection(void) {
    GT_LOG_DEBUG("Enabling anti-stepping protection");
    
    static volatile int step_counter = 0;
    static volatile clock_t last_time = 0;
    
    clock_t current_time = clock();
    
    /* If this is not the first call, check timing */
    if (last_time != 0) {
        clock_t elapsed = current_time - last_time;
        
        /* If execution is too slow, might be single-stepping */
        if (elapsed > CLOCKS_PER_SEC / 1000) { /* More than 1ms */
            step_counter++;
            
            if (step_counter > 5) {
                GT_LOG_WARNING("Anti-stepping: detected slow execution (possible single-stepping)");
                return GT_ERROR_BREAKPOINT_DETECTED;
            }
        } else {
            step_counter = 0; /* Reset counter on normal execution */
        }
    }
    
    last_time = current_time;
    
    return GT_SUCCESS;
}

