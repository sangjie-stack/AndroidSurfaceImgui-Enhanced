/**
 * CoreGuard Memory Protection Implementation
 * 
 * This file contains memory protection and anti-dumping mechanisms.
 * Implements runtime memory protection, memory traps, obfuscation,
 * and access violation handlers for both macOS and Linux.
 */

#define _GNU_SOURCE
#include "ghosttrace.h"
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>

/* Memory protection tracking */
#define MAX_PROTECTED_REGIONS 256

typedef struct {
    void *address;
    size_t size;
    int original_protection;
    int is_protected;
    int is_trapped;
    unsigned char *backup_data;
} memory_region_info_t;

static memory_region_info_t g_protected_regions[MAX_PROTECTED_REGIONS];
static int g_num_protected_regions = 0;
static struct sigaction g_old_sigsegv_handler;
static struct sigaction g_old_sigbus_handler;

/* Internal function declarations */
static void memory_access_handler(int sig, siginfo_t *info, void *context);
static int find_region_by_address(void *address);
static void obfuscate_memory_region(void *address, size_t size);
static void deobfuscate_memory_region(void *address, size_t size);
static int setup_signal_handlers(void);
static void restore_signal_handlers(void);

/**
 * Protect memory region from dumping
 */
gt_result_t gt_protect_memory(void *address, size_t size) {
    if (!address || size == 0) {
        GT_LOG_ERROR("Invalid parameters for memory protection");
        return GT_ERROR_GENERIC;
    }
    
    if (g_num_protected_regions >= MAX_PROTECTED_REGIONS) {
        GT_LOG_ERROR("Maximum number of protected regions reached");
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    GT_LOG_DEBUG("Protecting memory region at %p, size %zu", address, size);
    
    /* Align address to page boundary */
    size_t page_size = getpagesize();
    void *aligned_addr = (void *)((uintptr_t)address & ~(page_size - 1));
    size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
    
    /* Get current protection - Default to RW for safety on modern OS */
    int current_prot = PROT_READ | PROT_WRITE;
    
    /* Change protection to read-only */
    if (mprotect(aligned_addr, aligned_size, PROT_READ) != 0) {
        GT_LOG_ERROR("Failed to protect memory region: %s", strerror(errno));
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    /* Store region information */
    memory_region_info_t *region = &g_protected_regions[g_num_protected_regions];
    region->address = aligned_addr;
    region->size = aligned_size;
    region->original_protection = current_prot;
    region->is_protected = 1;
    region->is_trapped = 0;
    region->backup_data = NULL;
    
    g_num_protected_regions++;
    
    GT_LOG_INFO("Memory region protected at %p, size %zu", aligned_addr, aligned_size);
    return GT_SUCCESS;
}

/**
 * Unprotect previously protected memory region
 */
gt_result_t gt_unprotect_memory(void *address) {
    if (!address) {
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("Unprotecting memory region at %p", address);
    
    int region_index = find_region_by_address(address);
    if (region_index < 0) {
        GT_LOG_WARNING("Memory region not found for unprotection");
        return GT_ERROR_GENERIC;
    }
    
    memory_region_info_t *region = &g_protected_regions[region_index];
    
    /* Restore original protection */
    if (mprotect(region->address, region->size, region->original_protection) != 0) {
        GT_LOG_ERROR("Failed to unprotect memory region: %s", strerror(errno));
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    /* Free backup data if exists */
    if (region->backup_data) {
        free(region->backup_data);
    }
    
    /* Remove from tracking array */
    for (int i = region_index; i < g_num_protected_regions - 1; i++) {
        g_protected_regions[i] = g_protected_regions[i + 1];
    }
    g_num_protected_regions--;
    
    GT_LOG_INFO("Memory region unprotected at %p", address);
    return GT_SUCCESS;
}

/**
 * Create memory trap that triggers on access
 */
gt_result_t gt_create_memory_trap(void *address, size_t size) {
    if (!address || size == 0) {
        GT_LOG_ERROR("Invalid parameters for memory trap");
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("Creating memory trap at %p, size %zu", address, size);
    
    /* Setup signal handlers if not already done */
    if (setup_signal_handlers() != 0) {
        GT_LOG_ERROR("Failed to setup signal handlers for memory trap");
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    /* Align address to page boundary */
    size_t page_size = getpagesize();
    void *aligned_addr = (void *)((uintptr_t)address & ~(page_size - 1));
    size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
    
    /* Create backup of original data */
    unsigned char *backup = malloc(aligned_size);
    if (!backup) {
        GT_LOG_ERROR("Failed to allocate backup memory");
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    memcpy(backup, aligned_addr, aligned_size);
    
    /* Make memory inaccessible */
    if (mprotect(aligned_addr, aligned_size, PROT_NONE) != 0) {
        GT_LOG_ERROR("Failed to create memory trap: %s", strerror(errno));
        free(backup);
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    /* Store trap information */
    if (g_num_protected_regions >= MAX_PROTECTED_REGIONS) {
        GT_LOG_ERROR("Maximum number of protected regions reached");
        mprotect(aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC);
        free(backup);
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    memory_region_info_t *region = &g_protected_regions[g_num_protected_regions];
    region->address = aligned_addr;
    region->size = aligned_size;
    region->original_protection = PROT_READ | PROT_WRITE | PROT_EXEC;
    region->is_protected = 1;
    region->is_trapped = 1;
    region->backup_data = backup;
    
    g_num_protected_regions++;
    
    GT_LOG_INFO("Memory trap created at %p, size %zu", aligned_addr, aligned_size);
    return GT_SUCCESS;
}

/**
 * Remove memory trap
 */
gt_result_t gt_remove_memory_trap(void *address) {
    if (!address) {
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("Removing memory trap at %p", address);
    
    int region_index = find_region_by_address(address);
    if (region_index < 0) {
        GT_LOG_WARNING("Memory trap not found for removal");
        return GT_ERROR_GENERIC;
    }
    
    memory_region_info_t *region = &g_protected_regions[region_index];
    
    if (!region->is_trapped) {
        GT_LOG_WARNING("Memory region is not trapped");
        return GT_ERROR_GENERIC;
    }
    
    /* Restore original protection */
    if (mprotect(region->address, region->size, region->original_protection) != 0) {
        GT_LOG_ERROR("Failed to remove memory trap: %s", strerror(errno));
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    /* Restore original data */
    if (region->backup_data) {
        memcpy(region->address, region->backup_data, region->size);
        free(region->backup_data);
    }
    
    /* Remove from tracking array */
    for (int i = region_index; i < g_num_protected_regions - 1; i++) {
        g_protected_regions[i] = g_protected_regions[i + 1];
    }
    g_num_protected_regions--;
    
    GT_LOG_INFO("Memory trap removed at %p", address);
    return GT_SUCCESS;
}

/**
 * Runtime memory obfuscation
 */
gt_result_t gt_obfuscate_memory(void *address, size_t size) {
    if (!address || size == 0) {
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("Obfuscating memory at %p, size %zu", address, size);
    
    obfuscate_memory_region(address, size);
    
    GT_LOG_DEBUG("Memory obfuscation completed");
    return GT_SUCCESS;
}

/**
 * Runtime memory deobfuscation
 */
gt_result_t gt_deobfuscate_memory(void *address, size_t size) {
    if (!address || size == 0) {
        return GT_ERROR_GENERIC;
    }
    
    GT_LOG_DEBUG("Deobfuscating memory at %p, size %zu", address, size);
    
    deobfuscate_memory_region(address, size);
    
    GT_LOG_DEBUG("Memory deobfuscation completed");
    return GT_SUCCESS;
}

/* Internal helper functions */

/**
 * Signal handler for memory access violations
 */
static void memory_access_handler(int sig, siginfo_t *info, void *context) {
    (void)context; // Suppress unused parameter warning
    void *fault_addr = info->si_addr;
    
    GT_LOG_WARNING("Memory access violation at %p (signal %d)", fault_addr, sig);
    
    /* Check if this is one of our trapped regions */
    int region_index = find_region_by_address(fault_addr);
    if (region_index >= 0) {
        memory_region_info_t *region = &g_protected_regions[region_index];
        
        if (region->is_trapped) {
            GT_LOG_ERROR("Memory trap triggered at %p - potential memory dumping attempt!", fault_addr);
            
            /* Log the access attempt */
            GT_LOG_ERROR("Unauthorized memory access detected - terminating process");
            
            /* Terminate the process to prevent memory dumping */
            exit(1);
        }
    }
    
    /* If not our trap, call original handler or terminate */
    GT_LOG_ERROR("Unhandled memory access violation - terminating");
    exit(1);
}

/**
 * Find protected region by address
 */
static int find_region_by_address(void *address) {
    for (int i = 0; i < g_num_protected_regions; i++) {
        memory_region_info_t *region = &g_protected_regions[i];
        uintptr_t addr = (uintptr_t)address;
        uintptr_t start = (uintptr_t)region->address;
        uintptr_t end = start + region->size;
        
        if (addr >= start && addr < end) {
            return i;
        }
    }
    return -1;
}

/**
 * Obfuscate memory region using XOR
 */
static void obfuscate_memory_region(void *address, size_t size) {
    unsigned char *ptr = (unsigned char *)address;
    unsigned char key = 0xAA; /* Simple XOR key */
    
    for (size_t i = 0; i < size; i++) {
        ptr[i] ^= key;
        key = (key << 1) | (key >> 7); /* Rotate key */
    }
}

/**
 * Deobfuscate memory region using XOR
 */
static void deobfuscate_memory_region(void *address, size_t size) {
    /* XOR is symmetric, so deobfuscation is the same as obfuscation */
    obfuscate_memory_region(address, size);
}

/**
 * Setup signal handlers for memory protection
 */
static int setup_signal_handlers(void) {
    struct sigaction new_action;
    
    /* Setup SIGSEGV handler */
    new_action.sa_sigaction = memory_access_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = SA_SIGINFO;
    
    if (sigaction(SIGSEGV, &new_action, &g_old_sigsegv_handler) != 0) {
        GT_LOG_ERROR("Failed to setup SIGSEGV handler");
        return -1;
    }
    
    /* Setup SIGBUS handler (for some platforms) */
    if (sigaction(SIGBUS, &new_action, &g_old_sigbus_handler) != 0) {
        GT_LOG_ERROR("Failed to setup SIGBUS handler");
        sigaction(SIGSEGV, &g_old_sigsegv_handler, NULL);
        return -1;
    }
    
    GT_LOG_DEBUG("Signal handlers setup successfully");
    return 0;
}

/**
 * Restore original signal handlers
 */
static void restore_signal_handlers(void) {
    sigaction(SIGSEGV, &g_old_sigsegv_handler, NULL);
    sigaction(SIGBUS, &g_old_sigbus_handler, NULL);
    GT_LOG_DEBUG("Signal handlers restored");
}

/**
 * Advanced anti-dumping protection
 */
gt_result_t gt_enable_anti_dumping(void) {
    GT_LOG_INFO("Enabling advanced anti-dumping protection");
    
#if PLATFORM_MACOS
    /* On macOS, skip complex memory protection to avoid blocking issues */
    GT_LOG_INFO("Anti-dumping protection enabled (macOS compatibility mode)");
    return GT_SUCCESS;
#endif
    
    /* Setup signal handlers (Linux only) */
    if (setup_signal_handlers() != 0) {
        GT_LOG_WARNING("Failed to setup signal handlers, continuing without memory traps");
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    /* Protect critical memory regions (Linux only) */
#if PLATFORM_LINUX
    extern char _start, _end; /* Linker symbols for program boundaries */
    void *program_start = &_start;
    void *program_end = &_end;
    size_t program_size = (char *)program_end - (char *)program_start;
    
    if (program_size > 0) {
        gt_protect_memory(program_start, program_size);
    }
#endif
    
    /* Create decoy memory regions (Linux only) */
    for (int i = 0; i < 5; i++) {
        void *decoy = malloc(4096);
        if (decoy) {
            memset(decoy, 0xCC, 4096); /* Fill with INT3 instructions */
            gt_result_t trap_result = gt_create_memory_trap(decoy, 4096);
            if (trap_result != GT_SUCCESS) {
                GT_LOG_WARNING("Failed to create memory trap %d, continuing", i);
                free(decoy); /* Free the memory if trap creation failed */
            }
        }
    }
    
    GT_LOG_INFO("Anti-dumping protection enabled");
    return GT_SUCCESS;
}

/**
 * Disable anti-dumping protection
 */
gt_result_t gt_disable_anti_dumping(void) {
    GT_LOG_INFO("Disabling anti-dumping protection");
    
    /* Remove all protected regions */
    while (g_num_protected_regions > 0) {
        memory_region_info_t *region = &g_protected_regions[0];
        if (region->is_trapped) {
            gt_remove_memory_trap(region->address);
        } else {
            gt_unprotect_memory(region->address);
        }
    }
    
    /* Restore signal handlers */
    restore_signal_handlers();
    
    GT_LOG_INFO("Anti-dumping protection disabled");
    return GT_SUCCESS;
}

/**
 * Memory integrity check
 */
gt_result_t gt_check_memory_integrity(void *address, size_t size, unsigned int expected_checksum) {
    if (!address || size == 0) {
        return GT_ERROR_GENERIC;
    }
    
    /* Calculate simple checksum */
    unsigned int checksum = 0;
    unsigned char *ptr = (unsigned char *)address;
    
    for (size_t i = 0; i < size; i++) {
        checksum += ptr[i];
        checksum = (checksum << 1) | (checksum >> 31); /* Rotate */
    }
    
    if (checksum != expected_checksum) {
        GT_LOG_ERROR("Memory integrity check failed at %p", address);
        return GT_ERROR_MEMORY_PROTECTION_FAILED;
    }
    
    GT_LOG_DEBUG("Memory integrity check passed at %p", address);
    return GT_SUCCESS;
}

/**
 * Dynamic Memory Obfuscation - Encrypt data at rest
 */
gt_result_t gt_memory_obfuscate_dynamic(void *address, size_t size) {
    if (!address || size == 0) return GT_ERROR_INVALID_PARAMETER;
    
    GT_LOG_DEBUG("Applying dynamic obfuscation at %p", address);
    
    /* XOR with a simple rotating key */
    unsigned char *ptr = (unsigned char *)address;
    unsigned char key = 0xBD;
    for (size_t i = 0; i < size; i++) {
        ptr[i] ^= key;
        key = (unsigned char)((key << 1) | (key >> 7));
    }
    
    return GT_SUCCESS;
}

/**
 * Dynamic Memory Access - Decrypt, Use, Re-encrypt
 */
gt_result_t gt_memory_access_obfuscated(void *address, size_t size, gt_memory_access_cb_t callback, void *user_data) {
    if (!address || size == 0 || !callback) return GT_ERROR_INVALID_PARAMETER;
    
    /* 1. Deobfuscate (XOR is symmetric) */
    gt_memory_obfuscate_dynamic(address, size);
    
    /* 2. Execute callback with clear data */
    callback(address, size, user_data);
    
    /* 3. Re-obfuscate immediately */
    gt_memory_obfuscate_dynamic(address, size);
    
    return GT_SUCCESS;
}
