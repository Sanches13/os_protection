#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/version.h>

#include <linux/syscalls.h>
#include <linux/kprobes.h>

#include "syscalls.h"

// global pointer to sys_call_table
static unsigned long **sys_call_table;

static unsigned long **get_sys_call_table(void) {
    unsigned long (*kallsyms_lookup_name)(const char *name);
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    if (register_kprobe(&kp) < 0)
        return NULL;
    
    kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr;
    unregister_kprobe(&kp);

    return (unsigned long **)kallsyms_lookup_name("sys_call_table");
}

static inline void __write_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0"
                : "+r"(cr0)
                :
                : "memory");
}

static void enable_write_protection(void) {
    unsigned long cr0 = read_cr0(); 
    set_bit(16, &cr0); // cr0 | 0x10000
    __write_cr0(cr0);
}

static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0); // cr0 & ~0x10000
    __write_cr0(cr0);
}

static inline void setup_syscalls(void) {
    // Rewrite sys_call_table with custom hooks

    orig_open_call = (void *)sys_call_table[__NR_openat];
    sys_call_table[__NR_openat] = (unsigned long *)protect_sys_openat;
}

static inline void clear_syscalls(void) {
    sys_call_table[__NR_openat] = (unsigned long *)orig_open_call;
}

static int __init protection_start(void) {
    pr_info("[PROTECTION] PROTECTION start\n");
    if (!(sys_call_table = get_sys_call_table()))
        return -1;

    disable_write_protection();
    setup_syscalls();
    enable_write_protection();

    o_fp = filp_open("/home/user/output.txt", O_RDWR | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(o_fp)) {
        printk(KERN_INFO "output file open error/n");
        return -1;
    }

    prevention = filp_open("/home/user/prevention.txt", O_RDONLY | O_CREAT, 0644);
    if (IS_ERR(o_fp)) {
        printk(KERN_INFO "prevention file open error/n");
        return -1;
    }

    // prevention_func();

    return 0;
}

static void __exit protection_end(void) {
    pr_info("[PROTECTION] protection ended\n");
    if(!sys_call_table)
        return;

    disable_write_protection();
    clear_syscalls();
    enable_write_protection();

    filp_close(o_fp, NULL);
    filp_close(prevention, NULL);
    // protection_proc_exit();
}

module_init(protection_start);
module_exit(protection_end);

MODULE_LICENSE("GPL");