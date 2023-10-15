#include <linux/sched.h>

// openat
static asmlinkage long (*orig_open_call)(const struct pt_regs *regs);
static asmlinkage long protect_sys_openat(const struct pt_regs *regs)
{
    /*
    SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
    */
    const char __user *filename = (const char __user *)regs->si;
    umode_t mode = (umode_t)regs->cx;
    char *buffer = (char *)kcalloc(1024, sizeof(char), GFP_KERNEL);

    if (copy_from_user(buffer, filename, 1024))
        return orig_open_call(regs);

    if (strcmp(filename, "/etc/passwd") == 0)
        pr_info("[PROTECTION] opened file: %s with mode %hx by process [%d] %s\n", buffer, mode, current->pid, current->comm);

    kfree(buffer);
    buffer = NULL;

    return orig_open_call(regs);
};