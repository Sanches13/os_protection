#include <linux/sched.h>

struct file *o_fp = NULL;

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

    if (strcmp(filename, "/proc/self/setgroups") == 0 ||
        strcmp(filename, "/proc/self/uid_map") == 0 ||
        strcmp(filename, "/proc/self/gid_map") == 0) {

        pr_info("[PROTECTION] opened file: %s with mode %hx by process [%d] %s\n", buffer, mode, current->pid, current->comm);

        const void *out_buf = (char *)kcalloc(1024, sizeof(char), GFP_KERNEL);
        sprintf(out_buf, "{\"PID\": \"%d\", \"filename\": \"%s\", \"method\": \"open\"}\n", current->pid, filename);
        loff_t pos = 0;
        kernel_write(o_fp, out_buf, strlen(out_buf), &pos);
    }

    kfree(buffer);
    buffer = NULL;

    return orig_open_call(regs);
};