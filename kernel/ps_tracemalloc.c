/*
 * ps_tracemalloc - Syscall that trace for each malloc and free 
 * the dynamic data allocation and protect them from improper access
 *
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/ps.h>
#include <linux/mman.h>
#include <linux/string.h>


asmlinkage long sys_ps_tracemalloc (void *ptr, int size, char *cmd) {
    int ps_level = current->ps_level;
    if (strncmp(cmd, "MALLOC", 6) == 0) {
       printk (KERN_INFO "The command provided is MALLOC \n"); 

    }
    else if (strncmp(cmd, "FREE", 4) == 0) {
        printk (KERN_INFO "The command provided is FREE \n");

    }
    else {
        printk (KERN_ERR "Unknown command provided\n");
    }
}
