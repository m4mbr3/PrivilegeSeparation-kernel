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


asmlinkage unsigned long sys_ps_tracemalloc (unsigned long addr,
                                    unsigned long len,
                                    int prot,
                                    int flags,
                                    char *cmd,
                                    int privlev) {

    int found = 0;
    struct PrivSec_dyn_t *curr = NULL;
    struct PrivSec_dyn_t *new = NULL;
    struct PrivSec_dyn_t *next = NULL;
    unsigned long ptr;

    if (current->ps_info_h == NULL) {
        printk (KERN_ERR "PS_TRACEMALLOC: The program %u is not designed to use the "
                "Privilege Separation system\n", current->pid);
        return -EINVAL;
    }

    if (strncmp(cmd,"MMAP", 4) == 0) {

       ptr = sys_mmap_pgoff(addr, len, prot, flags, -1, (off_t)0);

       printk (KERN_INFO "PS_TRACEMALLOC: The command provided is MMAP \n");
       printk (KERN_INFO "PS_TRACEMALLOC: %lx ptr, %lu size\n", ptr, len);

       if (!IS_ERR((void *) ptr))
           force_successful_syscall_return();

       if (current->ps_dyn_info_h == NULL) {
            //create a new element that will be the first of the list
            struct PrivSec_dyn_t *new =
                (struct PrivSec_dyn_t *) kmalloc(sizeof(struct PrivSec_dyn_t),
                                          GFP_ATOMIC);
            new->ps_level = privlev;
            new->size = len;
            new->mem = (void *) ptr;
            new->next = NULL;
            current->ps_dyn_info_h = new;
            return ptr;
       }
       curr = current->ps_dyn_info_h;
       while (curr->next != NULL) curr = curr->next;
       new = (struct PrivSec_dyn_t *) kmalloc(sizeof(struct PrivSec_dyn_t),
                                      GFP_ATOMIC);
       new->ps_level = privlev;
       new->size = len;
       new->mem = (void *) ptr;
       new->next = NULL;
       curr->next = new;
       return ptr;
    }
    else if (strncmp(cmd, "MUNMAP", 6) == 0) {

        printk (KERN_INFO "PS_TRACEMALLOC: The command provided is MUNMAP \n");
        printk (KERN_INFO "PS_TRACEMALLOC: %lx address, %lu size\n", addr, len);

        if (current->ps_dyn_info_h == NULL) return -1; //case zero elements.

        curr = current->ps_dyn_info_h;

        if (curr->next == NULL) {
            //case only one element inside the list
            if (curr->mem == (void *)addr) {
                kfree(curr);
                current->ps_dyn_info_h = NULL;
                sys_munmap (addr, len);
                return 1;
            }
            else {
                return -EINVAL;
            }
        }
        next = curr->next;
        if (next->next == NULL) {
           //case two elements inside the list.
           if (curr->mem == (void *) addr) {
                current->ps_dyn_info_h = next;
                kfree(curr);
                sys_munmap (addr, len);
                return 1;
           }
           else if (next->mem == (void *) addr) {
                curr->next = NULL;
                kfree(next);
                sys_munmap (addr, len);
                return 1;
           }
           else {
               return -EINVAL;
           }
        }
        found = 0;
        while(!found && next != NULL) {
            if (curr->mem == (void *) addr) found=2;
            else if (next->mem == (void *) addr ) found=1;
            else {
                next = next->next;
                curr = curr->next;
            }
        }
        if (found == 2) {
            current->ps_dyn_info_h = next;
            kfree(curr);
            sys_munmap (addr, len);
            return 1;
        }
        if (found == 1) {
            curr->next = next->next;
            kfree(next);
            sys_munmap (addr, len);
            return 1;
        }
        return -EINVAL;
    }
    else {
        printk (KERN_ERR "PS_TRACEMALLOC: Unknown command provided\n");
        return -EINVAL;
    }
    return -EINVAL;
}
