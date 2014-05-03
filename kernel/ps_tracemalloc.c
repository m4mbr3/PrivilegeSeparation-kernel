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
    /*
    if (current->ps_info_h == NULL) {
        printk (KERN_ERR "PS_TRACEMALLOC: The program %u is not designed to use the "
                "Privilege Separation system\n", current->pid);
        return 0;
    }
    */
    int ps_level = current->ps_level;
    if (strncmp(cmd, "MALLOC", 6) == 0) {
       printk (KERN_INFO "PS_TRACEMALLOC: The command provided is MALLOC \n"); 
       printk (KERN_INFO "PS_TRACEMALLOC: %x address, %u size\n", ptr, size); 
       if (current->ps_dyn_info_h == NULL) {
            //create a new element that will be the first of the list
            struct PrivSec_dyn_t *new = 
                (struct PrivSec_dyn_t *) kmalloc(sizeof(struct PrivSec_dyn_t),
                                          GFP_ATOMIC);
            new->ps_level = current->ps_level;
            new->size = size;
            new->mem = ptr;
            new->next = NULL;
            current->ps_dyn_info_h = new;
            return 1;
       }
       struct PrivSec_dyn_t *curr = current->ps_dyn_info_h;
       while (curr->next != NULL) curr = curr->next;
       struct PrivSec_dyn_t *new = 
            (struct PrivSec_dyn_t *) kmalloc(sizeof(struct PrivSec_dyn_t), 
                                      GFP_ATOMIC);
       new->ps_level = current->ps_level;
       new->size = size;
       new->mem = ptr;
       new->next = NULL;
       curr->next = new;
    }
    else if (strncmp(cmd, "FREE", 4) == 0) {
        printk (KERN_INFO "PS_TRACEMALLOC: The command provided is FREE \n");
        printk (KERN_INFO "PS_TRACEMALLOC: %x address, %u size\n", ptr, size);
        if (current->ps_dyn_info_h == NULL) return -1; //case zero elements.
        struct PrivSec_dyn_t *curr = current->ps_dyn_info_h;
        if (curr->next == NULL) {
            //case only one element inside the list
            if (curr->mem == ptr) {
                kfree(curr);
                current->ps_dyn_info_h = NULL;
                return 1;
            }
            else {
                return -1;
            }
        }
        struct PrivSec_dyn_t *next = curr->next;
        if (next->next == NULL) {
           //case two elements inside the list. 
           if (curr->mem == ptr) {
                current->ps_dyn_info_h = next;
                kfree(curr);
                return 1;
           }
           else if (next->mem == ptr) {
                curr->next = NULL;
                kfree(next);
                return 1;
           }
           else {
               return -1;
           }
        }
        int found = 0;
        while(!found && next != NULL) {
            if (curr->mem == ptr) found=2;
            else if (next->mem == ptr ) found=1;
            else {
                next = next->next;
                curr = curr->next;
            }
        }
        if (found == 2) {
            current->ps_dyn_info_h = next;
            kfree(curr);
            return 1;
        }
        if (found == 1) {
            curr->next = next->next;
            kfree(next); 
            return 1;
        }
        return -1;
    }
    else {
        printk (KERN_ERR "PS_TRACEMALLOC: Unknown command provided\n");
    }
}
