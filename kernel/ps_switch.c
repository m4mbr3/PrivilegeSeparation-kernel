/*
 * ps_switch - Syscall that moves from a level to another the application program
 *
 *
 */
 
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/ps.h>
#include <linux/mman.h>
#include <linux/netlink.h>
#include <asm/timer.h>
#include <net/sock.h>

#define EXPORT_SYMTAB

struct sock *sk_b = NULL;
EXPORT_SYMBOL_GPL(sk_b);
wait_queue_head_t ps_wait_for_msg;
DECLARE_WAIT_QUEUE_HEAD(ps_wait_for_msg);
EXPORT_SYMBOL_GPL(ps_wait_for_msg);
int ps_daemon_pid;
EXPORT_SYMBOL_GPL(ps_daemon_pid);
char ps_buffer[20];
EXPORT_SYMBOL_GPL(ps_buffer);
/* Function to compare the first part of the string and see if it matches*/
int
_cmp_ps_string (char *str1, const char *str2) 
{
    int len1, len2, i;
	if (*str1 == '\0') return -1;
         len2 = strlen(str2);
	len1 = strlen(str1);
	if (len2 > len1) return -1;
	for (i=0; i<len2; ++i) {
	  if (*(str1+i) != *(str2+i)) return -1; 
	}
	return 1;
}

int
login(int new_level)
{
    struct nlmsghdr *nlh;
    char str[15];
    int msgsize = sizeof(str);
    int res;
    struct sk_buff  *skb_out;
    if ( sk_b == NULL ) {
        printk("PS_SWITCH: Load the module to register the netlink \n");
        return -1;
    }
    memset(str, 0, sizeof(str));
    sprintf(str, "%d", new_level);
    skb_out = nlmsg_new(msgsize, 0);
    if (!skb_out){
        printk(KERN_ERR "PS_SWITCH: Failed to allocate new skb\n");
        return  -1;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msgsize, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy((char *)nlmsg_data(nlh), str, msgsize);
    res = nlmsg_unicast(sk_b, skb_out, ps_daemon_pid);
    if (res < 0) {
        printk(KERN_INFO "PS_SWITCH: Error while unlock the daemon\n");
        return -1;
    }   
    //printk("PS_SWITCH: Going to sleep waiting messages\n");
    interruptible_sleep_on(&ps_wait_for_msg);
    printk("PS_SWITCH: The answer is %s\n", ps_buffer); 
    if (strncmp(ps_buffer, "OK", 2) == 0) return 0;
    else if (strncmp(ps_buffer, "NO", 2) == 0) return -1;
    else return -1;
}

asmlinkage long sys_ps_switch (int new_level) {
    uint64_t start, stop;
    struct PrivSec_t *head = current->ps_info_h;
    struct PrivSec_dyn_t *curr;
    int res;
    start = cycle_start();
    if (current->ps_info_h == NULL) {
        printk ("PS_SWITCH: The program %u is not designed to use the "
                 "Privilege Separation system\n", current->pid);
        return 0;
    }

    if (current->ps_level <= new_level) {
        //In this case the application is losing the privile.
        //printk("PS_SWITCH: DOWNGRADE from level %u to level %u \n", current->ps_level , new_level);
        while (head != NULL) {
            unsigned long lev;
            int ret;
            ret = kstrtoul(head->name+8, 10, &lev);
            if (ret != 0) return 0;
            if (lev < new_level) {
               current->ps_mprotected = 0;
               sys_mprotect ((long) head->add_beg, 
                (size_t) head->add_end-head->add_beg, 
                PROT_NONE);
               
               current->ps_mprotected = 1;
            }
            head = head->next;
        } 
        curr = current->ps_dyn_info_h;
        while(curr != NULL) {
            if ( curr->ps_level < new_level) {
                current->ps_mprotected = 0;
                sys_mprotect ((long) curr->mem,
                    (size_t) curr->size, 
                        PROT_NONE);
                current->ps_mprotected = 1;
            }
            curr = curr->next;
        }
        current->ps_level = new_level;
        stop = cycle_stop();
        //printk ("start : %llu\n", start);
        //printk ("stop : %llu\n", stop);
        printk("downgrade cycles : %llu\n", stop - start);
        return 1;
    }
    else {
        //In this case the application is earning the privile.
        //printk("PS_SWITCH: UPGRADE from level %u to level %u \n", current->ps_level, new_level);
        res = login(new_level); 
        if (res == 0){ 
            while (head != NULL) {
                unsigned long lev;
                int ret;
                ret = kstrtoul(head->name+8, 10, &lev);
                if (ret != 0 ) return 0;
                if (lev >= new_level) {
                   current->ps_mprotected = 0;
                   if (_cmp_ps_string(head->name, ".fun_ps_") == 1)
                    sys_mprotect ((long) head->add_beg,
                      (size_t) head->add_end-head->add_beg,
                      PROT_READ | PROT_EXEC);
                   if (_cmp_ps_string(head->name, ".dat_ps_") == 1)
                    sys_mprotect ((long) head->add_beg,
                      (size_t) head->add_end-head->add_beg,
                      PROT_READ | PROT_WRITE);
                   current->ps_mprotected = 1;
                }
                head = head->next;
            }
            curr = current->ps_dyn_info_h;
            while(curr!=NULL) {
                if( curr->ps_level >= new_level) {
                    current->ps_mprotected = 0;
                    sys_mprotect ((long) curr->mem, 
                      (size_t) curr->size,
                      PROT_READ | PROT_WRITE);
                    current->ps_mprotected = 1;
                }
                curr = curr->next;
            }
            current->ps_level = new_level;
        }
        else{ 
            printk ("PS_SWITCH: UPGRADE to %u has failed because noone authentication token provide was correct \n", new_level); 
            stop = cycle_stop();
            printk ("start : %llu\n", start);
            printk ("stop : %llu\n", stop);
            printk("cycles : %llu\n", stop - start);
            return 0;
        }
        stop = cycle_stop();
        //printk ("start : %llu\n", start);
        //printk ("stop : %llu\n", stop);
        printk("upgrade cycles :  %llu\n", stop - start);
        return 1;
    }
}
