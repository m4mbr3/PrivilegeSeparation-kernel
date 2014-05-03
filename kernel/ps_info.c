/* 
 * ps_info - Syscall that  copies the information about an application to provide
 * privilege separation among users 
 *
 */
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/ps_info.h>

asmlinkage long sys_ps_info(struct PrivSec_t *h, int level) 
{
	if (current->ps_info_h == NULL) {
		struct PrivSec_t *cur = h;
		struct PrivSec_t *head=NULL, *tail=NULL;
		//struct PrivSec_t *to_del = NULL;
		printk("WELCOME PS_INFO SYSCALL\n");
		while (cur != NULL) {
		  if (head == NULL) {
			head = kmalloc(sizeof(struct PrivSec_t), GFP_KERNEL);
			if (copy_from_user(head, cur, sizeof(struct PrivSec_t))) 
				return -EFAULT;
			head->next = NULL;
			tail = head;
		  }
		  else {	     
		     tail->next = kmalloc(sizeof(struct PrivSec_t), GFP_KERNEL);
		     tail = tail->next;
		     if (copy_from_user(tail, cur, sizeof(struct PrivSec_t))) 
				return -EFAULT;
		     tail->next = NULL;
		  }
		  cur = cur->next;
		}
		tail = head;
		while(tail != NULL) {
		   printk("Name: %s \n", tail->name);
		   printk("mapstart: %x \n", tail->add_beg);
		   printk("mapend: %x \n", tail->add_end);
		   printk("----------------------------\n");
		   tail = tail->next;
		}
		current->ps_info_h = head;
        current->ps_mprotected = 1;
		printk("Pid: %u\n", current->pid);
	}	
	else { 
		printk("INVALID DOUBLE CALL TO PS_INFO SYSCALL\n");
	}
    current->ps_level = level;
	return 0;
}
