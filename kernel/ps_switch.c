/*
 * ps_switch - Syscall that move from a level to another the application program
 *
 *
 */
 
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/ps_info.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>


struct file*
file_open(const char* path, 
         int flags, 
         int rights) {
    struct file* filep = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filep = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filep)) {
        err = PTR_ERR(filep);
        return NULL;
    }
    return filep;
}

void
file_close(struct file* file) 
{
    filp_close(file, NULL);
}

int
file_read(struct file* file, 
          unsigned long long offset, 
          unsigned char* data, 
          unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int
file_write(struct file* file, 
           unsigned long long offset, 
           unsigned char* data,
           unsigned int size)
{
    mm_segment_t oldfs;
    int ret;
    oldfs = get_fs();
    set_fs(get_ds());
    ret = vfs_write(file, data, size, &offset);
    set_fs(oldfs);
    return ret;
}


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
    struct file *fp = file_open("/dev/ps_pwd", O_RDWR, 0);
    char str[15];
    memset(str, 0, sizeof(str));
    if (fp < 0)
        return -1;
    sprintf(str, "%d", new_level);
    file_write(fp,0, str, 3); 
    memset(str, 0, sizeof(str));
    file_read(fp,0, str , 2);
    printk ("PS_SWITCH: str = %s ", str);
    file_close(fp);
    if (strncmp(str, "OK", 2) == 0) return 0;
    else if (strncmp(str, "NO", 2) == 0) return -1;
    else return -1;
}

asmlinkage long sys_ps_switch (int new_level) {
    struct PrivSec_t *head = current->ps_info_h;
    int res;
    if (current->ps_info_h == NULL) {
        printk ("PS_SWITCH: The program %u is not designed to use the "
                 "Privilege Separation system\n", current->pid);
        return 0;
    }

    if (current->ps_level < new_level) {
        //In this case the application is losing the privile.
        printk("PS_SWITCH: DOWNGRADE from level %u to level %u \n", current->ps_level , new_level);
        while (head != NULL) {
            unsigned long lev;
            int ret;
            ret = kstrtoul(head->name+8, 10, &lev);
            if (ret != 0) return 0;
            if (lev < new_level) {
               sys_mprotect ((long) head->add_beg, 
                (size_t) head->add_end-head->add_beg, 
                PROT_NONE);
            }
            head = head->next;
        } 
        current->ps_level = new_level;
        return 1;
    }
    else {
        //In this case the application is earning the privile.
        printk("PS_SWITCH: UPGRADE from level %u to level %u \n", current->ps_level, new_level);
        res = login(new_level); 
        if (res == 0){ 
            while (head != NULL) {
                unsigned long lev;
                int ret;
                ret = kstrtoul(head->name+8, 10, &lev);
                if (ret != 0 ) return 0;
                if (lev >= new_level) {
                   if (_cmp_ps_string(head->name, ".fun_ps_") == 1)
                    sys_mprotect ((long) head->add_beg,
                      (size_t) head->add_end-head->add_beg,
                      PROT_READ | PROT_EXEC);
                   if (_cmp_ps_string(head->name, ".dat_ps_") == 1)
                    sys_mprotect ((long) head->add_beg,
                      (size_t) head->add_end-head->add_beg,
                      PROT_READ | PROT_WRITE);
                }
                head = head->next;
            }
            current->ps_level = new_level;
        }
        else 
            printk ("PS_SWITCH: UPGRADE to %u has failed because noone authentication token provide was correct \n", new_level); 
        return 1;
    }
}
