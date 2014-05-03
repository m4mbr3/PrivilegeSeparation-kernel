/*
 * ps_tracemalloc - Syscall that trace for each malloc and free 
 * the dynamic data allocation and protect them from improper access
 *
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/ps.h>
#include <linux/mman.h>

