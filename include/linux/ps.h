#include <uapi/linux/elf.h>

#define FREQ_MAX 3600000
struct PrivSec_t {
	char name[100];
	Elf32_Addr add_beg;
	Elf32_Addr add_end;
	struct PrivSec_t *next;
};
 
struct PrivSec_dyn_t {
    int ps_level;
    int size;
    void *mem;
    struct PrivSec_dyn_t *next;
};
                                                                                                                                    
                                                                                                                                                         
static inline uint64_t cycle_start(void)                                                                                                                 
{                                                                                                                                                        
        uint32_t cycles_low, cycles_high;                                                                                                                
                                                                                                                                                         
        asm volatile (                                                                                                                                   
                "cpuid\n"                                                                                                                                
                "rdtsc\n"                                                                                                                                
                "movl %%eax, %0\n"                                                                                                                       
                "movl %%edx, %1\n"                                                                                                                       
                : "=r" (cycles_low), "=r" (cycles_high)
                :
                : "%rax", "%rbx", "%rcx", "%rdx"
        );

        return (uint64_t) cycles_high << 32 | (uint64_t) cycles_low;
}

static inline uint64_t cycle_stop(void)
{
        uint32_t cycles_low, cycles_high;

        asm volatile (
                "rdtscp\n"
                "movl %%eax, %0\n"
                "movl %%edx, %1\n"
                "cpuid\n"
                : "=r" (cycles_low), "=r" (cycles_high)
                :
                : "%rax", "%rbx", "%rcx", "%rdx"
        );

        return (uint64_t) cycles_high << 32 | (uint64_t) cycles_low;
}

static inline uint64_t cycle_time(uint64_t cycles)
{
        return div64_u64(cycles, FREQ_MAX);
}



