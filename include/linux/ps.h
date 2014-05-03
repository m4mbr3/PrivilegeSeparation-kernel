#include <uapi/linux/elf.h>

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
