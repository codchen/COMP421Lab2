#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

typedef struct pcb {
	SavedContext *ctx;
	int v_page_table_base;
	int pid;
	int uid;
	char state; //RUNNING is 0, READY is 1
	struct pcb *next;
} pcb;

typedef void (*trap_handler)(ExceptionStackFrame *frame);

void trap_kernel_handler(ExceptionStackFrame *frame){}
void trap_clock_handler(ExceptionStackFrame *frame){}
void trap_illegal_handler(ExceptionStackFrame *frame){}
void trap_memory_handler(ExceptionStackFrame *frame){}
void trap_math_handler(ExceptionStackFrame *frame){}
void trap_tty_receive_handler(ExceptionStackFrame *frame){}
void trap_tty_transmit_handler(ExceptionStackFrame *frame){}

void *k_brk = 0;
void *p_limit = 0;
char v_enabled = 0;
int free_pf_head = -1;
int free_pf_tail = -1;
int free_pfn = 0;
struct pte *region0, *region1;

extern void KernelStart(ExceptionStackFrame * frame, 
	unsigned int pmem_size, void *orig_brk, char **cmd_args) {
	k_brk = orig_brk;
	p_limit = (void *)((long)(PMEM_BASE + pmem_size));
	//initialize interrupt vector table
	trap_handler *interrupt_vector_table = calloc(TRAP_VECTOR_SIZE, sizeof(trap_handler));
	if (interrupt_vector_table == NULL) return;
	interrupt_vector_table[TRAP_KERNEL] = trap_kernel_handler;
	interrupt_vector_table[TRAP_CLOCK] = trap_clock_handler;
	interrupt_vector_table[TRAP_ILLEGAL] = trap_illegal_handler;
	interrupt_vector_table[TRAP_MEMORY] = trap_memory_handler;
	interrupt_vector_table[TRAP_MATH] = trap_math_handler;
	interrupt_vector_table[TRAP_TTY_RECEIVE] = trap_tty_receive_handler;
	interrupt_vector_table[TRAP_TTY_TRANSMIT] = trap_tty_transmit_handler;
	WriteRegister(REG_VECTOR_BASE, (RCS421RegVal)interrupt_vector_table);

	//initialize page table
	region0 = calloc(PAGE_TABLE_LEN, sizeof(struct pte));
	if (region0 == NULL) return;
	region1 = calloc(PAGE_TABLE_LEN, sizeof(struct pte));
	if (region1 == NULL) return;
	int k_base_pfn = VMEM_1_BASE >> PAGESHIFT;
	int i;
	for (i = k_base_pfn; i < UP_TO_PAGE(k_brk) >> PAGESHIFT; i++) {
		region1[i - k_base_pfn].pfn = i;
		region1[i - k_base_pfn].uprot = 0;
		region1[i - k_base_pfn].kprot = (i<(UP_TO_PAGE(&_etext) >> PAGESHIFT)?5:6);
		region1[i - k_base_pfn].valid = 1;
	}
	WriteRegister(REG_PTR0, (RCS421RegVal)region0);
	WriteRegister(REG_PTR1, (RCS421RegVal)region1);

	//initialize free physical page list
	//TODO: check if free space doesn't make up for even one single page
	free_pf_head = UP_TO_PAGE(k_brk) >> PAGESHIFT;
	for (i = free_pf_head; i < (DOWN_TO_PAGE(p_limit) >> PAGESHIFT) - 1; i++) {
		*(long *)((long)i * PAGESIZE) = i + 1;
		free_pfn++;
	}
	*(long *)((long)i * PAGESIZE) = MEM_INVALID_PAGES + 1;
	free_pfn++;
	for (i = MEM_INVALID_PAGES + 1; i < (DOWN_TO_PAGE(KERNEL_STACK_BASE) >> PAGESHIFT) - 1; i++) {
		*(long *)((long)i * PAGESIZE) = i + 1;
		free_pfn++;
	}
	free_pf_tail = i;
	free_pfn++;

	//enable VM
	WriteRegister(REG_VM_ENABLE, 1);

	//TODO: idle


}

extern int SetKernelBrk(void *addr) {
	if (!v_enabled) {
		if ((long)addr >= VMEM_1_BASE && (long)addr <= VMEM_1_LIMIT) {
			k_brk = addr;
			return 0;
		}
		else {
			perror("Brk out of bound.");
			return -1;
		}
	}
	return 0;
}

static void WriteToPhysPFN(int pfn, int value) {
	int tmp = UP_TO_PAGE(k_brk) >> PAGESHIFT;
	region1[tmp].valid = 1;
	region1[tmp].pfn = value;
	region1[tmp].kprot = 6;
	*(int *)(long)(tmp << PAGESHIFT) = value;
	region1[tmp].valid = 0;
}