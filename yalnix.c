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

void *p_k_brk = 0;
void *p_k_base = 0;
void *p_k_limit = 0;
char v_enabled = 0;
int free_pf_head = -1;
int free_pf_tail = -1;
int free_pfn = 0;

extern void KernelStart(ExceptionStackFrame * frame, 
	unsigned int pmem_size, void *orig_brk, char **cmd_args) {
	p_k_brk = orig_brk;
	p_k_base = orig_brk;
	p_k_limit = (void *)((long)(PMEM_BASE + pmem_size));
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

	//initialize page tables
	void *region0 = calloc(PAGE_TABLE_LEN, sizeof(struct pte));
	if (region0 == NULL) return;
	WriteRegister(REG_PTR0, (RCS421RegVal)region0);
	void *region1 = calloc(PAGE_TABLE_LEN, sizeof(struct pte));
	if (region1 == NULL) return;
	WriteRegister(REG_PTR1, (RCS421RegVal)region1);

	//initialize free physical page list
	//TODO: check if free space doesn't make up for even one single page
	free_pf_head = UP_TO_PAGE(p_k_brk) >> PAGESHIFT;
	int i;
	for (i = free_pf_head; i < (DOWN_TO_PAGE(p_k_limit) >> PAGESHIFT) - 1; i++) {
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
		if (addr >= p_k_base && addr <= p_k_limit) {
			p_k_brk = addr;
			return 0;
		}
		else {
			perror("Brk out of bound.");
			return -1;
		}
	}
	return 0;
}