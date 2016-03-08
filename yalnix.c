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

void *p_brk = 0;
void *p_base = 0;
void *p_limit = 0;
char v_enabled = 0;
int free_pf_head = -1;
int free_pf_tail = -1;

extern void KernelStart(ExceptionStackFrame * frame, 
	unsigned int pmem_size, void *orig_brk, char **cmd_args) {
	p_brk = orig_brk;
	p_base = orig_brk;
	p_limit = (void *)((long)(PMEM_BASE + pmem_size));
	//initialize interrupt vector table
	trap_handler *interrupt_vector_table = malloc(sizeof(trap_handler) * TRAP_VECTOR_SIZE);
	if (interrupt_vector_table == NULL) return;
	int i;
	for (i = 0; i < TRAP_VECTOR_SIZE; i++) {
		interrupt_vector_table = NULL;
	}
	interrupt_vector_table[TRAP_KERNEL] = trap_kernel_handler;
	interrupt_vector_table[TRAP_CLOCK] = trap_clock_handler;
	interrupt_vector_table[TRAP_ILLEGAL] = trap_illegal_handler;
	interrupt_vector_table[TRAP_MEMORY] = trap_memory_handler;
	interrupt_vector_table[TRAP_MATH] = trap_math_handler;
	interrupt_vector_table[TRAP_TTY_RECEIVE] = trap_tty_receive_handler;
	interrupt_vector_table[TRAP_TTY_TRANSMIT] = trap_tty_transmit_handler;
	WriteRegister(REG_VECTOR_BASE, (RCS421RegVal)interrupt_vector_table);

	//TODO: initialize page tables
	
	//initialize free physical page list
	//TODO: check if free space doesn't make up for even one single page
	free_pf_head = UP_TO_PAGE(p_brk) >> PAGESHIFT;
	for (i = free_pf_head; i < (DOWN_TO_PAGE(p_limit) >> PAGESHIFT) - 1; i++) {
		*(long *)((long)i * PAGESIZE) = i + 1;
	}
	*(long *)((long)i * PAGESIZE) = MEM_INVALID_PAGES + 1;
	for (i = MEM_INVALID_PAGES + 1; i < (DOWN_TO_PAGE(KERNEL_STACK_BASE) >> PAGESHIFT) - 1; i++) {
		*(long *)((long)i * PAGESIZE) = i + 1;
	}
	free_pf_tail = i;
}

extern int SetKernelBrk(void *addr) {
	if (!v_enabled) {
		if (addr >= p_base && addr <= p_limit) {
			p_brk = addr;
			return 0;
		}
		else {
			perror("Brk out of bound.");
			return -1;
		}
	}
	return 0;
}