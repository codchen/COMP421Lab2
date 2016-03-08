#include <stdlib.h>
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

extern void KernelStart(ExceptionStackFrame * frame, unsigned int pmem_size, void *orig_brk, char **cmd_args) {
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

}

extern int SetKernelBrk(void *addr) {
	return 0;
}