#include <comp421/yalnix.h>
#include <comp421/hardware.h>

/* Type definitions */
typedef void (*trap_handler)(ExceptionStackFrame *frame);	// definition of trap handlers
typedef struct pcb {
	SavedContext *ctx;
	int two_times_pfn_of_pt0; //since the page table may be located from the middle of a page 
	int pid;
	char state; //RUNNING is 0, READY is 1, WAITBLOCK is 2
	long time_to_switch;
	int nchild;
	struct pcb *next;
	struct pcb *parent;
	cei *exited_children_head;
	cei *exited_children_tail;
	//TODO: user brk
} pcb;
typedef struct child_exit_info {
	int pid;
	int status;
	struct child_exit_info *next;
} cei;

/* Kernel Start Methods */
void init_interrupt_vector_table();
void init_initial_page_tables();
void init_free_page_list();
void enable_VM();

/* Trap Handlers*/
void trap_kernel_handler(ExceptionStackFrame *frame);
void trap_clock_handler(ExceptionStackFrame *frame);
void trap_illegal_handler(ExceptionStackFrame *frame);
void trap_memory_handler(ExceptionStackFrame *frame);
void trap_math_handler(ExceptionStackFrame *frame);
void trap_tty_receive_handler(ExceptionStackFrame *frame);
void trap_tty_transmit_handler(ExceptionStackFrame *frame);

/* Global Variables */
extern void *kernel_break = 0;	// brk address of kernel
extern void *pmem_limit = -1;	// the limit of physical address, will be assigned by KernelStart
void *free_page_head = -1;	// the head of free page linked list
extern int num_free_pages = 0;
extern int vm_enabled = 0;