#include <stdlib.h>
#include "yalnix_core.h"

void *free_page_head = -1;	// the pfn of the head of free page linked list

pcb *running_block;
pcb *ready_head, *ready_tail;
pcb *delay_head, *delay_tail;
pcb *tty_head[NUM_TERMINALS], *tty_tail[NUM_TERMINALS];

/* KernalStart Method Series */
void init_interrupt_vector_table() {
	trap_handler *interrupt_vector_table = (trap_handler *) calloc(TRAP_VECTOR_SIZE, sizeof(trap_handler))
	interrupt_vector_table[TRAP_KERNEL] = trap_kernel_handler;
	interrupt_vector_table[TRAP_CLOCK] = trap_clock_handler;
	interrupt_vector_table[TRAP_ILLEGAL] = trap_illegal_handler;
	interrupt_vector_table[TRAP_MEMORY] = trap_memory_handler;
	interrupt_vector_table[TRAP_MATH] = trap_math_handler;
	interrupt_vector_table[TRAP_TTY_RECEIVE] = trap_tty_receive_handler;
	interrupt_vector_table[TRAP_TTY_TRANSMIT] = trap_tty_transmit_handler;
	WriteRegister(REG_VECTOR_BASE, (RCS421RegVal)interrupt_vector_table);
}

void init_initial_page_tables() {
	// two page tables make up to one page, placed below kernel stack
	region_0_pt = (struct pte *)((long)VMEM_0_LIMIT - KERNEL_STACK_SIZE - PAGE_SIZE);
	region_1_pt = (struct pte *)((long)region_0_pt + PAGE_TABLE_SIZE);

	// setup initial ptes in region 1 page table and region 0 page table
	long pt_addr;
	struct pte *cur_pte;
	for (pt_addr = ((long)region_1_pt) - KERNEL_STACK_SIZE; 
			pt_addr < UP_TO_PAGE(kernel_break); pt_addr += PAGE_SIZE) {
		cur_pte = (struct pte *) pt_addr;
		cur_pte->valid = 1;
		cur_pte->pfn = pt_addr >> PAGESHIFT;
		cur_pte->uprot = 0;
		if (pt_addr < KERNEL_STACK_LIMIT) {		// region 0 page table
			region_0_pt[index].kprot = PROT_READ | PROT_WRITE;	
		} else {	// region 1 page table
			cur_pte->kprot = ((pt_addr < &_etext) ? PROT_READ|PROT_EXEC : PROT_READ|PROT_WRITE);
		}
	}
	WriteRegister(REG_PTR0, (RCS421RegVal)region_0_pt);
	WriteRegister(REG_PTR1, (RCS421RegVal)region_1_pt);
}

void init_free_page_list() {
	free_page_head = UP_TO_PAGE(kernel_break) >> PAGESHIFT;
	void *page_itr;
	for (page_itr = free_page_head; page_itr < DOWN_TO_PAGE(pmem_limit) >> PAGESHIFT - 1; page_itr++) {
		*(int *)((long)page_itr << PAGESHIFT) = page_itr + 1;
		num_free_pages++;
	}
	*(int *)(page_itr) = MEM_INVALID_PAGES;	// link upper freelist to bottom free pages
	num_free_pages++;
	for (page_itr = MEM_INVALID_PAGES; 
			page_itr < DOWN_TO_PAGE(KERNEL_STACK_BASE) >> PAGESHIFT - 1; 
			page_itr += PAGE_SIZE) {
		if (page_itr != DOWN_TO_PAGE(KERNEL_STACK_BASE) >> PAGESHIFT - 2)	// last page doesn't have next pointer
			*(int *)((long)page_itr << PAGESHIFT) = page_itr + 1;
		num_free_pages++;
	}
}

void enable_VM() {
	WriteRegister(REG_VM_ENABLE, 1);
	WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_ALL);
	vm_enabled = 1;
}

/* Program Loading Method */
void load_program_from_file(char *names, char **args, ExceptionStackFrame* frame) {
	int init_res = LoadProgram(names, args, frame);
	if (init_res < 0) {
		fprintf(stderr, "Load init failed: %d\n", init_res);
		return;
	}
	running_block = malloc(sizeof(pcb));
	if (running_block == NULL) {
		fprintf(stderr, "Faliled malloc pcb for new program\n");
		return;
	}

	running_block->ctx = malloc(sizeof(SavedContext));
	if (running_block->ctx == NULL) {
		fprintf(stderr, "Failed malloc ctx for new program\n");
		return;
	}
	
	running_block->two_times_pfn_of_pt0 = region_0_pt >> PAGESHIFT << 1;	// WHAT'S THIS....
	running_block->pid = 1;
	running_block->state = 0;
	running_block->time_to_switch = time + 2;
	running_block->next = NULL;
	running_block->parent = NULL;
	running_block->exited_children_head = NULL;
	running_block->exited_children_tail = NULL;
	running_block->nchild = 0;
}

/* Memory Management Util Methods */
/* Given a virtual page number, add its corresponding physical page to free page list */
void free_page_enq(int isregion1, int vpn) {
	struct pte *region = (isregion1 ? region_1_pt : region_0_pt);
	region[vpn].valid = 0;
	// TODO: *(int *)((long)region[vpn].pfn >> PAGESHIFT) = free_page_head;
    *(int *)((long)(vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE) = free_page_head;
    free_page_head = region[vpn].pfn;
    num_free_pages++;
}

/* Given a virtual page number, assign a physical page to its corresponding pte entry */
int free_page_deq(int isregion1, int vpn, int kprot, int uprot) {
	if (free_pfn == 0) {
		fprintf(stderr, "No enough physical page\n");
        return -1;
    }
    struct pte *region = (isregion1 ? region_1_pt:region_0_pt);
    region[vpn].valid = 1;
    region[vpn].kprot = kprot;
    region[vpn].uprot = uprot;
    region[vpn].pfn = free_pf_head;
    // TODO: free_page_head = *(int *)((long)region[vpn].pfn >> PAGESHIFT);
    free_page_head = *(int *)((long)(vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE);
    num_free_pages--;
    return 0;
}


/* Trap Handlers */
void trap_kernel_handler(ExceptionStackFrame *frame){}
void trap_clock_handler(ExceptionStackFrame *frame){}
void trap_illegal_handler(ExceptionStackFrame *frame){}
void trap_memory_handler(ExceptionStackFrame *frame){}
void trap_math_handler(ExceptionStackFrame *frame){}
void trap_tty_receive_handler(ExceptionStackFrame *frame){}
void trap_tty_transmit_handler(ExceptionStackFrame *frame){}