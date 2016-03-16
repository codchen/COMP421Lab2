#include <stdlib.h>
#include "yalnix_core.h"

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
	long region_0_pt_addr = VMEM_0_LIMIT - KERNEL_STACK_SIZE - PAGE_SIZE;
	long region_1_pt_addr = region_0_pt_addr + PAGE_TABLE_SIZE;
	WriteRegister(REG_PTR0, (RCS421RegVal)region_0_pt_addr);
	WriteRegister(REG_PTR1, (RCS421RegVal)region_1_pt_addr);

	// setup initial ptes in region 1 page table and region 0 page table
	long pt_addr;
	struct pte *cur_pte;
	for (pt_addr = region_1_pt_addr - KERNEL_STACK_SIZE; pt_addr < UP_TO_PAGE(kernel_break);  pt_addr += PAGE_SIZE) {
		cur_pte = (struct pte *) pt_addr;
		cur_pte->valid = 1;
		cur_pte->pfn = pt_addr >> PAGESHIFT;
		cur_pte->uprot = 0;
		if (pt_addr < KERNEL_STACK_LIMIT) {		// region 0 page table
			region0[index].kprot = PROT_READ | PROT_WRITE;	
		} else {	// region 1 page table
			cur_pte->kprot = ((pt_addr < &_etext) ? PROT_READ|PROT_EXEC : PROT_READ|PROT_WRITE);
		}
	}
	WriteRegister(REG_PTR0, (RCS421RegVal)region_0_pt_addr);
	WriteRegister(REG_PTR1, (RCS421RegVal)region_1_pt_addr);
}

void init_free_page_list() {
	free_page_head = UP_TO_PAGE(kernel_break);
	void *page_itr;
	for (page_itr = free_page_head; page_itr < DOWN_TO_PAGE(pmem_limit) - PAGE_SIZE; page_itr += PAGE_SIZE) {
		*(int *)(page_itr) = page_itr >> PAGESHIFT + 1;
		num_free_pages++;
	}
	*(int *)(page_itr) = MEM_INVALID_PAGES;	// link upper freelist to bottom free pages
	num_free_pages++;
	for (page_itr = MEM_INVALID_PAGES << PAGESHIFT; 
			page_itr < DOWN_TO_PAGE(KERNEL_STACK_BASE) - PAGE_SIZE; 
			page_itr += PAGE_SIZE) {
		if (page_itr != DOWN_TO_PAGE(KERNEL_STACK_BASE) - 2 * PAGE_SIZE)	// last page doesn't have next pointer
			*(int *)((long)page_itr << PAGESHIFT) = page_itr + 1;
		num_free_pages++;
	}
}

void enable_VM() {
	WriteRegister(REG_VM_ENABLE, 1);
	WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_ALL);
	vm_enabled = 1;
}


/* Trap Handlers */
void trap_kernel_handler(ExceptionStackFrame *frame){}
void trap_clock_handler(ExceptionStackFrame *frame){}
void trap_illegal_handler(ExceptionStackFrame *frame){}
void trap_memory_handler(ExceptionStackFrame *frame){}
void trap_math_handler(ExceptionStackFrame *frame){}
void trap_tty_receive_handler(ExceptionStackFrame *frame){}
void trap_tty_transmit_handler(ExceptionStackFrame *frame){}