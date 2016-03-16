#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>
#include "yalnix_core.h"


void KernelStart(ExceptionStackFrame *frame, unsigned int pmem_size, void *orig_brk, char **cmd_args) {
	kernel_break = orig_brk;
	pmem_limit = PMEM_BASE + pmem_size;
	
	// initialize interrupt vector table
	init_interrupt_vector_table();

	// initialize region 1 & region 0 page table
	// two page tables make up to one page, placed below kernel stack
	init_initial_page_tables();

	// make a list of free physical pages
	init_free_page_list();

	// enable VM
	enable_VM();

	// 
}
