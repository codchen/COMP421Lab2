#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>
#include "yalnix_core.h"


extern void KernelStart(ExceptionStackFrame *frame, unsigned int pmem_size, void *orig_brk, char **cmd_args) {
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

	// init idle process

	// load first program
	load_program_from_file(cmd_args[0], cmd_args, frame);

}

extern int SetKernelBrk(void *addr) {
	if ((long)addr < VMEM_1_BASE && (long)addr >= VMEM_1_LIMIT) {
		fprintf(stderr, "Brk out of bound for kernel.\n");
		return -1;
	}
	if (!v_enabled) {
		kernel_break = addr;
		return 0;
	}
	else {
		int i;
		if (addr > kernel_break) {
			for (i = (UP_TO_PAGE(kernel_break) - VMEM_REGION_SIZE) >> PAGESHIFT; i <= (DOWN_TO_PAGE(addr) - VMEM_REGION_SIZE) >> PAGESHIFT; i++) {
				if (free_page_deq(1, i, PROT_READ | PROT_WRITE, 0) < 0) {
					return -1;
				}
			}
		}
		else {
			for (i = (DOWN_TO_PAGE(kernel_break) - VMEM_REGION_SIZE) >> PAGESHIFT; i >= (UP_TO_PAGE(addr) - VMEM_REGION_SIZE) >> PAGESHIFT; i--) {
				free_page_enq(1, i);
			}
		}
		kernel_break = addr;
		return 0;
	}
}
