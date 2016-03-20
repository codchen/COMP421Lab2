#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <comp421/loadinfo.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

/* Type definitions */
typedef void (*trap_handler)(ExceptionStackFrame *frame);   // definition of trap handlers
typedef struct child_exit_info {
    int pid;
    int status;
    struct child_exit_info *next;
} cei;
typedef struct pcb {
    SavedContext *ctx;
    void *pt_physical_addr;
    int pid;
    char state; //RUNNING is 0, READY is 1, WAITBLOCK is 2
    long time_to_switch;
    int nchild;
    struct pcb *next;
    struct pcb *parent;
    cei *exited_children_head;
    cei *exited_children_tail;
    //TODO: user brk
    int brk_pn;
    int stack_pn;
} pcb;

/* Kernel Start Methods */
void init_interrupt_vector_table();
void init_initial_page_tables();
void init_free_page_list();
void enable_VM();

/* Program Loading Method */
void load_program_from_file(char *names, char **args, ExceptionStackFrame* frame);
int LoadProgram(char *name, char **args, ExceptionStackFrame* frame, int *brk_pn);   // from load template 

/* Memory Management Util Methods */
void free_page_enq(int isregion1, int vpn); // Add a physical page corresponding to vpn to free page list
int free_page_deq(int isregion1, int vpn, int kprot, int uprot); // Assign a physical page to input vpn's pte entry

/* Trap Handlers*/
void trap_kernel_handler(ExceptionStackFrame *frame);
void trap_clock_handler(ExceptionStackFrame *frame);
void trap_illegal_handler(ExceptionStackFrame *frame);
void trap_memory_handler(ExceptionStackFrame *frame);
void trap_math_handler(ExceptionStackFrame *frame);
void trap_tty_receive_handler(ExceptionStackFrame *frame);
void trap_tty_transmit_handler(ExceptionStackFrame *frame);

/* Global Variables */
void *kernel_break = 0; // brk address of kernel
void *pmem_limit = 0;   // the limit of physical address, will be assigned by KernelStart
int num_free_pages = 0;
int vm_enabled = 0;
struct pte *region_0_pt, *region_1_pt;
int free_page_head = -1;    // the pfn of the head of free page linked list
long sys_time = 0;  // system time


pcb *running_block;
pcb *ready_head, *ready_tail;
pcb *delay_head, *delay_tail;
pcb *tty_head[NUM_TERMINALS], *tty_tail[NUM_TERMINALS];

extern void KernelStart(ExceptionStackFrame *frame, unsigned int pmem_size, void *orig_brk, char **cmd_args) {
    kernel_break = orig_brk;
    pmem_limit = (void *)((long)PMEM_BASE + pmem_size);
    
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
    if (!vm_enabled) {
        addr = (void *)((long)UP_TO_PAGE((long)addr));
        kernel_break = addr;
        return 0;
    }
    else {
        int i;
        if (addr > kernel_break) {
            printf("case 1\n");
            for (i = (UP_TO_PAGE(kernel_break) - VMEM_REGION_SIZE) >> PAGESHIFT; i <= (DOWN_TO_PAGE(addr) - VMEM_REGION_SIZE) >> PAGESHIFT; i++) {
                printf("%d\n", i);
                if (free_page_deq(1, i, PROT_READ | PROT_WRITE, 0) < 0) {
                    return -1;
                }
            }
        }
        else {
            printf("case 2\n");
            for (i = (DOWN_TO_PAGE(kernel_break) - VMEM_REGION_SIZE) >> PAGESHIFT; i >= (UP_TO_PAGE(addr) - VMEM_REGION_SIZE) >> PAGESHIFT; i--) {
                printf("%d\n", i); 
                free_page_enq(1, i);
            }
        }
        kernel_break = addr;
        return 0;
    }
}



/* KernalStart Method Series */
void init_interrupt_vector_table() {
    trap_handler *interrupt_vector_table = (trap_handler *) calloc(TRAP_VECTOR_SIZE, sizeof(trap_handler));
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
    region_0_pt = (struct pte *) calloc(2, PAGE_TABLE_SIZE);
    region_1_pt = (struct pte *)((long)region_0_pt + PAGE_TABLE_SIZE);

    // setup initial ptes in region 1 page table and region 0 page table
    int page_itr;

    // init region 0 page table
    for (page_itr = 0; page_itr < KERNEL_STACK_PAGES; page_itr++) {  
        int index = (VMEM_REGION_SIZE >> PAGESHIFT) - page_itr - 1;
        region_0_pt[index].pfn = index;
        region_0_pt[index].uprot = 0;
        region_0_pt[index].kprot = PROT_READ | PROT_WRITE;
        region_0_pt[index].valid = 1;
    }

    int kernel_base_pfn = VMEM_1_BASE >> PAGESHIFT;
    // init region 1 page table
    for (page_itr = kernel_base_pfn; page_itr < UP_TO_PAGE(kernel_break) >> PAGESHIFT; page_itr++) {
        region_1_pt[page_itr - kernel_base_pfn].pfn = page_itr;
        region_1_pt[page_itr - kernel_base_pfn].uprot = 0;
        region_1_pt[page_itr - kernel_base_pfn].kprot = (page_itr < (UP_TO_PAGE(&_etext) >> PAGESHIFT) ? PROT_READ | PROT_EXEC:PROT_READ | PROT_WRITE);
        region_1_pt[page_itr - kernel_base_pfn].valid = 1;
    }

    WriteRegister(REG_PTR0, (RCS421RegVal)region_0_pt);
    WriteRegister(REG_PTR1, (RCS421RegVal)region_1_pt);
}

void init_free_page_list() {
    free_page_head = UP_TO_PAGE(kernel_break) >> PAGESHIFT;
    int page_itr;
    for (page_itr = free_page_head; page_itr < (DOWN_TO_PAGE(pmem_limit) >> PAGESHIFT) - 1; page_itr++) {
        *(int *)((long)page_itr << PAGESHIFT) = page_itr + 1;
        num_free_pages++;
    }
    *(int *)((long)page_itr << PAGESHIFT) = MEM_INVALID_PAGES;  // link upper freelist to bottom free pages
    num_free_pages++;
    for (page_itr = MEM_INVALID_PAGES; 
            page_itr < (DOWN_TO_PAGE(KERNEL_STACK_BASE) >> PAGESHIFT); 
            page_itr++) {
        if (page_itr != (DOWN_TO_PAGE(KERNEL_STACK_BASE) >> PAGESHIFT) - 1) // last page doesn't have next pointer
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
    int *brk_pn = malloc(sizeof(int));
    *brk_pn = MEM_INVALID_PAGES;
    int init_res = LoadProgram(names, args, frame, brk_pn);
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
    running_block->pt_physical_addr = region_0_pt;
    running_block->pid = 1;
    running_block->state = 0;
    running_block->time_to_switch = sys_time + 2;
    running_block->next = NULL;
    running_block->parent = NULL;
    running_block->exited_children_head = NULL;
    running_block->exited_children_tail = NULL;
    running_block->nchild = 0;
    running_block->brk_pn = *brk_pn;
    running_block->stack_pn = (DOWN_TO_PAGE(frame->sp) >> PAGESHIFT) - 1;
    free(brk_pn);
}

/* Memory Management Util Methods */
/* Given a virtual page number, add its corresponding physical page to free page list */
void free_page_enq(int isregion1, int vpn) {
    struct pte *region = (isregion1 ? region_1_pt : region_0_pt);
    *(int *)((long)(vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE) = free_page_head;
    free_page_head = region[vpn].pfn;
    region[vpn].valid = 0;
    num_free_pages++;
}

/* Given a virtual page number, assign a physical page to its corresponding pte entry */
int free_page_deq(int isregion1, int vpn, int kprot, int uprot) {
    if (num_free_pages == 0) {
        fprintf(stderr, "No enough physical page\n");
        return -1;
    }
    struct pte *region = (isregion1 ? region_1_pt:region_0_pt);
    region[vpn].valid = 1;
    region[vpn].kprot = kprot;
    region[vpn].uprot = uprot;
    region[vpn].pfn = free_page_head;
    free_page_head = *(int *)((long)(vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE);
    num_free_pages--;
    return 0;
}

void print_pt(){
    int i;
    for (i = 0; i < PAGE_TABLE_LEN; i++) {
        if (region_0_pt[i].valid) {
            printf("0:%d->%d\n", i, region_0_pt[i].pfn);
        }
        if (region_1_pt[i].valid) {
            printf("1:%d->%d\n", i, region_1_pt[i].pfn);
        }
    }
}

/* Trap Handlers */
void trap_kernel_handler(ExceptionStackFrame *frame){}
void trap_clock_handler(ExceptionStackFrame *frame){}
void trap_illegal_handler(ExceptionStackFrame *frame){}
void trap_memory_handler(ExceptionStackFrame *frame){}
void trap_math_handler(ExceptionStackFrame *frame){}
void trap_tty_receive_handler(ExceptionStackFrame *frame){}
void trap_tty_transmit_handler(ExceptionStackFrame *frame){}

/* Load Program */
/*
 *  Load a program into the current process's address space.  The
 *  program comes from the Unix file identified by "name", and its
 *  arguments come from the array at "args", which is in standard
 *  argv format.
 *
 *  Returns:
 *      0 on success
 *     -1 on any error for which the current process is still runnable
 *     -2 on any error for which the current process is no longer runnable
 *
 *  This function, after a series of initial checks, deletes the
 *  contents of Region 0, thus making the current process no longer
 *  runnable.  Before this point, it is possible to return ERROR
 *  to an Exec() call that has called LoadProgram, and this function
 *  returns -1 for errors up to this point.  After this point, the
 *  contents of Region 0 no longer exist, so the calling user process
 *  is no longer runnable, and this function returns -2 for errors
 *  in this case.
 */
int LoadProgram(char *name, char **args, ExceptionStackFrame* frame, int* brk_pn) {
    int fd;
    int status;
    struct loadinfo li;
    char *cp;
    char *cp2;
    char **cpp;
    char *argbuf;
    int i;
    unsigned long argcount;
    int size;
    int text_npg;
    int data_bss_npg;
    int stack_npg;
    TracePrintf(0, "LoadProgram '%s', args %p\n", name, args);

    if ((fd = open(name, O_RDONLY)) < 0) {
        TracePrintf(0, "LoadProgram: can't open file '%s'\n", name);
        return (-1);
    }

    status = LoadInfo(fd, &li);
    TracePrintf(0, "LoadProgram: LoadInfo status %d\n", status);
    switch (status) {
        case LI_SUCCESS:
            break;
        case LI_FORMAT_ERROR:
            TracePrintf(0,
                "LoadProgram: '%s' not in Yalnix format\n", name);
            close(fd);
            return (-1);
        case LI_OTHER_ERROR:
            TracePrintf(0, "LoadProgram: '%s' other error\n", name);
            close(fd);
            return (-1);
        default:
            TracePrintf(0, "LoadProgram: '%s' unknown error\n", name);
            close(fd);
            return (-1);
    }
    TracePrintf(0, "text_size 0x%lx, data_size 0x%lx, bss_size 0x%lx\n",
        li.text_size, li.data_size, li.bss_size);
    TracePrintf(0, "entry 0x%lx\n", li.entry);
    /*
     *  Figure out how many bytes are needed to hold the arguments on
     *  the new stack that we are building.  Also count the number of
     *  arguments, to become the argc that the new "main" gets called with.
     */
    size = 0;
    for (i = 0; args[i] != NULL; i++) {
        size += strlen(args[i]) + 1;
    }
    argcount = i;
    TracePrintf(0, "LoadProgram: size %d, argcount %d\n", size, argcount);
    /*
     *  Now save the arguments in a separate buffer in Region 1, since
     *  we are about to delete all of Region 0.
     */
    cp = argbuf = (char *)malloc(size);
    for (i = 0; args[i] != NULL; i++) {
        strcpy(cp, args[i]);
        cp += strlen(cp) + 1;
    }

    /*
     *  The arguments will get copied starting at "cp" as set below,
     *  and the argv pointers to the arguments (and the argc value)
     *  will get built starting at "cpp" as set below.  The value for
     *  "cpp" is computed by subtracting off space for the number of
     *  arguments plus 4 (for the argc value, a 0 (AT_NULL) to
     *  terminate the auxiliary vector, a NULL pointer terminating
     *  the argv pointers, and a NULL pointer terminating the envp
     *  pointers) times the size of each (sizeof(void *)).  The
     *  value must also be aligned down to a multiple of 8 boundary.
     */
    cp = ((char *)USER_STACK_LIMIT) - size;
    cpp = (char **)((unsigned long)cp & (-1 << 4)); /* align cpp */
    cpp = (char **)((unsigned long)cpp - ((argcount + 4) * sizeof(void *)));

    text_npg = li.text_size >> PAGESHIFT;
    data_bss_npg = UP_TO_PAGE(li.data_size + li.bss_size) >> PAGESHIFT;
    stack_npg = (USER_STACK_LIMIT - DOWN_TO_PAGE(cpp)) >> PAGESHIFT;

    TracePrintf(0, "LoadProgram: text_npg %d, data_bss_npg %d, stack_npg %d\n",
       text_npg, data_bss_npg, stack_npg);

    /*
     *  Make sure we will leave at least one page between heap and stack
     */
    if (MEM_INVALID_PAGES + text_npg + data_bss_npg + stack_npg +
        1 + KERNEL_STACK_PAGES >= PAGE_TABLE_LEN) {
        TracePrintf(0, "LoadProgram: program '%s' size too large for VM\n",
           name);
        free(argbuf);
        close(fd);
        return (-1);
    }

    /*
     *  And make sure there will be enough physical memory to
     *  load the new program.
     */
    // >>>> The new program will require text_npg pages of text,
    // >>>> data_bss_npg pages of data/bss, and stack_npg pages of
    // >>>> stack.  In checking that there is enough free physical
    // >>>> memory for this, be sure to allow for the physical memory
    // >>>> pages already allocated to this process that will be
    // >>>> freed below before we allocate the needed pages for
    // >>>> the new program being loaded.
    if (text_npg + data_bss_npg + stack_npg > num_free_pages) {
        TracePrintf(0,
            "LoadProgram: program '%s' size too large for physical memory\n",
            name);
        free(argbuf);
        close(fd);
        return (-1);
    }

    // >>>> Initialize sp for the current process to (char *)cpp.
    // >>>> The value of cpp was initialized above.
    frame->sp = (char *)cpp;
    /*
     *  Free all the old physical memory belonging to this process,
     *  but be sure to leave the kernel stack for this process (which
     *  is also in Region 0) alone.
     */
    // >>>> Loop over all PTEs for the current process's Region 0,
    // >>>> except for those corresponding to the kernel stack (between
    // >>>> address KERNEL_STACK_BASE and KERNEL_STACK_LIMIT).  For
    // >>>> any of these PTEs that are valid, free the physical memory
    // >>>> memory page indicated by that PTE's pfn field.  Set all
    // >>>> of these PTEs to be no longer valid.
    for (i = MEM_INVALID_PAGES; i < KERNEL_STACK_BASE >> PAGESHIFT; i++) {
        if (region_0_pt[i].valid) {
            free_page_enq(0, i);
        }
    }

    /*
     *  Fill in the page table with the right number of text,
     *  data+bss, and stack pages.  We set all the text pages
     *  here to be read/write, just like the data+bss and
     *  stack pages, so that we can read the text into them
     *  from the file.  We then change them read/execute.
     */

    // >>>> Leave the first MEM_INVALID_PAGES number of PTEs in the
    // >>>> Region 0 page table unused (and thus invalid)
     for (i = 0; i < MEM_INVALID_PAGES; i++) {
        region_0_pt[i].valid = 0;
    }

    /* First, the text pages */
    // >>>> For the next text_npg number of PTEs in the Region 0
    // >>>> page table, initialize each PTE:
    // >>>>     valid = 1
    // >>>>     kprot = PROT_READ | PROT_WRITE
    // >>>>     uprot = PROT_READ | PROT_EXEC
    // >>>>     pfn   = a new page of physical memory
    for (i = MEM_INVALID_PAGES; i < MEM_INVALID_PAGES + text_npg; i++) {
        *brk_pn = *brk_pn + 1;
        if (free_page_deq(0, i, PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC) < 0) {
            free(argbuf);
            close(fd);
            return (-2);
        }
    }


    /* Then the data and bss pages */
    // >>>> For the next data_bss_npg number of PTEs in the Region 0
    // >>>> page table, initialize each PTE:
    // >>>>     valid = 1
    // >>>>     kprot = PROT_READ | PROT_WRITE
    // >>>>     uprot = PROT_READ | PROT_WRITE
    // >>>>     pfn   = a new page of physical memory

    for (i = MEM_INVALID_PAGES + text_npg; i < MEM_INVALID_PAGES + text_npg + data_bss_npg; i++) {
        *brk_pn = *brk_pn + 1;
        if (free_page_deq(0, i, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE) < 0) {
            free(argbuf);
            close(fd);
            return (-2);
        }
    }

    /* And finally the user stack pages */
    // >>>> For stack_npg number of PTEs in the Region 0 page table
    // >>>> corresponding to the user stack (the last page of the
    // >>>> user stack *ends* at virtual address USER_STACK_LMIT),
    // >>>> initialize each PTE:
    // >>>>     valid = 1
    // >>>>     kprot = PROT_READ | PROT_WRITE
    // >>>>     uprot = PROT_READ | PROT_WRITE
    // >>>>     pfn   = a new page of physical memory

    for (i = 0; i < stack_npg; i++) {
        int index = (USER_STACK_LIMIT >> PAGESHIFT) - 1 - i;
        if (free_page_deq(0, index, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE) < 0) {
            free(argbuf);
            close(fd);
            return (-2);
        }
    }
    /*
     *  All pages for the new address space are now in place.  Flush
     *  the TLB to get rid of all the old PTEs from this process, so
     *  we'll be able to do the read() into the new pages below.
     */
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    /*
     *  Read the text and data from the file into memory.
     */
    if (read(fd, (void *)MEM_INVALID_SIZE, li.text_size+li.data_size)
        != li.text_size+li.data_size) {
        TracePrintf(0, "LoadProgram: couldn't read for '%s'\n", name);
        free(argbuf);
        close(fd);
    // >>>> Since we are returning -2 here, this should mean to
    // >>>> the rest of the kernel that the current process should
    // >>>> be terminated with an exit status of ERROR reported
    // >>>> to its parent process.
        return (-2);
    }

    close(fd);          /* we've read it all now */

    /*
     *  Now set the page table entries for the program text to be readable
     *  and executable, but not writable.
     */
    // >>>> For text_npg number of PTEs corresponding to the user text
    // >>>> pages, set each PTE's kprot to PROT_READ | PROT_EXEC.
    for (i = MEM_INVALID_PAGES; i < MEM_INVALID_PAGES + text_npg; i++) {
        region_0_pt[i].kprot = PROT_READ | PROT_EXEC;
    }

    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    /*
     *  Zero out the bss
     */
    memset((void *)(MEM_INVALID_SIZE + li.text_size + li.data_size),
         '\0', li.bss_size);

    /*
     *  Set the entry point in the exception frame.
     */
    //>>>> Initialize pc for the current process to (void *)li.entry
    frame->pc = (void *)li.entry;

    /*
     *  Now, finally, build the argument list on the new stack.
     */
    *cpp++ = (char *)argcount;      /* the first value at cpp is argc */
    cp2 = argbuf;
    for (i = 0; i < argcount; i++) {      /* copy each argument and set argv */
        *cpp++ = cp;
        strcpy(cp, cp2);
        cp += strlen(cp) + 1;
        cp2 += strlen(cp2) + 1;
    }
    free(argbuf);
    *cpp++ = NULL;  /* the last argv is a NULL pointer */
    *cpp++ = NULL;  /* a NULL pointer for an empty envp */
    *cpp++ = 0;     /* and terminate the auxiliary vector */

    /*
     *  Initialize all regs[] registers for the current process to 0,
     *  initialize the PSR for the current process also to 0.  This
     *  value for the PSR will make the process run in user mode,
     *  since this PSR value of 0 does not have the PSR_MODE bit set.
     */
    // >>>> Initialize regs[0] through regs[NUM_REGS-1] for the
    // >>>> current process to 0.
    // >>>> Initialize psr for the current process to 0.
    for (i = 0; i < NUM_REGS; i++) {
        frame->regs[i] = 0;
    }
    frame->psr = 0;
    return (0);
}
