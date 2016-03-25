#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <comp421/loadinfo.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

#define REGION_0 0
#define REGION_1 1
#define INIT_PROC 0
#define NORMAL_PROC 1

#define PCB_TERMINATED  -1
#define PCB_RUNNING 0
#define PCB_READY 1
#define PCB_WAITBLOC 2

#define READY_Q NUM_TERMINALS * 2
#define DELAY_Q READY_Q + 1

#define READ_WRITE_PERM PROT_READ|PROT_WRITE

/* Type definitions */
typedef void (*trap_handler)(ExceptionStackFrame *frame);   // definition of trap handlers

typedef struct child_exit_info {
    int pid;
    int status;
    struct child_exit_info *next;
} cei;

typedef struct pcb {
    SavedContext *ctx;
    void *pt_phys_addr;
    int pid;
    int state; //TERMINATED is -1, RUNNING is 0, READY is 1, WAITBLOCK is 2
    long time_to_switch;
    int nchild;
    struct pcb *next;
    struct pcb *parent;
    struct pcb *child;
    struct pcb *sibling;
    cei *exited_children_head;
    cei *exited_children_tail;
    //TODO: user brk
    int brk_pn;
    int stack_pn;
} pcb;

typedef struct line {
    void *buf;
    int cur;
    int len;
    struct line next;
} line;

/* Kernel Start Methods */
void init_interrupt_vector_table();
void init_initial_page_tables();
void init_free_page_list();
void enable_VM();

/* utils */
void print_pt();
void *v2p(void *vaddr);

/* Program/process Related Methods */
int load_program_from_file(char *names, char **args);
int LoadProgram(char *name, char **args, int *brk_pn);   // from load template 
pcb *init_pcb(void *pt_addr, int pid, int is_init_proc);    // initialize pcb
pcb *get_next_proc_on_queue(int whichQ);
void add_next_proc_on_queue(int whichQ, pcb *toadd);

/* Memory Management Util Methods */
void free_page_enq(int isregion1, int vpn); // Add a physical page corresponding to vpn to free page list
int free_page_deq(int isregion1, int vpn, int kprot, int uprot); // Assign a physical page to input vpn's pte entry
void set_pte(int isregion1, int vpn, int kprot, int uprot, int pfn);
void clear_pte(int isregion1, int vpn);
void *allocate_physical_pt();
void add_half_free_pt(void *physical_pt);
int read_from_pfn(void *physical_addr);
void write_to_pfn(void *physical_addr, int towrite);
void validate_region_0_pt();   // set valid bit of region_0_pt pte to 1

/* Trap Handlers*/
void trap_kernel_handler(ExceptionStackFrame *frame);
void trap_clock_handler(ExceptionStackFrame *frame);
void trap_illegal_handler(ExceptionStackFrame *frame);
void trap_memory_handler(ExceptionStackFrame *frame);
void trap_math_handler(ExceptionStackFrame *frame);
void trap_tty_receive_handler(ExceptionStackFrame *frame);
void trap_tty_transmit_handler(ExceptionStackFrame *frame);

/* Kernel Calls */
extern int Fork(void);
extern int Exec(char *, char **);
extern void Exit(int) __attribute__ ((noreturn));
extern int Wait(int *);
extern int GetPid(void);
extern int Brk(void *);
extern int Delay(int);
extern int TtyRead(int, void *, int);
extern int TtyWrite(int, void *, int);

int check_buffer(void *buf, int len, int prot);
int check_string(char *string);


/* Switch Function*/
SavedContext *MySwitchFunc(SavedContext *ctxp, void *p1, void *p2);

/* Global Variables */
void *kernel_break = 0; // brk address of kernel
void *pmem_limit = 0;   // the limit of physical address, will be assigned by KernelStart
int num_free_pages = 0;
int vm_enabled = 0;
struct pte *region_0_pt, *region_1_pt;
int free_page_head = -1;    // the pfn of the head of free page linked list
unsigned long sys_time = 0;  // system time
int next_pid = 0;
int upper_next_pt_pfn = -1, lower_next_pt_pfn = -1;     // upper & lower half empty page table linked list

ExceptionStackFrame *EXCEPTION_FRAME_ADDR; //need further check!!!

pcb *running_block = NULL; //when updated, update region_0_pt also!!!
pcb *ready_head = NULL, *ready_tail = NULL;
pcb *delay_head = NULL, *delay_tail = NULL; //Delay function should keep this list sorted
pcb *tty_head[NUM_TERMINALS * 2], *tty_tail[NUM_TERMINALS * 2]; //first NUM_TERMINALS are for receiving; second NUM_TERMINALS are for transmiting
pcb *tty_transmiting[NUM_TERMINALS];
pcb *idle_pcb = NULL;

line *line_head = NULL, *line_tail = NULL;

int init_returned = 0;

extern void KernelStart(ExceptionStackFrame *frame, unsigned int pmem_size, void *orig_brk, char **cmd_args) {
    EXCEPTION_FRAME_ADDR = frame;
    kernel_break = orig_brk;
    pmem_limit = (void *)((long)PMEM_BASE + pmem_size);
    tty_head = calloc(2 * NUM_TERMINALS, sizeof(pcb *));
    if (tty_head == NULL) {
        fprintf(stderr, "Not enough memory for initialize kernel.\n");
        return;
    }
    tty_tail = calloc(2 * NUM_TERMINALS, sizeof(pcb *));
    if (tty_tail == NULL) {
        fprintf(stderr, "Not enough memory for initialize kernel.\n");
        return;
    }
    tty_transmiting = calloc(NUM_TERMINALS, sizeof(pcb *));
    if (tty_transmiting == NULL) {
        fprintf(stderr, "Not enough memory for initialize kernel.\n");
        return;
    }

    // initialize interrupt vector table
    init_interrupt_vector_table();
    // initialize region 1 & region 0 page table. they are located at the top of region 1
    init_initial_page_tables();
    // make a list of free physical pages
    init_free_page_list();
    // enable VM
    enable_VM();

    // new exceptionframe
    // init idle process
    char *idle_proc = "idle";
    void *new_region0 = allocate_physical_pt();
    if (new_region0 == NULL) {
        fprintf(stderr, "Error allocate free physical page table\n");
        return;
    }
    idle_pcb = init_pcb(new_region0, next_pid++, NORMAL_PROC);
    if (init_returned) {
        char **args = calloc(1, sizeof(char *));
        if (args == NULL) return;
        args[0] = NULL;
        load_program_from_file(idle_proc, args);
        free(args);
    } else {
        init_returned = 1;
        running_block = init_pcb((void *)(DOWN_TO_PAGE(pmem_limit) - 2 * PAGESIZE), next_pid++, INIT_PROC);
        load_program_from_file(cmd_args[0], cmd_args);
    }
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
            for (i = (UP_TO_PAGE(kernel_break) - VMEM_1_BASE) >> PAGESHIFT; 
                    i <= (DOWN_TO_PAGE(addr) - VMEM_1_BASE) >> PAGESHIFT; i++) {
                if (free_page_deq(REGION_1, i, PROT_READ | PROT_WRITE, 0) < 0) {
                    return -1;
                }
            }
        }
        else {
            printf("case 2\n");
            for (i = (DOWN_TO_PAGE(kernel_break) - VMEM_REGION_SIZE) >> PAGESHIFT; i >= (UP_TO_PAGE(addr) - VMEM_REGION_SIZE) >> PAGESHIFT; i--) {
                free_page_enq(REGION_1, i);
            }
        }
        kernel_break = (void *)UP_TO_PAGE(addr);
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
    // initial region 0 & 1 page tables are placed at the top page of region 1
    region_0_pt = (struct pte *)(DOWN_TO_PAGE(pmem_limit) - 2 * PAGESIZE);
    region_1_pt = (struct pte *)(DOWN_TO_PAGE(pmem_limit) - PAGESIZE);

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

    // init pte for two page tables
    int region_1_pt_idx = (VMEM_REGION_SIZE >> PAGESHIFT) - 1;
    int region_0_pt_idx = region_1_pt_idx - 1;

    region_1_pt[region_0_pt_idx].pfn = (long)region_0_pt >> PAGESHIFT;
    region_1_pt[region_0_pt_idx].uprot = 0;
    region_1_pt[region_0_pt_idx].kprot = READ_WRITE_PERM;
    region_1_pt[region_0_pt_idx].valid = 1;

    region_1_pt[region_1_pt_idx].pfn = (long)region_1_pt >> PAGESHIFT;
    region_1_pt[region_1_pt_idx].uprot = 0;
    region_1_pt[region_1_pt_idx].kprot = READ_WRITE_PERM;
    region_1_pt[region_1_pt_idx].valid = 1;

    WriteRegister(REG_PTR0, (RCS421RegVal)region_0_pt);
    WriteRegister(REG_PTR1, (RCS421RegVal)region_1_pt);
}

void init_free_page_list() {
    free_page_head = UP_TO_PAGE(kernel_break) >> PAGESHIFT;
    int page_itr;
    for (page_itr = free_page_head; page_itr < ((long)region_0_pt >> PAGESHIFT) - 1; page_itr++) {
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
    region_0_pt = (struct pte *) (VMEM_1_LIMIT - 2 * PAGESIZE);
    region_1_pt = (struct pte *) (VMEM_1_LIMIT - PAGESIZE);
    WriteRegister(REG_VM_ENABLE, 1);
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_ALL);
    vm_enabled = 1;
}

/* Context switch methods */
SavedContext *MySwitchFunc(SavedContext *ctxp, void *p1, void *p2) {
    pcb *pp1 = (pcb *)p1;
    pcb *pp2 = (pcb *)p2;
    if (pp1 == pp2) return pp1->ctx; //initialize SavedContext for currently running process
    if (pp2 == NULL) {               //initialize SavedContext and copy kernel stack for a newly created (not running) process
        printf("Initializing process...\n");
        int i;
        for (i = 0; i < KERNEL_STACK_PAGES; i++) {
            if ((long)kernel_break >= VMEM_LIMIT) {
                fprintf(stderr, "Kernel virtual space full, cannot copy kernel stack\n");
                // TODO: I don't think break is enough, maybe return error?
                break;
            }
            int pt_index = PAGE_TABLE_LEN - 1 - i;
            int k_index = UP_TO_PAGE(kernel_break - VMEM_1_BASE) >> PAGESHIFT;
            int pfn = free_page_deq(REGION_1, k_index, PROT_ALL, PROT_NONE);    // deq a free page from region 1
            if (pfn < 0) {
                fprintf(stderr, "cannot copy kernel stack\n");
                break;
            }
            memcpy((void *)((long)(UP_TO_PAGE(kernel_break))), (void *)((long)(pt_index << PAGESHIFT)), PAGESIZE);
            clear_pte(REGION_1, k_index);

            set_pte(REGION_1, k_index, PROT_ALL, PROT_NONE, (long)(pp1->pt_phys_addr) >> PAGESHIFT);
            struct pte *pp1_pt_virtual_addr = (struct pte *)((long)(UP_TO_PAGE(kernel_break)) + (long)(pp1->pt_phys_addr) % PAGESIZE);
            pp1_pt_virtual_addr[pt_index].valid = 1;
            pp1_pt_virtual_addr[pt_index].kprot = region_0_pt[pt_index].kprot;
            pp1_pt_virtual_addr[pt_index].uprot = region_0_pt[pt_index].uprot;
            pp1_pt_virtual_addr[pt_index].pfn = pfn;
            clear_pte(REGION_1, k_index);
        }
        return pp1->ctx;
    }

    if (pp1->state == PCB_TERMINATED) {
        // free region 0 memory
        int itr;
        for (itr = MEM_INVALID_PAGES; itr < (VMEM_REGION_SIZE >> PAGESHIFT); itr++) {
            free_page_enq(REGION_0, itr);
        }
        // free region 0 page table
        add_half_free_pt(pp1->pt_phys_addr);
        // free pcb
        free(pp1);
    }

    printf("Starts context switching...\n");
    WriteRegister(REG_PTR0, (RCS421RegVal)((long)(pp2->pt_phys_addr)));
    running_block = pp2;
    running_block->time_to_switch = sys_time + 2;
    validate_region_0_pt();
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_0);

    return pp2->ctx;
}

/*************************** Process/program Related Methods ***************************/
/* Initialize a new pcb */
pcb *init_pcb(void *pt_phys_addr, int pid, int is_init_proc) {
    pcb *new_process = malloc(sizeof(pcb));
    if (new_process == NULL) {
        fprintf(stderr, "Faliled malloc pcb for new program\n");
        return NULL;
    }
    new_process->ctx = calloc(1, sizeof(SavedContext));
    if (new_process->ctx == NULL) {
        fprintf(stderr, "Failed malloc ctx for new program\n");
        return NULL;
    }
    new_process->pt_phys_addr = pt_phys_addr;
    new_process->pid = pid;
    new_process->state = 0;
    new_process->time_to_switch = sys_time + 2;
    new_process->next = NULL;
    new_process->parent = NULL;
    new_process->child = NULL;
    new_process->sibling = NULL;
    new_process->exited_children_head = NULL;
    new_process->exited_children_tail = NULL;
    new_process->nchild = 0;
    if (running_block != NULL) {
        new_process->brk_pn = running_block->brk_pn;
        new_process->stack_pn = running_block->stack_pn;
    }
    ContextSwitch(MySwitchFunc, new_process->ctx, (void *)new_process, is_init_proc ? NULL:(void *)new_process);
    return new_process;
}

/* Load a program from file, init the program with given page table */
int load_program_from_file(char *names, char **args) {
    //map physical region 0 to virtual region 0
    validate_region_0_pt(); //Maybe not necessary

    int *brk_pn = malloc(sizeof(int));
    if (brk_pn == NULL) {
        fprintf(stderr, "Malloc failed for loading program.\n");
        return -1;
    }
    *brk_pn = MEM_INVALID_PAGES;
    int init_res = LoadProgram(names, args, brk_pn);
    if (init_res < 0) {
        fprintf(stderr, "Load %s failed: %d\n", names, init_res);
        return -1;
    }
    running_block->brk_pn = *brk_pn;
    running_block->stack_pn = (DOWN_TO_PAGE(((ExceptionStackFrame *)((long)EXCEPTION_FRAME_ADDR))->sp) >> PAGESHIFT) - 1;
    free(brk_pn);
    printf("Successfully load %s into kernel\n", names);
    return 0;
}

/* Given the head and tail of a pcb queue (ready or delay), return the next available process pcb */
pcb *get_next_proc_on_queue(int whichQ) {
    if (whichQ < 0 || whichQ > DELAY_Q) return NULL;
    if (whichQ < READY_Q) {
        pcb *to_return = tty_head[whichQ];
        if (tty_head[whichQ] == tty_tail[whichQ]) tty_head[whichQ] = tty_tail[whichQ] = NULL;
        else tty_head[whichQ] = tty_head[whichQ]->next;
        return to_return;
    }
    else if (whichQ == READY_Q) {
        pcb *to_return = ready_head;
        if (ready_head == ready_tail) ready_head = ready_tail = NULL;
        else ready_head = ready_head->next;
        return (to_return == NULL)?idle:to_return;
    }
    else {
        pcb *to_return = delay_head;
        if (delay_head == delay_tail) delay_head = delay_tail = NULL;
        else delay_head = delay_head->next;
        return to_return;
    }
}

void add_next_proc_on_queue(int whichQ, pcb *toadd) {
    if (whichQ < 0 || whichQ > DELAY_Q) return NULL;
    toadd->next = NULL;
    if (whichQ < READY_Q) {
        if (tty_head[whichQ] == NULL) tty_head[whichQ] = toadd;
        else tty_tail[whichQ]->next = toadd;
        tty_tail[whichQ] = toadd;
    }
    else if (whichQ == READY_Q) {
        if (ready_head == NULL) ready_head = toadd;
        else ready_tail->next = toadd;
        ready_tail = toadd;
    }
    else {
        if (delay_head == NULL) delay_head = delay_tail = toadd;
        else {
            pcb *current = delay_head;
            pcb *next = delay_head->next;
            while (current != NULL) {
                if (toadd->time_to_switch < current->time_to_switch) {
                    toadd->next = current;
                    delay_head = toadd;
                    return;
                }
                else if (next == NULL) {
                    current->next = toadd;
                    delay_tail = toadd;
                    return;
                }
                else if (toadd->time_to_switch < next->time_to_switch) {
                    current->next = toadd;
                    toadd->next = next;
                    return;
                }
                else {
                    current = next;
                    next = next->next;
                }
            }
        }
    }
}

/* Enqueue a new child exit info */
void enq_cei(pcb *parent, cei *info) {
    if (parent->exited_children_head == NULL) {
        parent->exited_children_head = info;
        parent->exited_children_tail = info;
    } else {
        parent->exited_children_tail->next = info;
        parent->exited_children_tail = info;
    }
}

/* Adjust the order of siblings when a child exits */
void adjust_siblings(pcb *parent, pcb *exited_child) {
    pcb *brother = parent->children;
    if (brother == exited_child) {
        parent->children = brother->sibling;
        return;
    }

    while (brother->sibling != exited_child) {
        brother = brother->sibling;
    }
    brother->sibling = exited_child->sibling;
}

/* Terminate the running process by informing its parent and children */
void terminate_process(int status) {
    running_block->state = PCB_TERMINATED;

    // let parent know the process is being terminated
    if (running_block->parent != NULL) {
        cei *info = (cei *) calloc(1, sizeof(struct cei));
        info->pid = running_block->pid;
        info->status = status;
        parent->nchild -= 1;
        enq_cei(running_block->parent, info);
        adjust_siblings(parent, running_block);
    }
    // let children know the process is exiting
    if (running_block->children != NULL) {
        pcb *child = running_block->children;
        while (child != NULL) {
            child->parent = NULL;
            child = child->sibling;
        }
    }
    // memory related operation will be performed in context switch
}

/************************ Trap Handlers *************************/

//may need to terminate malfunctional process in this handler
void trap_kernel_handler(ExceptionStackFrame *frame){
    printf("Trapped Kernel Handler...\n");
    int code = frame->code;
    switch(code) {
        case YALNIX_FORK:
            frame->regs[0] = (unsigned long)Fork();
            break;
        case YALNIX_EXEC:
            frame->regs[0] = (unsigned long)Exec((char *)(frame->regs[1]), (char **)(frame->regs[2]));
            break;
        case YALNIX_EXIT:
            Exit((int)(frame->regs[1]));
            break;
        case YALNIX_WAIT:
            frame->regs[0] = (unsigned long)Wait((int *)(frame->regs[1]));
            break;
        case YALNIX_GETPID:
            frame->regs[0] = (unsigned long)GetPid();
            break;
        case YALNIX_BRK:
            frame->regs[0] = (unsigned long)Brk((void *)(frame->regs[1]));
            break;
        case YALNIX_DELAY:
            frame->regs[0] = (unsigned long)Delay((int)(frame->regs[1]));
            break;
        case YALNIX_TTY_READ:
            frame->regs[0] = (unsigned long)TtyRead((int)(frame->regs[1]), (void *)(frame->regs[2]), (int)(frame->regs[3]));
            break;
        case YALNIX_TTY_WRITE:
            frame->regs[0] = (unsigned long)TtyWrite((int)(frame->regs[1]), (void *)(frame->regs[2]), (int)(frame->regs[3]));
            break;
    }
}

void trap_clock_handler(ExceptionStackFrame *frame){
    printf("Trapped Clock...\n");
    sys_time++;
    printf("Current system time is %lu\n", sys_time);
    if (delay_head != NULL && delay_head->time_to_switch == sys_time) 
        add_next_proc_on_queue(READY_Q, get_next_proc_on_queue(DELAY_Q));
    if (running_block == idle || running_block->time_to_switch == sys_time) {
        if (ready_head != NULL) {
            ContextSwitch(MySwitchFunc, running_block->ctx, (void *)running_block, (void *)get_next_proc_on_queue(READY_Q));
        }
    }
}

void trap_illegal_handler(ExceptionStackFrame *frame){
    printf("Trapped Illegal Instruction...\n");
    int code = frame->code;
    char error_msg[255];
    char *reason;
    switch(code) {
        case TRAP_ILLEGAL_ILLOPC:
            reason = "Illegal Opcode";
            break;
        case TRAP_ILLEGAL_ILLOPN:
            reason = "Illegal Operand";
            break;
        case TRAP_ILLEGAL_ILLADR:
            reason = "Illegal Addressing Mode";
            break;
        case TRAP_ILLEGAL_ILLTRP:
            reason = "Illegal Software Trap";
            break;
        case TRAP_ILLEGAL_PRVOPC:
            reason = "Privileged Opcode";
            break;
        case TRAP_ILLEGAL_PRVREG:  
            reason = "Privileged Register";
            break;
        case TRAP_ILLEGAL_COPROC:  
            reason = "Coprocessor Error";
            break;
        case TRAP_ILLEGAL_BADSTK:
            reason = "Bad Stack";
            break;
        case TRAP_ILLEGAL_KERNELI:  
            reason = "Receiving SIGILL from LINUX Kernel";
            break;
        case TRAP_ILLEGAL_USERIB:    
            reason = "Receiving SIGILL or SIGBUS from User";
            break;
        case TRAP_ILLEGAL_ADRALN:
            reason = "Invalid Address Alignment";
            break;
        case TRAP_ILLEGAL_ADRERR:
            reason = "Non-existant Physical Address";
            break;
        case TRAP_ILLEGAL_OBJERR:
            reason = "Object-specific HW Error";
            break;
        case TRAP_ILLEGAL_KERNELB:
            reason = "Receiving SIGBUS from LINUX Kernel";
            break;
    }
    sprintf(error_msg, "Kernel terminates process %d because of %s\n", running_block->pid, reason);
    fprintf(stderr, error_msg);
    terminate_process(ERROR);
    pcb *next_proc = get_next_proc_on_queue(READY_Q);
    ContextSwitch(MySwitchFunc, running_block->ctx, (void *)running_block, (void *) next_proc));

}
void trap_memory_handler(ExceptionStackFrame *frame){
    printf("Trapped Memory...%p, %p, %p\n", frame->pc, frame->sp, frame->addr);
    void *addr = frame->addr;
    int code = frame->code;
    int term_proc = 1;      // check if the process needs to be terminated 0: no, 1: yes
    char error_msg[255];
    char *reason;
    switch(code) {
        case TRAP_MEMORY_MAPERR:   /* No mapping at %p */
            if ((long) addr >= VMEM_1_BASE) {   // referenced address is in region 1
                reason = "user process attempted to reference kernel address at ";
            } else if (((long)addr >> PAGESHIFT) < running_block->brk_pn){
                reason = "user process attempted to reference an address in user heap at ";
            } else if (((long)addr >> PAGESHIFT) > running_block->stack_pn) {
                reason = "user process attempted to reference unmapped page above user stack at ";
            } else if ((DOWN_TO_PAGE((long)addr) >> PAGESHIFT) == running_block->brk_pn) {
                reason = "user process attempted to reference a red zone address between user stack and user heap at  ";
            } else {
                term_proc = 0;
                int itr;
                for (itr = (DOWN_TO_PAGE((long)addr) >> PAGESHIFT; itr < frame->sp; itr++) {
                    free_page_deq(REGION_0, itr, READ_WRITE_PERM, READ_WRITE_PERM)
                    set_pte(REGION_0, itr, READ_WRITE_PERM, READ_WRITE_PERM);
                }
            }
            break;
        case TRAP_MEMORY_ACCERR:   /* Protection violation at %p */
            reason = "protection is violated at ";
            break;
        case TRAP_MEMORY_KERNEL:   /* Linux kernel sent SIGSEGV at %p */
            reason = "received SIGSEGV from Linux kernel at ";
            break;
        case TRAP_MEMORY_USER:     /* Received SIGSEGV from user */
            reason = "received SIGSEGV from user at ";
            break;
    }

    if (term_proc == 1) {
        sprintf(error_msg, "Kernel terminates process %d because %s%p\n", running_block->pid, reason, addr);
        fprintf(stderr, error_msg);
        terminate_process(ERROR);
        pcb *next_proc = get_next_proc_on_queue(READY_Q);
        ContextSwitch(MySwitchFunc, running_block->ctx, (void *)running_block, (void *) next_proc));
    }
}

void trap_math_handler(ExceptionStackFrame *frame){
    printf("Trapped Math...\n");
    int code = frame->code;
    char error_msg[255];
    char *reason;
    switch(code) {
    case TRAP_ILLEGAL_ILLOPC:
        reason = "Illegal Opcode";
        break;
    case TRAP_ILLEGAL_ILLOPN:
        reason = "Illegal Operand";
        break;
    case TRAP_ILLEGAL_ILLADR:
        reason = "Illegal Addressing Mode";
        break;
    case TRAP_ILLEGAL_ILLTRP:
        reason = "Illegal Software Trap";
        break;
    case TRAP_ILLEGAL_PRVOPC:
        reason = "Privileged Opcode";
        break;
    case TRAP_ILLEGAL_PRVREG:  
        reason = "Privileged Register";
        break;
    case TRAP_ILLEGAL_COPROC:  
        reason = "Coprocessor Error";
        break;
    case TRAP_ILLEGAL_BADSTK:
        reason = "Bad Stack";
        break;
    case TRAP_ILLEGAL_KERNELI:  
        reason = "Receiving SIGILL from LINUX Kernel";
        break;
    case TRAP_ILLEGAL_USERIB:    
        reason = "Receiving SIGILL or SIGBUS from User";
        break;
    case TRAP_ILLEGAL_ADRALN:
        reason = "Invalid Address Alignment";
        break;
    case TRAP_ILLEGAL_ADRERR:
        reason = "Non-existant Physical Address";
        break;
    case TRAP_ILLEGAL_OBJERR:
        reason = "Object-specific HW Error";
        break;
    case TRAP_ILLEGAL_KERNELB:
        reason = "Receiving SIGBUS from LINUX Kernel";
        break;
    }

}

void trap_tty_receive_handler(ExceptionStackFrame *frame){
    printf("Trapped Tty Receive...\n");
    int tty = frame->code;
    void *buf = malloc(sizeof(char) * TERMINAL_MAX_LINE);
    if (buf == NULL) {
        fprintf(stderr, "Malloc error, tty_receiver_handler abort.\n");
        return;
    }
    int len = TtyReceive(tty, buf, TERMINAL_MAX_LINE);
    
    line *newline = malloc(sizeof(line));
    if (newline == NULL) {
        fprintf(stderr, "Malloc error, tty_receiver_handler abort.\n");
        return;
    }
    newline->buf = malloc(sizeof(char) * len);
    if (newline->buf == NULL) {
        fprintf(stderr, "Malloc error, tty_receiver_handler abort.\n");
        return;
    }
    memcpy(newline->buf, buf, len);
    free(buf);
    newline->cur = 0;
    newline->len = len;
    if (line_head == NULL) line_head = newline;
    else line_tail->next = newline;
    line_tail = newline;

    if (tty_head[tty] != NULL)
        add_next_proc_on_queue(READY_Q, get_next_proc_on_queue(tty));
}

void trap_tty_transmit_handler(ExceptionStackFrame *frame){
    printf("Trapped Tty Transmit...\n");
    int tty = frame->code;
    if (tty_transmiting[tty] != NULL) {
        add_next_proc_on_queue(READY_Q, tty_transmiting[tty]);
        tty_transmiting[tty] = NULL;
        if (tty_head[tty + NUM_TERMINALS] != NULL)
            add_next_proc_on_queue(READY_Q, get_next_proc_on_queue(tty + NUM_TERMINALS));
    }
}

/************************ Kernel calls *************************/

extern int Fork() {
    void *new_region0 = allocate_physical_pt();
    if (new_region0 == NULL) {
        fprintf(stderr, "Error allocate free physical page table\n");
        return ERROR;
    }
    new_pcb = init_pcb(new_region0, next_pid++, NORMAL_PROC);

    int i;
    for (i = MEM_INVALID_PAGES; i < running_block->brk_pn; i++) {
        if ((long)kernel_break >= VMEM_LIMIT) {
            fprintf(stderr, "Kernel virtual space full, cannot fork\n");
            return ERROR;
        }
        int k_index = UP_TO_PAGE(kernel_break - VMEM_1_BASE) >> PAGESHIFT;
        int pfn = free_page_deq(REGION_1, k_index, PROT_ALL, PROT_NONE);    // deq a free page from region 1
        if (pfn < 0) {
            fprintf(stderr, "cannot copy memory image for fork\n");
            return ERROR;
        }
        memcpy((void *)((long)(UP_TO_PAGE(kernel_break))), (void *)((long)(i << PAGESHIFT)), PAGESIZE);
        clear_pte(REGION_1, k_index);

        set_pte(REGION_1, k_index, PROT_ALL, PROT_NONE, (long)(new_pcb->pt_phys_addr) >> PAGESHIFT);
        struct pte *new_pt_virtual_addr = (struct pte *)((long)(UP_TO_PAGE(kernel_break)) + (long)(new_pcb->pt_phys_addr) % PAGESIZE);
        new_pt_virtual_addr[i].valid = 1;
        new_pt_virtual_addr[i].kprot = region_0_pt[i].kprot;
        new_pt_virtual_addr[i].uprot = region_0_pt[i].uprot;
        new_pt_virtual_addr[i].pfn = pfn;
        clear_pte(REGION_1, k_index);
    }

    add_next_proc_on_queue(READY_Q, running_block);
    ContextSwitch(MySwitchFunc, running_block->ctx, (void *)running_block, (void *)new_pcb);
    if (running_block->pid == new_pcb->pid) return 0;
    else return new_pcb->pid;
}

extern int Exec(char *filename, char **argvec) {
    return load_program_from_file(filename, argvec);
}

extern void Exit(int) __attribute__ ((noreturn));
extern int Wait(int *);

extern int GetPid() {
    return running_block->pid;
}

extern int Brk(void *);

extern int Delay(int);

extern int TtyRead(int tty_id, void *buf, int len) {
    if (len < 0) return ERROR;
    if (len == 0) return 0;
    if (line_head == NULL) {
        add_next_proc_on_queue(tty_id, running_block);
        ContextSwitch(MySwitchFunc, running_block->ctx, (void *)running_block, (void *)get_next_proc_on_queue(READY_Q));
    }
    if (len >= line_head->len - line_head->cur) {
        int res = line_head->len - line_head->cur
        memcpy(buf, (void *)((long)line_head->buf + line_head->cur), res);
        line_head = line_head->next;
        if (line_head == NULL) line_tail = NULL;
        return res;
    }
    else {
        memcpy(buf, (void *)((long)line_head->buf + line_head->cur), len);
        line_head->cur = line_head->cur + len;
        if (tty_head[tty_id] != NULL)
            add_next_proc_on_queue(READY_Q, get_next_proc_on_queue(tty_id));
        return len;
    }
}

extern int TtyWrite(int tty_id, void *buf, int len) {
    if (len < 0 || len > TERMINAL_MAX_LINE) return ERROR;
    if (len == 0) return 0;
    if (tty_transmiting[tty_id] != NULL) {
        add_next_proc_on_queue(tty_id + NUM_TERMINALS, running_block);
        ContextSwitch(MySwitchFunc, running_block->ctx, (void *)running_block, (void *)get_next_proc_on_queue(READY_Q));
    }
    tty_transmiting[tty_id] = running_block;
    TtyTransmit(tty_id, buf, len);
    ContextSwitch(MySwitchFunc, running_block->ctx, (void *)running_block, (void *)get_next_proc_on_queue(READY_Q));
    return len;
}

int check_buffer(void *buf, int len, int prot) {

    return 0;
}

int check_string(char *string) {
    int cur_pn = (int)(((long)string)>>PAGESHIFT);
    int i;
    while(1) {
        if (!region_0_pt[cur_pn].valid || !(region_0_pt[cur_pn].kprot & PROT_READ))
            return -1;
        for (i = 0; i < PAGESIZE; i++) {
            if (string[i] == '\0') return 0;
        }
    }
}

/************************************* Memory Management Util Methods **********************************************/
/* Given a virtual page number, add its corresponding physical page to free page list */
void free_page_enq(int isregion1, int vpn) {
    struct pte *region = isregion1?region_1_pt:region_0_pt;
    *(int *)((long)(vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE) = free_page_head;
    free_page_head = region[vpn].pfn;
    clear_pte(isregion1, vpn);
    num_free_pages++;
}

/* Given a virtual page number, assign a physical page to its corresponding pte entry */
int free_page_deq(int isregion1, int vpn, int kprot, int uprot) {
    if (num_free_pages == 0) {
        fprintf(stderr, "No enough physical page\n");
        return -1;
    }
    struct pte *region = isregion1 ? region_1_pt:region_0_pt;
    set_pte(isregion1, vpn, kprot, uprot, free_page_head);
    free_page_head = *(int *)((long)(vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE);
    num_free_pages--;
    return region[vpn].pfn;
}

/* Set pte of specified region with input parameters and flush corresponding TLB */
void set_pte(int isregion1, int vpn, int kprot, int uprot, int pfn) {
    struct pte *region = isregion1 ? region_1_pt:region_0_pt;
    region[vpn].valid = 1;
    region[vpn].kprot = kprot;
    region[vpn].uprot = uprot;
    region[vpn].pfn = pfn;
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal)(long)((vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE));
}

/* Invalidate pte of specified region */
void clear_pte(int isregion1, int vpn) {
    struct pte *region = isregion1 ? region_1_pt:region_0_pt;
    region[vpn].valid = 0;
    WriteRegister(REG_TLB_FLUSH, (RCS421RegVal)(long)((vpn << PAGESHIFT) + isregion1 * VMEM_REGION_SIZE));
}

/* Return a new physical page table */
void *allocate_physical_pt() {
    void *res;
    if (upper_next_pt_pfn != -1) {
        res = (void *)((long)(upper_next_pt_pfn << PAGESHIFT) + PAGE_TABLE_LEN);
        upper_next_pt_pfn = read_from_pfn(res);
    } 
    else if (lower_next_pt_pfn != -1) {
        res = (void *)((long)(lower_next_pt_pfn<< PAGESHIFT));
        lower_next_pt_pfn = read_from_pfn(res);
    }
    else {
        if (free_page_head == -1) {
            fprintf(stderr, "No more free pages\n");
            // TODO: again, here should cause some kernel trap indicating this error
            return NULL;
        }
        res = (void *)((long)(free_page_head << PAGESHIFT));
        free_page_head = read_from_pfn(res);
        // add half of the page to upper_next_pt_pfn
        add_half_free_pt((void *)((long)res + PAGE_TABLE_LEN));   
    }
    //zero out page table
    int k_index = UP_TO_PAGE(kernel_break - VMEM_1_BASE) >> PAGESHIFT;
    set_pte(REGION_1, k_index, PROT_ALL, PROT_NONE, (long)(res) >> PAGESHIFT);
    void *pt_virtual_addr = (void *)((long)(UP_TO_PAGE(kernel_break)) + (long)(res) % PAGESIZE);
    memset(pt_virtual_addr,'\0', PAGE_TABLE_SIZE);
    clear_pte(REGION_1, k_index);
    return res;
}

/* Add half free page to upper_next_pt_pfn or lower_next_pt_pfn*/
void add_half_free_pt(void *physical_pt) {
    long pt_val = (long)physical_pt;
    if (pt_val % PAGESIZE == 0) {
        write_to_pfn(physical_pt, upper_next_pt_pfn);
        upper_next_pt_pfn = pt_val >> PAGESHIFT;
    } else {
        write_to_pfn(physical_pt, lower_next_pt_pfn);
        lower_next_pt_pfn = pt_val >> PAGESHIFT;
    }
}

/* Read next available free pfn/half_pt_pfn of passed in physical_addr */
int read_from_pfn(void *physical_addr) {
    if ((long)kernel_break >= VMEM_LIMIT) {
        fprintf(stderr, "Kernel virtual space full, cannot read from physical address\n");
        // TODO: ERROR CHECK
        return -1;
    }
    int k_index = UP_TO_PAGE(kernel_break - VMEM_1_BASE) >> PAGESHIFT;

    set_pte(REGION_1, k_index, PROT_ALL, PROT_NONE, (long)physical_addr >> PAGESHIFT);
    int res = *(int *)(VMEM_1_BASE + (k_index << PAGESHIFT) + (long)physical_addr % PAGESIZE);
    clear_pte(REGION_1, k_index);
    return res;
}

/* Write next available free pfn/half_pt_pfn into passed in physical_addr */
void write_to_pfn(void *physical_addr, int towrite) {
    if ((long)kernel_break >= VMEM_LIMIT) {
        fprintf(stderr, "Kernel virtual space full, cannot write to physical address\n");
        return;
    }
    int k_index = UP_TO_PAGE(kernel_break - VMEM_1_BASE) >> PAGESHIFT;
    set_pte(REGION_1, k_index, PROT_ALL, PROT_NONE, (long)physical_addr >> PAGESHIFT);
    *(int *)(VMEM_1_BASE + (k_index << PAGESHIFT) + (long)physical_addr % PAGESIZE) = towrite;
    clear_pte(REGION_1, k_index);
}

void validate_region_0_pt() {
    int region_0_pt_idx = (VMEM_REGION_SIZE >> PAGESHIFT) - 2;
    set_pte(REGION_1, region_0_pt_idx, PROT_ALL, PROT_NONE, (long)(running_block->pt_phys_addr)>>PAGESHIFT);
    region_0_pt = (struct pte *) (VMEM_1_LIMIT - 2 * PAGESIZE + (long)(running_block->pt_phys_addr)%PAGESIZE);
}

/* Given a virtual address, return its physical address*/
void *v2p(void *vaddr) {
    struct pte *region = (long)vadd r < VMEM_1_BASE ? region_0_pt:region_1_pt;
    if ((long)vaddr >= VMEM_1_BASE) vaddr -= VMEM_1_BASE;
    return (void *)((long)((region[(long)vaddr >> PAGESHIFT].pfn << PAGESHIFT) + (long)vaddr % PAGESIZE));
}

/* Print valid entries of region_0_pt and region_1_pt */
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
int LoadProgram(char *name, char **args, int* brk_pn) {
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
    ExceptionStackFrame *frame = (ExceptionStackFrame *)((long)EXCEPTION_FRAME_ADDR);
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
        if (free_page_deq(REGION_0, i, PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC) < 0) {
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
        if (free_page_deq(REGION_0, i, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE) < 0) {
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
        if (free_page_deq(REGION_0, index, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE) < 0) {
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
