#ifndef _hardware_h
#define _hardware_h

#define	_LAB3		/* define to include Lab 3 features */

#ifndef	__ASSEMBLER__
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#ifdef	__USE_GNU
#include <ucontext.h>
#else
#define __USE_GNU
#include <ucontext.h>
#undef __USE_GNU
#endif
#endif	/* __ASSEMBLER */

/*
 *  Definitions for the hardware register names.  These names
 *  are used with the WriteRegister and ReadRegister operations.
 *  The value that can be written into or read from any of these
 *  registers is of type "RCS421RegVal".
 */
#define REG_VECTOR_BASE	1	/* phys addr of interrupt vector */
#define REG_PTR0	2	/* phys addr of page table for Region 0 */
#define REG_PTR1	3	/* phys addr of page table for Region 1 */
#define REG_VM_ENABLE	4	/* write 1 to enable virtual memory */
#define REG_TLB_FLUSH	5	/* translation lookaside buffer flush */

#ifndef	__ASSEMBLER__
typedef	unsigned long	RCS421RegVal;
#endif	/* __ASSEMBLER */

/*
 *  Define page size-related constants, and make sure they are set
 *  as we expect.  We also verify PAGESIZE against getpagesize() at
 *  runtime in the internal intiialization code, just  to be sure.
 */
#undef PAGESIZE
#define PAGESIZE	0x1000		/* 4 kB */
#undef PAGEOFFSET
#define PAGEOFFSET	(PAGESIZE-1)
#undef PAGEMASK
#define PAGEMASK	(~PAGEOFFSET)
#define PAGESHIFT	12

/*
 *  Define the physical memory layout of the machine.
 *
 *  The PMEM_BASE is determined by the machine's architecture design
 *  specification.  The actual size of physical memory, though, is
 *  determined by how much RAM is installed in the machine.  This
 *  is computed by the boot ROM and is passed to your KernelStart
 *  at boot time.
 */
#define PMEM_BASE               0

#ifndef	__ASSEMBLER__
/*
 *  Macros for rounding numbers up to a multiple of the page size,
 *  or down to a multiple of the page size.  For example, if PAGESIZE
 *  is 0x1000, then:
 *
 *        addr          UP_TO_PAGE(addr)        DOWN_TO_PAGE(addr)
 *      -------         ----------------        ------------------
 *         0x0                 0x0                       0x0
 *         0x1              0x1000                       0x0
 *       0xfff              0x1000                       0x0
 *      0x1000              0x1000                    0x1000
 *      0x1001              0x2000                    0x1000
 */
#define	UP_TO_PAGE(n)	(((long)(n) + PAGEOFFSET) & PAGEMASK)
#define	DOWN_TO_PAGE(n)	((long)(n) & PAGEMASK)
#endif

/*
 *  Define the virtual memory layout of the machine.
 *
 *  The virtual memory layout is determined by the design specifications
 *  of the machine's architecture.
 */
#define	VMEM_REGION_SIZE	0x200000	/* 2 MB */
#define	VMEM_NUM_REGION		2
#define	VMEM_SIZE		(VMEM_NUM_REGION * VMEM_REGION_SIZE)

#define	VMEM_BASE		0
#define	VMEM_0_BASE		VMEM_BASE
#define	VMEM_0_SIZE		VMEM_REGION_SIZE
#define	VMEM_0_LIMIT		(VMEM_0_BASE + VMEM_0_SIZE)
#define	VMEM_1_BASE		VMEM_0_LIMIT
#define	VMEM_1_SIZE		VMEM_REGION_SIZE
#define	VMEM_1_LIMIT		(VMEM_1_BASE + VMEM_1_SIZE)
#define	VMEM_LIMIT		VMEM_1_LIMIT

/*
 * In order to help catch accidental dereferencing of a NULL pointer,
 * the hardware will not let any address less than MEM_INVALID_SIZE be
 * used as an address (whether as a physical address before you enable
 * virtual memory or as a virtual address after that).
 *
 * Thus, before you enable virtual memory, you cannot access physical
 * memory below MEM_INVALID_SIZE at all.
 * 
 * After you have enabled virtual memory, you can access this low
 * *physical* memory, as you can use small PFNs such as 0 (for
 * example) in the pfn field of a PTE to map some *virtual* address to
 * physical page 0 (in this example), but you can't actually use 0 (or
 * other numbers less than MEM_INVALID_SIZE) as an *address* (either
 * as a physical address before you enable virtual memory or as a
 * virtual address after that).  So these low physical pages such as
 * physical page 0 really exist, but you can't access them other than
 * by a virtual address after you have enabled virtual memory, where
 * that virtual address is not less then MEM_INVALID_SIZE.
 */
#define	MEM_INVALID_SIZE	0x10000
#define	MEM_INVALID_PAGES	(0x10000 >> PAGESHIFT)

/* The minimum legal virtual page number for the machine */
#define MIN_VPN			0

/* The number of virtual pages on this machine */
#define NUM_VPN			(VMEM_LIMIT >> PAGESHIFT)

/* The maximum legal virtual page number for the machine */
#define	MAX_VPN			(NUM_VPN - 1)

/*
 *  The size of a page table (number of page table entries) to map a
 *  region of virtual memory, and the number of bytes in a page table.
 */
#define	PAGE_TABLE_LEN		(VMEM_REGION_SIZE >> PAGESHIFT)
#define	PAGE_TABLE_SIZE		(PAGE_TABLE_LEN * sizeof(struct pte))

/*
 *  The kernel stack is at the top of Region 0.  The kernel stack pointer
 *  gets reset to KERNEL_STACK_LIMIT at each trap, interrupt, or exception.
 *  The stack grows down and must not go below KERNEL_STACK_BASE.
 */
#define KERNEL_STACK_LIMIT	VMEM_0_LIMIT
#define KERNEL_STACK_PAGES	4
#define KERNEL_STACK_SIZE	(KERNEL_STACK_PAGES * PAGESIZE)
#define KERNEL_STACK_BASE	(KERNEL_STACK_LIMIT - KERNEL_STACK_SIZE)

/*
 *  The user stack goes in Region 0 below the kernel stack, but with
 *  an unmapped (no access) page between the kernel stack and the
 *  user stack.  This unmapped page serves as a "red zone" to prevent
 *  the kernel stack from growning so large as to accidentally overlap
 *  the user stack.
 *
 *  The user stack contents and user stack pointer are initialized by
 *  the Yalnix kernel, not by the hardware.  We define this user
 *  stack constant here, though, since it relates to the kernel stack
 *  constants above.
 */
#define USER_STACK_LIMIT	(KERNEL_STACK_BASE - PAGESIZE)

#ifndef	__ASSEMBLER__
/*
 *  Define the structure of a page table entry.  The total size
 *  of each page table entry is 32 bits.
 *
 *  (FYI: When viewed as an "unsigned int", the individual bit fields
 *  within the entry are mapped by the compiler beginning at the least
 *  significant end of the int, making, for example, the valid bit
 *  be 0x80000000.)
 */
struct pte {
    unsigned int pfn	: 20;	/* page frame number */
    unsigned int unused	: 5;	/* (unused by the hardware) */
    unsigned int uprot	: 3;	/* user mode protection bits */
    unsigned int kprot	: 3;	/* kernel mode protection bits */
    unsigned int valid	: 1;	/* page table entry is valid */
};
#endif

/*
 *  Define the protection bits used in page table entries.
 *
 *  PROT_READ, PROT_WRITE, and PROT_EXEC come from
 *  /usr/include/bits/mman.h on Linux.
 */
#ifndef	PROT_NONE
#define	PROT_NONE	0
#endif
#ifndef	PROT_ALL
#define	PROT_ALL	(PROT_READ|PROT_WRITE|PROT_EXEC)
#endif

#ifndef	__ASSEMBLER__

/*
 *  The machine has a "translation lookaside buffer" (TLB), which must
 *  be flushed during a context switch or when changing page tables.
 *  The TLB is flushed by writing one of the following values into
 *  the REG_TLB_FLUSH privileged machine register:
 *
 *   - TLB_FLUSH_ALL: flushes the entire TLB.
 *   - TLB_FLUSH_0: flushes all mappings for region 0 from the TLB.
 *   - TLB_FLUSH_1: flushes all mappings for region 1 from the TLB.
 *   - addr: flushes only the mapping for virtual address "addr".
 */
#define	TLB_FLUSH_ALL	((RCS421RegVal)(-1))
#define	TLB_FLUSH_0	((RCS421RegVal)(-2))
#define	TLB_FLUSH_1	((RCS421RegVal)(-3))

/*
 *  Define the format of an exception stack frame, pushed onto the
 *  kernel stack by the hardware when any interrupt, trap, or exception
 *  occurs.  The address of the exception stack frame is passed to the
 *  handler function called through the interrupt vector.  An initial
 *  exception stack frame is also built by the boot ROM and is passed
 *  to KernelStart.
 */
#define	NUM_REGS	8	/* number of general purpose registers */
struct exception_stack_frame {
    int vector;		/* vector number */
    int code;		/* additional "code" for vector */
    void *addr;		/* offending address, if any */
    unsigned long psr;	/* processor status register */
    void *pc;		/* PC at time of exception */
    void *sp;		/* SP at time of exception */
    unsigned long regs[NUM_REGS]; /* general registers at time of exception */
};

typedef struct exception_stack_frame ExceptionStackFrame;

/*
 *  Define the bits of the Processor Status Register (PSR).
 *
 *  The only bit that should be needed is the "mode" bit, which is
 *  set (1) if in kernel mode and clear (0) if in user mode.
 */
#define	PSR_MODE	(1L<<63)	/* 1 = kernel mode, 0 = user mode */

/*
 *  This is the structure that holds a current context of the CPU.
 *  Created and/or restored by ContextSwitch(), which records
 *  the current state of a running thread.  ContextSwitch()
 *  is only called while inside the kernel.
 *
 *  DO NOT IN ANY WAY MODIFY ANYTHING INSIDE ANY SavedContext.
 */
typedef struct {
    char s[24+sizeof(ucontext_t)];	/* Do not modify any of this */
} SavedContext;

#endif

/*
 *  Define the interrupt and exception vector numbers.  These numbers
 *  are used as a subscript into the vector table, which is pointed to
 *  by the hardware register REG_VECTOR_BASE.  The vector table must be
 *  built as TRAP_VECTOR_SIZE entries long, although not all entries
 *  are currently used by the hardware.  All unused entries should be
 *  initialized to NULL.
 */
#define	TRAP_KERNEL		0
#define	TRAP_CLOCK		1
#define	TRAP_ILLEGAL		2
#define	TRAP_MEMORY		3
#define	TRAP_MATH		4
#define	TRAP_TTY_RECEIVE	5
#define	TRAP_TTY_TRANSMIT	6
#ifdef	_LAB3
#define	TRAP_DISK		7
#endif	/* _LAB3 */

#define	TRAP_VECTOR_SIZE	16	/* dimensioned size of array */

/*
 *  Define the code values associated with RCS 421 TRAP_ILLEGAL exceptions.
 *
 *  You do not need (and should not use) these code values as any part
 *  of the operation of your kernel, other than perhaps using them as
 *  part of your kernel printing an error message when a TRAP_ILLEGAL
 *  exception occurs.
 *
 *  In the simulation, these values come from Linux code values for SIGILL
 *  and SIGBUS, defined in /usr/include/bits/siginfo.h.
 */
#define	TRAP_ILLEGAL_ILLOPC  ILL_ILLOPC     /* Illegal opcode */
#define	TRAP_ILLEGAL_ILLOPN  ILL_ILLOPN     /* Illegal operand */
#define	TRAP_ILLEGAL_ILLADR  ILL_ILLADR     /* Illegal addressing mode */
#define	TRAP_ILLEGAL_ILLTRP  ILL_ILLTRP     /* Illegal software trap */
#define	TRAP_ILLEGAL_PRVOPC  ILL_PRVOPC     /* Privileged opcode */
#define	TRAP_ILLEGAL_PRVREG  ILL_PRVREG     /* Privileged register */
#define	TRAP_ILLEGAL_COPROC  ILL_COPROC     /* Coprocessor error */
#define	TRAP_ILLEGAL_BADSTK  ILL_BADSTK     /* Bad stack */
#define	TRAP_ILLEGAL_KERNELI SI_KERNEL	    /* Linux kernel sent SIGILL */
#define	TRAP_ILLEGAL_USERIB  SI_USER  /* Received SIGILL or SIGBUS from user */
#define	TRAP_ILLEGAL_ADRALN  (-BUS_ADRALN)  /* Invalid address alignment */
#define	TRAP_ILLEGAL_ADRERR  (-BUS_ADRERR)  /* Non-existant physical address */
#define	TRAP_ILLEGAL_OBJERR  (-BUS_OBJERR)  /* Object-specific HW error */
#define	TRAP_ILLEGAL_KERNELB (-SI_KERNEL)   /* Linux kernel sent SIGBUS */

/*
 *  Define the code values associated with RCS 421 TRAP_MEMORY exceptions.
 *  The %p below means the value of "addr" from the ExceptionStackFrame.
 *
 *  You do not need (and should not use) these code values as any part
 *  of the operation of your kernel, other than perhaps using them as
 *  part of your kernel printing an error message when a TRAP_MEMORY
 *  exception occurs.
 *
 *  In the simulation, these values come from Linux code values for
 *  SIGSEGV, defined in /usr/include/bits/siginfo.h.
 */
#define	TRAP_MEMORY_MAPERR   SEGV_MAPERR    /* No mapping at %p */
#define	TRAP_MEMORY_ACCERR   SEGV_ACCERR    /* Protection violation at %p */
#define	TRAP_MEMORY_KERNEL   SI_KERNEL    /* Linux kernel sent SIGSEGV at %p */
#define	TRAP_MEMORY_USER     SI_USER        /* Received SIGSEGV from user */

/*
 *  Define the code values associated with RCS 421 TRAP_MATH exceptions.
 *
 *  You do not need (and should not use) these code values as any part
 *  of the operation of your kernel, other than perhaps using them as
 *  part of your kernel printing an error message when a TRAP_MATH
 *  exception occurs.
 *
 *  In the simulation, these values come from Linux code values for
 *  SIGFPE, defined in /usr/include/bits/siginfo.h.
 */
#define	TRAP_MATH_INTDIV     FPE_INTDIV     /* Integer divide by zero */
#define	TRAP_MATH_INTOVF     FPE_INTOVF     /* Integer overflow */
#define	TRAP_MATH_FLTDIV     FPE_FLTDIV     /* Floating divide by zero */
#define	TRAP_MATH_FLTOVF     FPE_FLTOVF     /* Floating overflow */
#define	TRAP_MATH_FLTUND     FPE_FLTUND     /* Floating underflow */
#define	TRAP_MATH_FLTRES     FPE_FLTRES     /* Floating inexact result */
#define	TRAP_MATH_FLTINV     FPE_FLTINV     /* Invalid floating operation */
#define	TRAP_MATH_FLTSUB     FPE_FLTSUB     /* FP subscript out of range */
#define	TRAP_MATH_KERNEL     SI_KERNEL      /* Linux kernel sent SIGFPE */
#define	TRAP_MATH_USER	     SI_USER        /* Received SIGFPE from user */

/*
 *  Definitions for the terminals attached to the machine.
 *
 *  The first terminal is the system console, but there is no difference
 *  in the hardware between it and the other terminals.  The difference
 *  is only in the use that Yalnix user processes make of the terminals.
 */

#define	TTY_CONSOLE	0		/* terminal 0 is the console */
#define	TTY_1		1
#define	TTY_2		2
#define	TTY_3		3

#define	NUM_TERMINALS	4		/* # of terminals, including console */

#define	TERMINAL_MAX_LINE	1024	/* maximum length of terminal line */

#ifndef	__ASSEMBLER__

/*
 *  Some function definitions.
 */

/*
 *  Definitions for the special operations provided by the hardware.
 */

extern RCS421RegVal ReadRegister(int);
extern void WriteRegister(int, RCS421RegVal);
extern void TtyTransmit(int, void *, int);
extern int TtyReceive(int, void *, int);
#ifdef	_LAB3
extern void DiskAccess(int, int, void *);
#endif	/* _LAB3 */
extern void Halt(void) __attribute__ ((noreturn));
extern void Pause(void);

extern void TracePrintf(int, char *, ...);
extern void VTracePrintf(int, char *, va_list);

/* 
 *  Definitions of functions to be written by students
 */

extern int SetKernelBrk(void *);

/*
 *  This is the primary entry point into the kernel:
 *
 *  ExceptionStackFrame *frame
 *  unsigned int pmem_size
 *  void *orig_brk
 *  char **cmd_args
 */
extern void KernelStart(ExceptionStackFrame *, unsigned int, void *, char **);

/*
 *  Switching thread context (which is done from inside the kernel) is
 *  tricky.  Real operating systems do this within one function that
 *  is careful not to use local variables or make function calls, so
 *  that the kernel stack can be switched without messing up the switch
 *  itself.  The operating system also has to be careful to save and
 *  restore registers without interfering with the code that saves and
 *  restores them.  For these reasons, this is usually done in
 *  carefully-written assembly code.
 *
 *  To make the job of switching thread context easier in the project,
 *  we provide the function:
 * 
 *     int ContextSwitch(SwitchFunc_t *, SavedContext *, void *, void *)
 *
 *  The type SwitchFunc_t ("context switch function" type) is a messy
 *  C typedef of a specific kind of function (matched by MySwitch,
 *  below, for example).
 *
 *  The function ContextSwitch temporarily stops using the standard
 *  kernel stack, saved the current hardware context in the SavedContext
 *  pointed to by the second argument, and calls a function provided
 *  by you (suppose your function is called MySwitch):
 * 
 *     SavedContext *MySwitch(SavedContext *, void *, void *)
 *
 *  The pointer passed as the first argument is the same SavedContext
 *  pointer passed to ContextSwitch (as its second argument).  The
 *  two "void *" arguments to ContextSwitch will be passed unmodified
 *  to MySwitch.  You should use them to point to the current thread's
 *  PCB and to the PCB of the new thread to be context switched in,
 *  respectively.
 *
 *  In MySwitch, you should do whatever you need to do to context
 *  switch between these two threads.  The "SavedContext *" argument
 *  passed to MySwitch is a pointer to a temporary copy of the current
 *  thread's context somewhere in memory.  You should copy this
 *  SavedContext (not just the pointer) into the old thread's PCB.
 *  The "SavedContext *" value you return from  MySwitch should
 *  point to a SavedContext containing the context of the new
 *  thread to run.  This SavedContext *must* have been created
 *  by some call to ContextSwitch.  If you return the same
 *  ContextSwitch * pointer that was passed to your MySwitch
 *  function, no switch actually occurs, but you can still save
 *  the SavedContext in a PCB for later use on some other
 *  ContextSwitch call.
 *
 *  You should use ContextSwitch to in effect "block" a thread
 *  somewhere in the middle of some procedure somewhere inside your
 *  kernel.  ContextSwitch and MySwitch do the context switch, and when
 *  this thread is later context switched back to, ContextSwitch
 *  returns.  The return value of ContextSwitch in this case is 0.
 *  If, instead, any error occurs, ContextSwitch does not switch
 *  contexts and returns -1.
 */
typedef SavedContext *SwitchFunc_t(SavedContext *, void *, void *);
extern int ContextSwitch(SwitchFunc_t *, SavedContext *, void *, void *);

/*
 *  The following definition is not really hardware, but it is
 *  necessary for the project.  By saying
 *
 *     &_etext
 *
 *  in your kernel, you get the address of the first byte immediately
 *  after the program text (machine code instructions) of your kernel.
 *
 *  There is no real variable named _etext in your kernel.  It is
 *  only useful to take the address (with &) of _etext.  The symbol
 *  _etext is automatically put into the symbol table of every
 *  program created by the Unix linker.  Since the Yalnix kernel
 *  is linked by the Unix linker, the _etext symbol exist in your
 *  Yalnix kernel.
 */
extern char _etext;

#endif

#ifdef	_LAB3
/*
 *  Define the physical properties of the disk.
 */
#define	SECTORSIZE	512	/* size of a disk sector in bytes */
#define	NUMSECTORS	1426	/* number of sectors on the disk */

/*
 *  Define the operation codes for DiskAccess, the hardware operation
 *  that the kernel uses to read/write sectors on the disk.
 */
#define DISK_READ	0
#define DISK_WRITE	1
#endif	/* _LAB3 */

#endif /*!_hardware_h*/
