/*
 *  External definitions for the Yalnix kernel user interface.
 */

#ifndef	_yalnix_h
#define	_yalnix_h

/*
 *  Define the kernel call number for each of the supported kernel calls.
 */
#define	YALNIX_FORK		1
#define	YALNIX_EXEC		2
#define	YALNIX_EXIT		3
#define	YALNIX_WAIT		4
#define YALNIX_GETPID           5
#define	YALNIX_BRK		6
#define	YALNIX_DELAY		7

#define	YALNIX_TTY_READ		21
#define	YALNIX_TTY_WRITE	22

/* Remaining kernel call numbers below here are not part of Lab 2 */

#define	YALNIX_REGISTER		31
#define YALNIX_SEND		32
#define YALNIX_RECEIVE		33
#define YALNIX_RECEIVESPECIFIC	34
#define YALNIX_REPLY		35
#define YALNIX_FORWARD		36
#define YALNIX_COPY_FROM	37
#define YALNIX_COPY_TO		38

#define YALNIX_READ_SECTOR	40
#define YALNIX_WRITE_SECTOR	41
#define YALNIX_DISK_STATS	42

/*
 *  All Yalnix kernel calls return ERROR in case of any error.
 */
#define	ERROR			(-1)

/*
 *  Server index definitions for Register(index) and Send(msg, -index):
 *  (not part of Lab 2)
 */
#define	FILE_SERVER		1
#define	MAX_SERVER_INDEX	16	/* max legal index */

/*
 *  Define the (constant) size of a message for Send/Receive/Reply.
 *  (not part of Lab 2)
 */
#define	MESSAGE_SIZE		32

#ifndef	__ASSEMBLER__

#include <sys/types.h>

/*
 *  The structure of values filled in by DiskStats.
 *  (not part of Lab 2)
 */
struct diskstats {
    int reads;		/* count of ReadSector calls completed */
    int writes;		/* count of WriteSector calls completed */
};

/*
 *  Function prototypes for each of the Yalnix kernel calls.
 */
extern int Fork(void);
extern int Exec(char *, char **);
extern void Exit(int) __attribute__ ((noreturn));
extern int Wait(int *);
extern int GetPid(void);
extern int Brk(void *);
extern int Delay(int);
extern int TtyRead(int, void *, int);
extern int TtyWrite(int, void *, int);
extern int Register(unsigned int);
extern int Send(void *, int);
extern int Receive(void *);
extern int ReceiveSpecific(void *, int);
extern int Reply(void *, int);
extern int Forward(void *, int, int);
extern int CopyFrom(int, void *, void *, int);
extern int CopyTo(int, void *, void *, int);
extern int ReadSector(int, void *);
extern int WriteSector(int, void *);
extern int DiskStats(struct diskstats *);

/*
 *  A Yalnix library function: TtyPrintf(num, format, args) works like
 *  printf(format, args) on terminal num.
 */
extern int TtyPrintf(int, char *, ...);

int ValidateKernelStack(void);

#endif

#endif /*!_yalnix_h*/
