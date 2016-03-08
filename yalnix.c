#include <comp421/yalnix.h>
#include <comp421/hardware.h>

typedef struct pcb {
	SavedContext *ctx;
	int v_page_table_base;
	int pid;
	int uid;
	char state; //RUNNING is 0, READY is 1
	pcb *next;
} pcb;