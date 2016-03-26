#include <stdio.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

#define NUM_FORKS	10

int
main(int argc, char **argv)
{
    int pid1, pid2;
    int status;
    int i, j;
    int pids[NUM_FORKS];

    setbuf(stdout, NULL);

    printf("FORKWAIT> This program tests that Wait collects zombie processes\n");
    printf("FORKWAIT> If no more FORKWAIT output, Fork does not work\n");

    for (i = 0; i < NUM_FORKS; i++) {

	if ((pid1 = Fork()) == 0)
	{
	    TracePrintf(0, "FORKWAIT> CHILD %d about to exit with 1234567\n",
		GetPid());
	    printf("FORKWAIT> CHILD %d about to exit with 1234567\n",
		GetPid());
	    Exit(1234567);
	}
	TracePrintf(0, "Fork returned pid %d\n", pid1);

	pids[i] = pid1;

	printf("FORKWAIT> PARENT: child pid = %d, &status = %p\n",
	    pid1, &status);
    }

    Delay(2);

    for (i = 0; i < NUM_FORKS; i++) {

	pid2 = Wait(&status);

	printf("FORKWAIT> Wait returned pid %d status %d\n", pid2, status);

	if (status != 1234567) {
	    printf("Should have returned status 1234567!!\n");
	    Exit(1);
	}

	for (j = 0; j < NUM_FORKS; j++) {
	    if (pid2 == pids[j]) {
		pids[j] = -1;
		break;
	    }
	}
	if (j >= NUM_FORKS) {
	    TracePrintf(0, "unrecognized pid %d returned!!\n", pid2);
	    printf("unrecognized pid %d returned!!\n", pid2);
	    Exit(1);
	}

	TracePrintf(0, "GOOD!\n");
	printf("FORKWAIT> GOOD!\n");
    }

    TracePrintf(0, "DONE!\n");
    printf("DONE!\n");

    Exit(0);
}
