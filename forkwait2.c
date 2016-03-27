#include <stdio.h>
#include <comp421/yalnix.h>

int
main(int argc, char **argv)
{
    int pid1, pid2;
    int status;
    int i;

    setbuf(stdout, NULL);

    printf("FORKWAIT> This program tests that child properly adjust sibling queue.\n");
    printf("FORKWAIT> If no more FORKWAIT output, Fork does not work\n");

    for (i = 0; i < 3; i++) {

	if ((pid1 = Fork()) == 0)
	{
	    printf("FORKWAIT> CHILD about to exit with 1234567\n");
	    if (i == 1) {
	    	Delay(5);
	    }
	    else {
	    	Delay(10);
	    }
	    Exit(1234567);
	}

	printf("FORKWAIT> PARENT: child pid = %d, &status = %p\n",
	    pid1, &status);
	}

	pid2 = Wait(&status);
	printf("FORKWAIT> Wait returned pid %d status %d\n", pid2, status);

    Exit(0);
}