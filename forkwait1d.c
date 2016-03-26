#include <stdio.h>
#include <comp421/yalnix.h>

int
main(int argc, char **argv)
{
    int pid1, pid2;
    int status;
    int i;

    setbuf(stdout, NULL);

    printf("FORKWAIT> This program tests that Wait collects zombie processes\n");
    printf("FORKWAIT> If no more FORKWAIT output, Fork does not work\n");

    for (i = 0; i < 10; i++) {

	if ((pid1 = Fork()) == 0)
	{
	    printf("FORKWAIT %d> CHILD about to exit with 1234567\n", i);
	    Exit(1234567);
	}

	printf("FORKWAIT %d> PARENT: child pid = %d, &status = %p\n",
	    i, pid1, &status);

	pid2 = Wait(&status);

	printf("FORKWAIT %d> Wait returned pid %d status %d\n",
	    i, pid2, status);

	if ((pid2 != pid1) || (status != 1234567)) {
	    printf("%d Should have returned pid %d status 1234567!!\n",
		i, pid1);
	    Exit(1);
	}
	else {
	    printf("FORKWAIT %d> GOOD!\n", i);
	}
	  
    }

    Exit(0);
}
