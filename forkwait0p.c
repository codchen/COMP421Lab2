#include <stdio.h>
#include <comp421/yalnix.h>

int
main()
{
    int pid;
    int pid2;
    int status;

    setbuf(stdout, NULL);

    printf("testing Exit before Wait\n");

    pid = Fork();
    if (pid < 0) {
	printf("Fork failed %d\n", pid);
	Exit(1);
    }

    if (pid == 0) {
	printf("child calling Exit(123)\n");
	Exit(123);
    }
    else {
	printf("parent Fork returned %d\n", pid);
	printf("parent calling Delay(10)\n");
	Delay(10);
	printf("parent calling Wait\n");
	pid2 = Wait(&status);
	printf("wait returned pid2 %d status %d\n", pid2, status);
	Exit(0);
    }
}
