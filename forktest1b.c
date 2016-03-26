#include <stdio.h>
#include <comp421/yalnix.h>

int
main(int argc, char **argv)
{
    setbuf(stdout, NULL);

    printf("FORK1> This program is a simple test of Fork()\n");
    printf("FORK1> BEFORE Fork(): If nothing else is printed, Fork fails \n");

    if (Fork() == 0) {
	printf("CHILD %d\n", GetPid());
    }
    else {
	printf("PARENT %d\n", GetPid());
	Delay(8);
	printf("FORK1 %d> You should have seen \"CHILD\" and \"PARENT\" printed\n", GetPid());
	printf("FORK1 %d> in the order in which they were scheduled\n", GetPid());
	printf("FORK1 %d> If you missed one or the other, the kernel\n", GetPid());
	printf("FORK1 %d> does NOT switch contexts!!!\n", GetPid());

    }

    Exit(0);
}
