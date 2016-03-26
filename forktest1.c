#include <stdio.h>
#include <comp421/yalnix.h>

int
main(int argc, char **argv)
{
    setbuf(stdout, NULL);

    printf("FORK1> This program is a simple test of Fork()\n");
    printf("FORK1> BEFORE Fork(): If nothing else is printed, Fork fails \n");

    if (Fork() == 0) {
	printf("CHILD\n");
    }
    else {
	printf("PARENT\n");
	Delay(8);
	printf("FORK1> You should have seen \"CHILD\" and \"PARENT\" printed\n");
	printf("FORK1> in the order in which they were scheduled\n");
	printf("FORK1> If you missed one or the other, the kernel\n");
	printf("FORK1> does NOT switch contexts!!!\n");

    }

    Exit(0);
}
