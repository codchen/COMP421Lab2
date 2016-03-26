#include <stdio.h>
#include <stdlib.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

void
foo(int depth)
{
    char array[65532];
    int i;

    TracePrintf(0, "blowstack foo: depth %d\n", depth);

    fprintf(stderr,"%d ",depth);
    fflush(stderr);

    for (i = 0; i < sizeof(array); i++)
	array[i] = 'a';

    if (depth == 1) return;

    foo(depth-1);
}

int
main(int argc, char **argv)
{
    int num = atoi(argv[1]);

    TracePrintf(0, "blowstack initially calling foo depth %d", num);
    foo(num);

    Exit(0);
}
