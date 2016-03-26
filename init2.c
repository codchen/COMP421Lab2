#include <stdio.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

int a = 5, c = 15;

int
main()
{
    int b = 10, d = 20;

    Delay(20);
    /* Pause(); */

    TracePrintf(2, "init!\n");

    TracePrintf(2, "init: main %p\n", main);
    TracePrintf(2, "pid %d\n", GetPid());

    printf("hello world\n");
    printf("this %d is %d a %d test %d\n", a, b, c, d);

    Exit(3);
}
