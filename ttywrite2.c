#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

#define	TTY_WRITE_STR(term, str) TtyWrite(term, str, strlen(str))

int
main()
{
    int i;

    for (i = 0; i < 10; i++)
	TTY_WRITE_STR(0, "Hello world\n");

    Exit(0);
}
