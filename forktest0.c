#include <comp421/yalnix.h>
#include <comp421/hardware.h>

int
main(int argc, char **argv)
{
    if (Fork() == 0) {
	TracePrintf(0, "CHILE\n");
    }
    else {
	TracePrintf(10, "PARENT\n");
	Delay(8);
    }

    Exit(0);
}
