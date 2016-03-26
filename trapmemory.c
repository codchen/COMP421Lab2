#include <comp421/yalnix.h>

int
main()
{
    int x;

    /*
     *  The address 0x123 should be invalid, so this should result
     *  in a TRAP_MEMORY trap.
     */
    x = *(int *)0x123;

    Exit(1);
}
