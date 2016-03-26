#include <comp421/yalnix.h>

int
main()
{
    int x = 0;
    int y;

    /*
     *  Dividing by zero here should result in a TRAP_MATH trap.
     */
    y = 5/x;

    Exit(1);
}
