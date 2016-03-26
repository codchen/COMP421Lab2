#include <unistd.h>
#include <comp421/yalnix.h>

int
main()
{
    write(2, "init!\n", 6);
    Exit(0);
}
