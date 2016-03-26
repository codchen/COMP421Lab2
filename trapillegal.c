#include <comp421/yalnix.h>

int
main()
{
    /*
     *  Opcode 0x37 is the AAA (ASCII Adjust after Addition)
     *  instruction, which is illegal in 64-bit mode on the
     *  x86-64 architecture.  This should result in a
     *  TRAP_ILLEGAL trap.
     */
    asm(".byte 0x37");

    Exit(1);
}
