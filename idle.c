#include <stdio.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>

int main(int argc, char **argv)
{
	printf("Running Idle...\n");
    while (1) {
        Pause();
    }
}