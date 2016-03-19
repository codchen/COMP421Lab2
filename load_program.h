#ifndef _load_program_h
#define	_load_program_h

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <comp421/yalnix.h>
#include <comp421/hardware.h>
#include "yalnix_core.h"

extern int LoadProgram(char *name, char **args, ExceptionStackFrame* frame);


#endif

