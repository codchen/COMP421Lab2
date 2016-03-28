COMP421
Lab2 - Yalnix Kernel
Xiaoyu Chen (xc12) and Jiafang Jiang (jj26)

* All implementations of the yalnix kernel locate in yalnix.c, except for 
  the idle program which locates in idle.c.

Data Structure
-----------------------------------------------------------------------------
Struct cei (Child Exit Info):
	Each struct contains pid and exit status of one exited child process, and
	the pointer to the next cei (NULL if none), which enables each parent 
	process to record all cei's in a FIFO linked list. Note that only when a
	child process exits will it add its corresponding cei to its parent's 
	linked list.

Struct pcb (Process Control Block):
	Each process has one until it exits. It contains all necessary bookkeeping
	variables, whose names themselves are self-explanatory enough. Still, two
	of them needs some more explanation. 'time_to_switch' is meaningful for 
	two kinds of processes. For the currently running process, it represents 
	the time that the process needs to be context switched if it has not 
	already done so through kernel calls during two clock clicks. In other
	words, when a process is context switched to, its time_to_switch will be 
	set to current system 'time' plus 2. The other kind of process is delayed
	process. When a process calls Delay, Its 'time_to_switch' will be set to 
	current system 'time' plus the amount of clock clicks it wants to delay.
	The other variable 'next' also has different meanings in different
	circumstances. When a process is in ready queue, its 'next' points to the
	the next ready process in ready queue (NULL if none). Similarly, when a 
	process is in other queues, its 'next' points to the next process in that
	specific queue.

Struct line:
	Struct line represents an input line of user from a specific terminal that
	has not been read by any programs. So each terminal has its own queue of 
	lines. 'buf' contains the actual line of inputs. 'cur' is the current 
	cursor on the line. 'len' is the length of the line. 'next' makes the 
	queue as a linked list.


-----------------------------------------------------------------------------