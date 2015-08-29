/*---------------------------------------------------------------*/
/* shmdemo.c -- Demonstrate Tempo's original shmem system call.  */
/*								 */
/* Invoke this program as "shmdemo 1" or "shmdemo 2".		 */
/*								 */
/* When invoked as "shmdemo 1" it will do this:			 */
/* 1. Create a shared memory region with the key 12345.		 */
/* 2. Create a semaphore with a count of 0.			 */
/* 3. Copy the semaphore ID to the first 4 bytes of the shared	 */
/*    memory region.						 */
/* 4. Fill the next 100 ints of the shared memory region with    */
/*    the values 1, 2, ... 100 (4 bytes each, of course).	 */
/* 5. Do a down on the semaphore, causing us to block.		 */
/*    Use a timeout value of 1 minute, just for safety.		 */
/* 6. When we awaken, if a timeout occurred, report and error.   */
/*    Otherwise, report success.				 */
/* 7. Unmap the shared memory region and free the semaphore.	 */
/* 8. Terminate.						 */
/*								 */
/* When invoked as "shmdemo 2" it will do this:			 */
/* 1. Attach to the shared memory region with the key 12345.	 */
/*    Assume the region contains an array of ints named a.	 */
/* 2. Check that a[1] through a[100] contain 1 through 100. If   */
/*    they don't report an appropriate error message. Otherwise  */
/*    report that the integer values are correct.		 */
/* 3. Copy the semaphore ID in the first int of shared memory to */
/*    a local variable.						 */
/* 4. Unmap the shared memory region.				 */
/* 5. Do an up on the semaphore (use the non-shared memory ID).  */
/* 6. Terminate.						 */
/*---------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int main(int argc, char *argv[])
{
    int which;			/* which way was the program invoked? */
    int err;			/* error code from a system call */
    int *mem;			/* pointer to the shared memory region */
    int i;			/* loop index */
    sem_t s;			/* semaphore ID */

    if (argc == 2)
	which = atoi(argv[1]);
    if (argc != 2 || which < 1 || which > 2) {
	printf("Usage:    shmdemo 1    -or-    shmdemo 2\n");
	printf("Look at the program source code for details on operation.\n");
	return 1;
    }

    if (which == 1) {
	err = shmem(12345,1,(void **)&mem);
	if (err != 0) {
	    printf("shmem failed in shmdemo 1; error code = %d\n", err);
	    exit(1);
	}
	s = newsema(0);
	if (s < 0) {
	    printf("newsema failed; error code = %d\n", (int)s);
	    shmem(12345,0,(void **)&mem);	/* free the shared memory */
	    exit(1);
	}
	mem[0] = (int)s;
	for(i=1;i<=100;i++)
	    mem[i] = i;
	if (down(s,60 * 1000) == TIMEOUT)	/* one minute, for now XXX */
	    printf("shmdemo 1 timed out.\n");
	else
	    printf("Successfully returned to shmdemo 1.\n");
	shmem(12345,0,(void **)&mem);
	freesema(s);
	return 0;
    }

    if (which == 2) {
	err = shmem(12345,1,(void **)&mem);
	if (err != 0) {
	    printf("shmem failed in shmdemo 2; error code = %d\n", err);
	    exit(1);
	}
	err = 0;	/* this is 0 anyway, but we'll be explicit */
	for(i=1;i<=100;i++) {
	    if (mem[i] != i) {
		err = i;
		break;
	    }
	}
	if (err) {
	    printf("shmdemo 2 error: value in mem[%d] = %d.\n", err, mem[err]);
	    printf("                 It should be %d\n", err);
	} else
	    printf("shmdemo 2: all integer values are as expected.\n");
	s = (sem_t)mem[0];
	shmem(12345,0,(void **)&mem);
	up(s);
	return 0;
    }
}
