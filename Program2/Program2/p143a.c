//
//  p143a.c
//  Program2
//
//  Created by Mike Bynum on 10/4/14.
//  Copyright (c) 2014 Mike Bynum. All rights reserved.
//  -create a two-page shared region
//  -then fill all of it except for the first four bytes
//  with random integers (using rand function)
//  -then create a semaphore with an initial count of 0
//  -put the semaphore ID in the first 4
//  bytes of the shared memory region
//  -then display a message saying it is waiting on
//  the second process
//  -do a down operation on the semaphore with a reasonably long
//  timeout value (say 5 minutes, or perhaps less)
//  -This will, of course block the process.
//  -When it continues, if it timed out, it will display an appropriate error message,
//  free the shared memory region (that is, unmap it from the process virtual address space using
//  shmem), free the semaphore, and quit.
//  -If it did not time out, it will display the value of
//  the integer in the second 4 bytes of
//

#include <p143a.h>
#include <sys.c>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

#define RAND_MAX 32767

int rand(void);
unsigned long rand_seed = 1;

int main(int argc, const char * argv[]) {

    int key; //unique integer identifier for the shared memory region to be created, attached to, or
             //detached from
    void *address; //pointer to the lowest (virtual) address in the shared memory region
    sem_t semID; //semaphore ID
	int err; //error code from a system call
	int i; //used for a counter
	
	key = 12345;
    
    //create a two-page shared region (each page is 4K bytes)
    err = shmem(key,2, (void **) &address);
	
	if (err != 0) {
	    printf("shmem failed in shmdemo 1; error code = %d\n", err);
	    exit(1);
	}
    
    //fill all except first 4 bytes with random ints (each int is 4 bytes long)
    //--original number is 2048 because each page is 1024 and there are 2 pages--
    for(i=1;i<=2047;i++)
    {
	    address[i] = rand();
    }
    
    //create semophore with initial count of 0
	semID =  newsema(0);
   
   	if (semID < 0) 
   	{
	    printf("newsema failed; error code = %d\n", (int)semID);
	    shmem(key,0,(void **)&address);	/* free the shared memory */
	    exit(1);
	}
    
    //put semID in the first 4 bytes of shared memory region
    address[0] = int(semID);
    
    printf("\nWaiting on the second process....\n");
    
    //do a down operation on a semaphore (5 min)
    //if time runs out, throw an error
    if(down(semID,300000) == TIMEOUT)
	{
		printf("shmdemo 1 timed out.\n");
	}
    else
	{
	    printf("Successfully returned to shmdemo 1.\n");
	}
	
	shmem(key,0,(void **)&address);
	freesema(semID);
    return 0;
}


int rand(void) {
    rand_seed = rand_seed * 1103515245 + 12345;
    return (unsigned int)(rand_seed >> 16) & RAND_MAX;
}