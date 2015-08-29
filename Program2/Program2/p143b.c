//
//  p143b.c
//  Program2
//
//  Created by Mike Bynum on 10/12/14.
//  Copyright (c) 2014 Mike Bynum. All rights reserved.
//

#include "p143b.h"

int main (int argc, const char * argv[])
{
    int i,sum;
    sem_t semID; //semaphore ID
    void *address;
    int key; //unique integer identifier for the shared memory region to be created, attached to, or
    //detached from
    
    //map the shared memory region into an address space using
    //shmem system call
    shmem();
    
    
    //compute the sum of the 2047 4-byte integers in the two-page
    //shared memory region
    for (i=0; i<2047; i++)
    {
        <#statements#>
    }
    
    //place the sum in the second integer
    //in the shared memory region
    
    
    //display the sum on the console
    printf("The sum of the 2047 integers is: %d\n", sum);
    
    //do an up on the semaphore whose ID is the first 4-bytes of the
    //shared memory region
    semID = address[0];
    up(semID);
    
    //free the shared memory region
    
    return 0;
}
