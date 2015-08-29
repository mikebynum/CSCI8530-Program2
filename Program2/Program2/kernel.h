/*************************************/
/* kernel.h - declarations for Tempo */
/*************************************/
#ifndef KERNEL_H
#define KERNEL_H

/**********************************************************/
/* Define the symbol VALIDATE to request that the system  */
/* perform ambitious validation of the various structures */
/* used. This is very useful in finding pointer problems. */
/**********************************************************/
#define VALIDATE

/***********************************************************/
/* Define the symbol ENABLEDISK (that is, include the line */
/* "#define ENABLEDISK") if you wish  Tempo to utilize the */
/* first hard disk on the first disk controller. DO NOT    */
/* include this line if want to protect the contents of    */
/* the hard disk on the system executing Tempo.            */
/***********************************************************/
#define ENABLEDISK

/*************************************************************/
/* Define the symbol MAXNIC as the maximum number of network */
/* interface controllers (NICs) that you wish to utilize. If */
/* this value is 0, then no network support will be included */
/* in the system. If a system has more than MAXNIC Ethernet  */
/* cards, then only the first MAXNIC of them discovered in   */
/* the scan of the PCI busses will be available.             */
/*************************************************************/
#define MAXNIC 1

#include "../h/syserrs.h"
#include "../h/sysparm.h"
#include "../h/types.h"
#include "../h/hdisk.h"
#include "../h/video.h"
#include "../h/enet.h"

#define CTLG 0x07
#define CTLH 0x08
#define CTLI 0x09
#define CTLJ 0x0a
#define CTLL 0x0c
#define CTLM 0x0d
#define CTLU 0x15
#define CTLZ 0x1a
#define DEL 0x7f

#define EOFCH 0x1a	/* EOF character is control-Z */
#define TAB CTLI

/************************************************************/
/* User Segment Selectors (descriptors defined in kernel.s) */
/************************************************************/
#define USER_CODE_SEL 0x23
#define USER_DATA_SEL 0x2B

/************************************/
/* Where user virtual memory begins */
/************************************/
#define USERVMA 0x08000000

/*********************/
/* structure id tags */
/*********************/
#define TAG_PROCESS 0x7a3f
#define TAG_EQ 0x3fe8
#define TAG_SEMAPHORE 0xf20b
#define TAG_MSGNODE 0xee01
#define TAG_RDYQ 0x880b

/****************************/
/* Debug flags (in kd_Flag) */
/****************************/
#define DEBUG_RUN 0x0000001		/* 1 = display user stack in run */
#define DEBUG_ELF 0x0000002		/* 2 = display ELF loading info. */

/***********************/
/* Function prototypes */
/***********************/
void _initbc(void);			/* init buffer cache & fdesc array */
struct bufhd *getblk(unsigned int);	/* get buffer for specified block */
void brelse(struct bufhd *);		/* release a locked buffer */
struct bufhd *bread(unsigned int);	/* read a specified block */
int bmap(struct dirent *, unsigned int,	/* map offset in file to block/offset */
	 unsigned int*, unsigned int *);
int getfb(void);			/* get next free block from list */
struct bufhd *allocnb(int);		/* allocate next free block */
int dget(char *);			/* get locked fdesc entry for path */
int makede(char *,struct bufhd **,	/* make empty directory entry */
    unsigned int *);
void dtrunc(int);			/* delete all blocks for an open file */
void freedref(int);			/* reduce refcnt for fdesc entry */
int getfb(void);			/* get a block from the free list */
void putfb(int bn);			/* put a block on the free list */
struct bufhd *allocnb(int);		/* allocate a file block */

unsigned short getimask(void);		/* get interrupt mask from PICs */
void setimask(unsigned short);		/* set PIC interrupt masks */

/*-------*/
/* mem.c */
/*-------*/
void setpmap(void);			/* setup free physical page map */
unsigned int pgset(void);		/* setup initial page dir and table */
unsigned long sizmem(void);		/* get memory size, in pages */
int validaddr(unsigned int *);		/* check an address for validity */
void setpresent(int pageno, int state);	/* set/clear present bit for a page */
unsigned int *allocpage(
    unsigned int proctabndx, int zero);	/* allocate & clear? a physical page */
void freepage(unsigned int *addr);	/* free page of physmem at 'addr' */
void freeptents(unsigned int *addr);	/* free pages for a loaded process */
unsigned int *allocstack(
    int npages, unsigned int ptndx);	/* allocate pages to a process stack */
void freepages(int start, int n);	/* mark n pages from 'start' as free */
int _addimap(unsigned long addr);	/* identity map virt address 'addr' */
int virt2phys(unsigned long vaddr,	/* translate virt addr to phys addr */
    unsigned long *paddr);

#endif
