/*********************************************/
/* sys.c -- Tempo system call implementation */
/*********************************************/
#include "kernel.h"
#include "../h/stdarg.h"
#include "../h/runfile.h"
#include "../h/elf.h"
#include "../h/pe.h"
#include "../h/pic.h"

/***************************************************************************/
/* User processes (started by run) have the following memory organization: */
/*									   */
/*   +----------+ <-- USERVMA						   */
/*   |   code   |							   */
/*   +----------+							   */
/*   |   data   |							   */
/*   +----------+							   */
/*   |   heap   | <-- break						   */
/*   ~          ~							   */
/*   ~          ~							   */
/*   |  stack   |							   */
/*   +----------+ <-- USERVMA + 0x400000 = USERVMA + 4M			   */
/*									   */
/* Processes cannot be larger than 4M, including stack.			   */
/***************************************************************************/

struct Proc proctab[NPROC];	/* proctab[0] = idle process */
				/* proctab[1] = Main */

extern char start;
extern char etext;
extern char _end;

extern char pagedir;		/* system page directory (kernel.s) */
extern char pagetbl;		/* a single page table (kernel.s) */

int kd_Flag = 0;		/* kernel debug flags */

/*********************************************************************/
/* pgmap[i] contains:                                                */
/*     0 if physical page i is unused                                */
/*  1-254 if the page is used by 1-254 processes/threads             */
/*  0xff if the page was allocated, but not to a specific process    */
/*********************************************************************/
extern unsigned char pgmap[4096];

extern volatile int _rs;		/* reschedule flag (kernel.s) */

/***********************************************************************/
/* Each video display adapter supports one or more "consoles", one for */
/* each page of video RAM. The number of such consoles is specified by */
/* the NVPG parameter in sysparm.h. One of these pages/consoles is     */
/* visible at any time, and this is the one identified by the actcon   */
/* global variable. The cursor position for each console is given by   */
/* the values in the vidrow and vidcol arrays.                         */
/***********************************************************************/
/* actcon and the values in the vidrow and vidcol arrays are set to 0  */
/* during system initialization.                                       */
/***********************************************************************/
int actcon;		/* currently displayed console (0..NVPG-1) */
static int vidrow[NVPG];
static int vidcol[NVPG];

/*---------------------------*/
/* External function headers */
/*---------------------------*/
void outb(unsigned int, unsigned int);
unsigned char inb(unsigned int);
void *memcpy(void *dest, void *src, int n);
unsigned int getcr2(void);
int putchar(int);
void removep (Process p);
unsigned int _invtlb(void);
unsigned long ckmem(char *, unsigned);
int strcmp(char *,char *);
int conout(int,char);
void serput(int,char);
void bios_reboot(void);
unsigned int *allocpage(unsigned int proctabndx, int zero);
unsigned int *allocStack(int npages, unsigned int ptndx);
void _vtxt(unsigned char *s);

/*------------*/
/* Prototypes */
/*------------*/
int printf(char *Fmt, ...);
int idle(void);
int Main(void);
void quit(char *);
static void processDone(void);
void _addready (Process p);
void freepage(unsigned int *);
void freeptents(unsigned int *);
static void DeltaEnqueue (Process, unsigned int);
unsigned int _DeltaRemoveElement (Process);
static void startdiskcmd(void);
void awakeup(unsigned int);
int loadRUN(int, unsigned int, unsigned int *);
int loadELF(int, unsigned int, unsigned int *);
int loadPE(int, unsigned int, unsigned int *);
unsigned int uservmck(struct Proc *);
int xconout(int ch);
int chkrange(unsigned int lo, unsigned int hi);
void bios_reboot(void);

/*******************/
/* Debugging tools */
/*******************/
void newlog(unsigned int nbytes);
void logbyte(unsigned char b);

static int numprocesses;	/* number of processes in the system */
static unsigned int nextpid;	/* monotonically increasing process IDs */

Process activeProcess;		/* currently-executing process */
				/* also referenced in kernel.s */
				/* NULL until initialization completed */

unsigned int frstkey[NVPG];	/* first key available to user */
unsigned int nxtkey[NVPG];	/* index of first char */
unsigned short kbdata[NVPG][NKEYS];	/* keyboard data buffer */

sem_t Tempo_mutex;		/* CS-macro semaphore */
sem_t _keysem;			/* keyboard semaphore for console 0 */
				/* _keysem+i is sem_t for console i */

static struct Queue readyList[PRIORITY_LEVELS];	/* ready queues */

struct Sem _semtab[NSEMA];	/* pool of semaphores */

struct Shmem _shmtbl[NSHMEM];	/* shared memory structures */

static struct MsgNode msgtab[NMSGS];	/* pool of message nodes */

extern int _nticks;		/* time (in clock ticks) since startup */

extern unsigned int memsize;	/* # pages of RAM above 0x200000 (kernel.s) */

/**************************************************************/
/* For each video "page" that is not currently active, the    */
/* cursor location (row and column) is saved in these arrays. */
/**************************************************************/
extern unsigned int _vidrow[];
extern unsigned int _vidcol[];

/************/
/* Disk I/O */
/************/
int _diskpresent;		/* non-zero if a hard disk is present */
static unsigned int ncyls;	/* # of cylinders */
static unsigned int nheads;	/* # of heads */
static unsigned int nsects;	/* # of sectors per track */
static unsigned int maxblk;	/* maximum logical block number */
static unsigned int iostat;	/* I/O status (from controller) */
static struct IOreq *request;	/* request structure being created */
static int needstart;		/* 1 if disk I/O should be started */
static unsigned spc;		/* sectors per cylinder */
static struct IOreq IORQ[NDISKRQ];	/* pool of disk I/O request structs */
static struct IOreq *IOfree;	/* head of list of free IOreq structures */
static struct IOreq *IOhead;	/* ptr to first/active IOreq structure */
static struct IOreq *IOtail;	/* ptr to last pending IOreq structure */

/**************/
/* Filesystem */
/**************/
int _fspresent;			/* 0: no fs, 1: fs, -1: not yet checked */
extern struct superblock sblk;	/* the superblock for the filesystem */
extern struct FDESC fdesc[];	/* system-wide open file entries */
int abspath(char *path, char *rslt);	/* get absolute path */

/*****************/
/* Timed wakeups */
/*****************/
static Process sleepq;		/* first ms-sleeping process */
static Process awakeq;		/* first RTC-sleeping process */

/*******************************************************************/
/* Overall system execution time limit, in ticks. If this is zero, */
/* then no time limit is enforced. Primarily for system debugging. */
/*******************************************************************/
static unsigned int _time_limit = 0;

int _ticks_left;		/* ticks remaining before context switch */
int qrunouts = 0;		/* total times quantum expired (statistic) */
int _quantum = 0;		/* clock ticks per process "release" */

/********************/
/* Ethernet support */
/********************/
#if MAXNIC>0

struct nic *_nicdev[MAXNIC];	/* one for each possible NIC */

#endif

int _numnic = 0;		/* number of NICs found */


/*----------------------------------------------------------------*/
/* kprintf - used ONLY for kernel printing; always uses console 0 */
/*----------------------------------------------------------------*/
int kprintfOut (char *Str, char Char)
{
    return conout(0,Char);
}

int kprintf(char *Fmt, ...)
{
    va_list Args;
    int RetVal;

    va_start(Args, Fmt);
    RetVal = myPrintf(kprintfOut, NULL, Fmt, Args);
    va_end(Args);

    return RetVal;
}

/*-------------------------------------------------------------*/
/* dprintf - like kprintf, but writes to serial port 0 (com1:) */
/*-------------------------------------------------------------*/
int dprintfOut(char *Str, char Char)
{
    serput(0,Char);
    return (int)Char;
}

int dprintf(char *Fmt, ...)
{
    va_list Args;
    int RetVal;

    va_start(Args, Fmt);
    RetVal = myPrintf(dprintfOut, NULL, Fmt, Args);
    va_end(args);

    return RetVal;
}

/*-------------------------------------*/
/* Display a backtrace of stack frames */
/*-------------------------------------*/
void backtrace(unsigned int *ebp)
{
    unsigned int *iptr;

    kprintf("Call Frame Backtrace (ebp = %x)\r\n", ebp);
    kprintf("     ebp    return\r\n");
    while (validaddr(ebp)) {
	kprintf("%8x  ", ebp);
	kprintf("%8x\r\n", *(ebp+1));
	ebp = (unsigned int *)(*ebp);
    }
}

/*********************************************************/
/* Given a process ID, return the address of its process */
/* structure, or NULL if it does not exist.              */
/*********************************************************/
struct Proc *pid2a(pid_t pid)
{
    int i;

    for (i=0;i<NPROC;i++) {
	if (proctab[i].state == PROCESS_FREE) continue;
	if (proctab[i].pid == pid) return &proctab[i];
    }
    return 0;
}

/*******************************************/
/* Get the current external interrupt mask */
/*******************************************/
unsigned short getimask(void)
{
    unsigned char a1, a2;

    a1 = inb(PIC1_DATA);
    a2 = inb(PIC2_DATA);
    return ((unsigned short)a2 << 8) | a1;
}

/***********************************/
/* Set the external interrupt mask */
/***********************************/
/************************************************************************/
/* Note that bits in the mask are set to PREVENT interrupt notification */
/* from being passed through the PIC to the processor. Also note that   */
/* IRQ2 is the cascade interrupt, and its bit should always be 0.       */
/************************************************************************/
void setimask(unsigned short imask)
{
    unsigned char a1, a2;

    a1 = imask & 0xfb;		/* force IRQ2 to be recognized */
    a2 = imask >> 8;
    outb(PIC1_DATA,a1);
    outb(PIC2_DATA,a2);
}

/******************************************************************/
/* setxih: establish (if f is not null) or clear the second-level */
/* handler for an external interrupt.                             */
/******************************************************************/
extern void(*xitab[])(void);

void setxih(int irq, void (*f)(void) )
{
    unsigned short im;

    kprintf("Entering setxih\r\n");
    /*----------------------------------*/
    /* Verify a valid irq was specified */
    /*----------------------------------*/
    if (irq < 0 || irq > 15) {
	kprintf("setxih: invalid irq number to setxih.\r\n");
	while(1);
    }
    if (irq == 0 || irq == 1 || irq == 8 || irq == 14) {
	kprintf("setxih: irq handled by built-in handler.\r\n");
	while(1);
    }

    if (f == NULL) {	/* if disabling, set PIC bit, clear xitab entry */
kprintf("f is NULL in setxih!\r\n");
	im = getimask();		/* get current PIC mask bits */
	im = im | (1 << irq);		/* set bit (disable int recog) */
	setimask(im);
	xitab[irq] = 0;
	return;
    }

    /*-----------------------------------------------------------------------*/
    /* Otherwise put the appropriate address in the xitab enry and clear the */
    /* appropriate mask bit. This will enable recognition of the interrupt.  */
    /*-----------------------------------------------------------------------*/
    kprintf("setxih: irq = %d, f = 0x%08x\r\n", irq, f);
    xitab[irq] = f;
    im = getimask();
    im &= ~(1 << irq);
    setimask(im);
} 

/*****************************************************************/
/* Given an allocated semaphore's ID, return the address of its  */
/* underlying structure, or NULL if ID is bad or not allocated.  */
/*****************************************************************/
/* NB. A semaphore's ID is one larger than the index of its      */
/* _semtab table entry. This allows us to make a semaphore ID of */
/* 0 an illegal value; this is likely a common mistake, and we   */
/* can catch it here.                                            */
/*****************************************************************/
struct Sem *sid2a(sem_t sid)
{
    if (sid < 1 || sid > NSEMA) return NULL;
    if (_semtab[sid-1].count == -1) return NULL;	/* not allocated */
    return &_semtab[sid-1];
}

char *Msg[] = {			/* Name exceptions */
    "zero divide",
    "debug exception",
    "NMI",
    "INT3",
    "INTO",
    "BOUND exception",
    "invalid opcode",
    "no coprocessor",
    "double fault",
    "coprocessor segment overrun",
    "bad TSS",
    "segment not present",
    "stack fault",
    "GPF",
    "page fault",
    "coprocessor error",
    "??",
    "alignment check",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "??",
    "timer tick",
    "keyboard",
    "IRQ 2",
    "IRQ 3",
    "IRQ 4",
    "IRQ 5",
    "floppy",
    "IRQ 7",
    "real-time clock",
    "IRQ 9",
    "IRQ 10",
    "IRQ 11",
    "IRQ 12",
    "math chip",
    "primary IDE",
    "secondary IDE"
};

/****************************/
/* XXX - This is incomplete */
/****************************/
static void StackDump(void)
{
    unsigned int esp = getesp();
    int i;

    dprintf("ss = 0x??, esp = 0x%x\r\n", esp);
    for (i=0;i<25;i++)
	dprintf("0x%08x: 0x%08x\n", esp+i*4, *(unsigned int *)(esp+i*4));
    dprintf("-----------------------\n");
    dprintf("_keysem = %d (should be 2)\n", _keysem);
    dprintf("TAG_SEMAPHORE = 0x%08x\n", TAG_SEMAPHORE);
    for (i=1;i<=NVPG;i++) {
	dprintf("_semtab[%d].tag = 0x%08x\n", i, _semtab[i].tag);
	dprintf("_semtab[%d].count = %d\n", i, _semtab[i].count);
	dprintf("_semtab[%d].head/tail = 0x%08x/0x%08x\n",
	    i, _semtab[i].head, _semtab[i].tail);
    }
    dprintf("-----------------------\n");
    dprintf("activeProcess = 0x%08x\n", activeProcess);
    if (activeProcess != NULL) {
	dprintf("   pid = %d\n", activeProcess->pid);
	dprintf("   tag = 0x%08x (should be 0x%08x)\n",
	    activeProcess->tag, TAG_PROCESS);
	dprintf("   stkbase = 0x%08x\n", activeProcess->stkbase);
	dprintf("   kstkbase = 0x%08x\n", activeProcess->kstkbase);
	dprintf("   ksp = 0x%08x\n", activeProcess->ksp);
    }
}

/*****************************************************/
/* unhand: print information for unhandled exception */
/*****************************************************/
void unhand(unsigned int WhichInt, unsigned int Off, unsigned int Sel)
{
    kprintf("\nException #%u (%s) at address 0x%X:0x%lX\r\n"
	"System halted.\r\n", WhichInt, (WhichInt < 48 ?
	Msg[WhichInt] : "??"), Sel, Off);
    dprintf("\nException #%u (%s) at address 0x%X:0x%lX\r\n"
	"System halted.\r\n", WhichInt, (WhichInt < 48 ?
	Msg[WhichInt] : "??"), Sel, Off);
    StackDump();
}

/***************************************************************/
/* Dump process-related information for debugging some faults. */
/***************************************************************/
void dumpproc(void)
{
    unsigned int *pda;			/* page directory address */
    unsigned int *pta;			/* user page table address */
    unsigned int pagenum;		/* page# for staddr */
    int i;

    pda = (unsigned int *) &pagedir;

#define OMIT
#ifdef OMIT
    kprintf("start = 0x%08x, ptaddr = 0x%08x\r\n",
	activeProcess->staddr, activeProcess->ptaddr);
    kprintf("page directory: [0] = 0x%08x, [%d] = 0x%08x\r\n",
	pda[0], USERVMA>>22, pda[USERVMA>>22]);
    pta = (unsigned int *)((unsigned int)pda[USERVMA>>22] & ~0xfff);
    pagenum = (activeProcess->staddr >> 12) & 0x3ff;
    kprintf("page table entry for start = [%d] = 0x%08x\r\n",
	pagenum, pta[pagenum]);
    kprintf("page table (at 0x%08x) entries:\r\n", pta);
    for (i=16;i<80;i++) {
	if (i % 8 == 0) printf("%02d: ", i);
	kprintf("%08x ",pta[i]);
	if (i % 8 == 7) kprintf("\r\n");
    }
    for (i=1016;i<1024;i++) {
	if (i % 8 == 0) printf("%04d: ", i);
	kprintf("%08x ",pta[i]);
	if (i % 8 == 7) kprintf("\r\n");
    }
#endif
}

/******************************************************/
/* unhand2: print information for unhandled exception */
/*          which has an error code                   */
/******************************************************/
void unhand2(unsigned int WhichInt, unsigned int ErrorCode,
    unsigned int Off, unsigned int Sel)
{
    unsigned long PageFaultAdr;

    kprintf("\nException #%u (%s) at address 0x%x:0x%08x (error code "
	"0x%x)\r\n", WhichInt, (WhichInt < 48 ? Msg[WhichInt] : "??"),
	Sel, Off, ErrorCode);
    if (WhichInt == 14) {
	PageFaultAdr = getcr2();
	kprintf("Page fault address: 0x%08x\r\n", PageFaultAdr);
	dumpproc();
    }
}

/***************************************************************************/
/* hpfault: handle page faults (0x0E == 14)                                */
/*-------------------------------------------------------------------------*/
/* The only page faults from which we recover are those caused by a user   */
/* process attempting to expand the stack space for the process, and then  */
/* only for "new-style" processes (those started with the "run" system     */
/* call. "Old-style" processes are started with a specified stack size     */
/* which is never enlarged. We enlarge the stack for "new-style" processes */
/* by adding a page to the stack, if possible, and then restarting the     */
/* instruction that caused the fault.                                      */
/*                                                                         */
/* The error code for the cases we handle must be 0110b (0x6). That is,    */
/* it must have been caused by a non-present page (not protection),        */
/* it must have been a write operation (not a read), the processor must    */
/* have been executing in user mode, and the fault must not have occurred  */
/* because of a reserved bit set to 1 in a page directory.                 */
/*                                                                         */
/* The possibility exists that adding just a single page will not correct  */
/* the problem. Even in this case, though, we can proceed by adding just a */
/* single page at a time.                                                  */
/*                                                                         */
/* Addition of the new page will be allowed if (1) there is an available   */
/* page of physical memory, (2) the page table slot for the new page is    */
/* not already used, and (3) the next (lower) page table slot is unused.   */
/* This guarantees that we won't accidentally create a situation where the */
/* stack growth beyond currently allocated space will not be detected      */
/* unless each page of the stack isn't actually referenced!                */
/***************************************************************************/
void hpfault(unsigned int ErrorCode, unsigned int Off, unsigned int Sel)
{
    unsigned long PageFaultAdr;
    int ok = 1;
    unsigned int *pda;			/* page directory address */
    unsigned int *pta;			/* user page table address */
    unsigned int ptx;			/* page table index */
    unsigned int *np;			/* ptr to newly allocated page */

    PageFaultAdr = getcr2();		/* get linear address causing fault */
dprintf("Page fault:\n   Linear address = 0x%08x\n", PageFaultAdr);
dprintf("   Error code = 0x%08x\n", ErrorCode);
if (activeProcess == NULL) dprintf("   Old"); else dprintf("   New");
dprintf("-style process\n");

    /*-----------------------------------------------------------*/
    /* Determine if this qualifies for potential stack expansion */
    /*-----------------------------------------------------------*/
    if (ok == 1 && ErrorCode != 6) ok = 0;
    if (ok == 1 && activeProcess == NULL) ok = 0;
#ifdef VALIDATE
    if (ok == 1 && activeProcess->tag != TAG_PROCESS) ok = 0;
#endif
    if (ok == 1 && activeProcess->ptaddr == 0) ok = 0;

    if (!ok) {
	kprintf("\nPage fault at address 0x%x:0x%08x (error code "
	    "0x%x)\r\n", Sel, Off, ErrorCode);
	kprintf("Linear address causing fault: 0x%08x\r\n", PageFaultAdr);
	/* dumpproc(); */
	/*-------------------------------------------------------------*/
	/* At this point we might choose just to terminate a process   */
	/* if the fault occurred in user mode. We might also terminate */
	/* a process if the fault occurred in kernel mode, but the     */
	/* probability of such a fault being the user's responsibility */
	/* is (hopefully) small, and so shutting down the system is    */
	/* probably safer.                                             */
	/*-------------------------------------------------------------*/
	pcdebug();
	kprintf("System halted.\r\n");
	while(1);
    }

    /*---------------------------------------------------------------*/
    /* Determine if the faulting address is in the first unallocated */
    /* stack page. As a result of this test, we won't be able to     */
    /* handle faults that access lower pages of the stack (that is,  */
    /* code that "leaves a hole") before accessing the next lowest   */
    /* page. It's conceivable that this could occur if more than 4K  */
    /* is required for local variables, but we'll take that chance - */
    /* for now.                                                      */
    /*---------------------------------------------------------------*/
    pda = (unsigned int *) &pagedir;
    pta = (unsigned int *)((unsigned int)pda[USERVMA>>22] & ~0xfff);

    /*-------------------------------------------------------------------*/
    /* Bits 21..12 of the linear address are the index to the page table */
    /* slot that would be used if the translation had succeeded.         */
    /* This must obviously be in the range 0..1023, and 1023 (the top    */
    /* stack page) shouldn't be an acceptable value for stack expansion. */
    /*-------------------------------------------------------------------*/
    /* Conditions required:                                              */
    /*	   ptx < 1023 && ptx > 0                                         */
    /*        (Actually, ptx must be above the last data page...)        */
    /*     pta[ptx] == 0                                                 */
    /*     pta[ptx+1] != 0                                               */
    /*     pta[ptx-1] == 0                                               */
    /*-------------------------------------------------------------------*/
    ptx = (PageFaultAdr >> 12) & 0x3ff;
    ok = (ptx < 1023 && ptx > 0 && pta[ptx] == 0 && pta[ptx+1] != 0 &&
	pta[ptx-1] == 0);
dprintf("   ptx = %d; pta[ptx+1]...pta[ptx-1] = ", ptx);
dprintf("0x%08x, 0x%08x, 0x%08x\n", pta[ptx+1], pta[ptx], pta[ptx-1]);
dprintf("   ok = %d\n", ok);
    if (ok) {
	np = allocpage(0,1);		/* allocate zero-filled page */
if (np == 0) dprintf("   *** No pages available for stack expansion.\n");
	if (np != 0) {			/* if successful */
	    pta[ptx] = (unsigned int)np | 7;
	    /* Do we have to invalidate the TLB? */
	    return;
	}
    }
	    
    kprintf("\n---DEBUG---\r\n");
    kprintf("\nPage fault; page table index = %d\r\n", ptx);
    kprintf("Linear address causing fault: 0x%08x\r\n", PageFaultAdr);
    dumpproc();
    pcdebug();
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/
/*    S Y S T E M   C A L L   I M P L E M E N T A T I O N    */
/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/
/* Each of these functions is to be called ONLY from isr30,  */
/* and is to have a name that begins with an underscore (in  */
/* C) and two underscores (in assembler). Each function has  */
/* a single 'void *' parameter (which may be recast to a 32- */
/* bit object, as necessary).                                */
/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/
/* Many of these functions would be signficantly faster if   */
/* they were implemented in assembler. In the interest of    */
/* pedagogy, they are written in C if possible.              */
/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/
/* If a processor rescheduling is possibly required after a  */
/* system call, then the global flag '_rs' should be set to  */
/* 1 before the system call body returns.                    */
/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

/**********************************************************************/
/**********************************************************************/
/********* System Call 0: Display a character on the console  *********/
/**********************************************************************/
/**********************************************************************/

/* #define M6845_INDEX 0x3d4 */
/* #define M6845_DATA 0x3d5 */

/***********************************/
/* Set the visible cursor location */
/***********************************/
static void vsetcur(int vpage, int vcol, int vrow)
{
    unsigned int offset;		/* offset to cursor position */

    if (vcol >= 80) vcol = 79;		/* guarantee valid column number */
    if (vrow >= 25) vrow = 24;		/* guarantee valid row number */
    offset = 2000 * vpage		/* compute offset */
	+ vrow * 80 + vcol;

    outb(M6845_INDEX,14);		/* select high-order cursor port */
    outb(M6845_DATA,(offset>>8)&0xff);	/* write high-order bits */
    outb(M6845_INDEX,15);		/* select low-order cursor port */
    outb(M6845_DATA,offset & 0xff);	/* write low-order bits */
}

/********************************************/
/* Scroll a page of video memory up one row */
/********************************************/
static void vscroll(int vpage)
{
    unsigned int c;			/* column number */
    unsigned int offset;		/* offset to page 'vpage' in vid RAM */
    unsigned char *vbase;		/* base of RAM for page 'vpage' */

    offset = vpage * 80 * 25;		/* offset to page */
    vbase = (unsigned char *)0xb8000 + 2 * offset;
    memcpy(
	(void *)vbase,			/* destination */
	(void *)vbase+160,		/* source */
	(size_t)(24 * 160));		/* # bytes to copy */
    for (c=0;c<80;c++)			/* reset the last row */
	vbase[24*160+c*2] = ' ';
}

/********************************/
/* Clear a page of video memory */
/********************************/
void clearpg(int vpage)
{
/* What to fill the page with (character, color): */
/*    unsigned short blank = 0x0720;	/* blank, white on black */
/*    unsigned short blank = 0x0420;	/* blank, red on black */
/*    unsigned short blank = 0x0220;	/* blank, green on black */
/*    unsigned short blank = 0x0120;	/* blank, blue on black */
    unsigned short blank = 0x7020;	/* blank, black on white */
/*    unsigned short blank = 0xf820;	/* blank, blink black on hi-white */
    unsigned int offset;
    unsigned short *vidmem;		/* word-sized video RAM */
    int i;

    offset = vpage * 80 * 25;
    vidmem = (unsigned short *)(0xb8000 + 2 * offset);
    for (i=0;i<80*25;i++) vidmem[i] = blank;
}

/******************************************************/
/* "Display" character 'ch' on console page 'con'.    */
/* If 'con' specifies the currently-visible console,  */
/* also change the position of the visible cursor.    */
/******************************************************/
int vcout (int con, int ch)
{
    unsigned int charno;
    unsigned int *vcol, *vrow;
    unsigned int offset;		/* offset to page 'vpage' in vid RAM */
    unsigned char *vbase;		/* base of RAM for page 'vpage' */

    if (con < 0 || con > NVPG-1) return NOSUCHCON;
    vcol = &vidcol[con];
    vrow = &vidrow[con];

    switch(ch) {
	case CTLH:			/* backspace */
	    if (*vcol > 0) (*vcol)--;
	    break;

/* Tabs can be "destructive" or "non-destructive". A destructive tab will  */
/* cause the columns which are skipped to be forced to blank, while a non- */
/* destructive tab will not alter the skipped columns. We implement a non- */
/* destructive tab in this code.                                           */
	case CTLI:			/* tab */
	    (*vcol)++;
	    while ((*vcol & 7) != 0) (*vcol)++;
	    break;

	case CTLJ:			/* line feed */
	    (*vrow)++;
	    if (*vrow == 25) {		    /* past end of video page? */
		vscroll(con);
		*vrow = 24;
	    }
	    break;

	case CTLL:			/* form feed */
	    clearpg(con);
	    *vrow = *vcol = 0;
	    break;

	case CTLM:			/* carriage return */
	    *vcol = 0;			    /* back to column 0 */
	    break;

	default:			/* all other characters */
	    charno = (*vrow) * 80 + *vcol;    /* char # on video page */
	    offset = con * 80 * 25;		/* offset to page */
	    vbase = (unsigned char *)0xb8000 + 2 * offset;
	    vbase[2*charno] = ch;	    /* store the character */
	    if (*vcol < 79) (*vcol)++;	    /* move to next column */
    }
    if (con == actcon)
	vsetcur(con,*vcol,*vrow);		/* move visible cursor */
    return ch;
}

/************************************/
/* System call interface for conout */
/************************************/
int _conout(void *args[])
{
    int con, ch;			/* syscall parameters */

    con = (int)args[0];
    ch = (int)args[1];
    if (con < 0 || con > NVPG-1) return NOSUCHCON;
    return vcout(con, ch);
}

/****************************************************************************/
/* Display a character on the currently-visible page and update the cursor. */
/****************************************************************************/
int xconout(int ch)
{
    return vcout(actcon,ch);
}

/******************************************/
/* Sound the audible alert on the console */
/******************************************/
static bell(void)
{
    /* For now, we'll do nothing */
}

/************************************************************************/
/* Display a null-terminated text string starting at 's' on the console */
/************************************************************************/
void _vtxt(unsigned char *s)
{
    while (*s) xconout(*s++);
}
/**********************************************************************/
/* Display byte (2 char), word (4 char), and long (8 char) hex values */
/**********************************************************************/
void _vhexb(unsigned char v)
{
    static char hexchar[] = "0123456789abcdef";
    xconout(hexchar[v/16]);
    xconout(hexchar[v%16]);
}
void _vhexw(unsigned short v)
{
    _vhexb(v>>8);
    _vhexb(v&0xff);
}
void _vhexl(unsigned long v)
{
    _vhexw(v>>16);
    _vhexw(v&0xffff);
}

/****************************************************/
/****************************************************/
/********* System Call 1: Select video page *********/
/****************************************************/
/****************************************************/
int _setvidpg(void *pg)
{
    unsigned int page = (unsigned int)pg;
    unsigned int offset;

    if (page >= NVPG) return NOSUCHVIDPG; /* parameter too large */

    if (page == actcon) return NOERROR;	/* no change */

    /*-----------------------------------------------------------------*/
    /* Registers 12 and 13 in the 6845 CRT controller chip are set to  */
    /* the offset of the new page in video ram. Note that this offset  */
    /* is in units of 16-bit (2-byte) quantities, since the chip views */
    /* ram in such units.                                              */
    /*-----------------------------------------------------------------*/
    actcon = page;
    offset = page * 80 * 25;		/* offset to new page */
    outb(M6845_INDEX,12);		/* select high-order pg offset port */
    outb(M6845_DATA,(offset>>8)&0xff);	/* write high-order bits */
    outb(M6845_INDEX,13);		/* select low-order pg offset port */
    outb(M6845_DATA,offset & 0xff);	/* write low-order bits */

    vsetcur(page,vidcol[page],vidrow[page]);	/* set visible cursor */

    return NOERROR;
}

/*********************************************************************/
/*********************************************************************/
/********* System Call 2: Return number of timer expirations *********/
/********* since the system was started.                     *********/
/*********************************************************************/
/*********************************************************************/
unsigned int _time(void *unused)
{
    return _nticks;
}

/**********************************************************/
/**********************************************************/
/********* System Call 3: Return the process ID of ********/
/********* the currently-executing process.       *********/
/**********************************************************/
/**********************************************************/
pid_t _getpid(void *unused)
{
    return activeProcess->pid;
}

/********************************************************************/
/********************************************************************/
/********* System Call 4: Return state of specified process *********/
/********************************************************************/
/********************************************************************/
int _getpstate(pid_t pid)
{
    struct Proc *p;

    p = pid2a(pid);			/* get ptr to process table entry */
    if (p == 0) return NOSUCHPROCESS;	/* bad pid */
    return p->state;
}

/*************************************************************/
/*************************************************************/
/********* System Call 5: Return the priority of the *********/
/********* currently-running process.                *********/
/*************************************************************/
/*************************************************************/
int _getprio(void *unused)
{
    return activeProcess->priority;
}

/***************************************************************************/
/***************************************************************************/
/********* System Call 6: Set overall system execution time limit. *********/
/***************************************************************************/
/***************************************************************************/
int _setxlimit(unsigned int newlimit)
{
    _time_limit = newlimit;
    if (_time_limit > 0 && _nticks >= _time_limit)
	quit("Time limit exceeded");
    return NOERROR;
}

/***************************************************************************/
/***************************************************************************/
/********* System Call 7: Get overall system execution time limit. *********/
/***************************************************************************/
/***************************************************************************/
unsigned int _getxlimit(void *unused)
{
    return _time_limit;
}

/*******************************************************/
/*******************************************************/
/********* System Call 8: Position the cursor. *********/
/*******************************************************/
/*******************************************************/
int _poscur(void *args[])
{
    int con, row, col;			/* syscall parameters */

    con = (int)args[0];
    row = (int)args[1];
    col = (int)args[2];

    if (con < 0 || con > NVPG-1) return NOSUCHCON;
    if (row < 1 || row > 25) return BADVAL;
    if (col < 1 || col > 80) return BADVAL;

    vidcol[con] = col - 1;
    vidrow[con] = row - 1;

    if (con == actcon)
	vsetcur(con,col-1,row-1);		/* move visible cursor */
}

/*************************************************************/
/*************************************************************/
/********* System Call 9: Set round-robin scheduling *********/
/********* quantum size (0 = FCFS scheduling).       *********/
/*************************************************************/
/*************************************************************/
int _setquantum(unsigned int newquantum)
{
    int oldquantum;

    oldquantum = _quantum;
    _quantum = newquantum;
    return oldquantum;
}

/*****************************************************************/
/*****************************************************************/
/********* System Call 10: Get round-robin quantum size. *********/
/*****************************************************************/
/*****************************************************************/
unsigned int _getquantum(void *unused)
{
    return _quantum;
}

/****************************************************************************/
/****************************************************************************/
/********* System Call 11: Set the priority of the current process. *********/
/****************************************************************************/
/****************************************************************************/
int _setprio(int newprio)
{
    int prio;

    /*----------------------------------------------------------------*/
    /* Note that IDLE_PRIORITY (the priority of the idle process) is  */
    /* smaller than LOWEST_PRIORITY. This system call can not be used */
    /* to set any process priority less than or equal to that of the  */
    /* idle process.                                                  */
    /*----------------------------------------------------------------*/
    if (newprio < LOWEST_PRIORITY || newprio > HIGHEST_PRIORITY)
	return BADPRIO;			/* bad new priority value */

    if (newprio == activeProcess->priority)
	return NOERROR;	/* no change in priority */

    activeProcess->priority = newprio;		/* set the new priority */

    /*------------------------------------------------------------*/
    /* If as a result of this priority change this process is no  */
    /* longer the highest priority process (or one of the highest */
    /* priority ready processes), it should yield the CPU so the  */
    /* correct higher-priority process can run. Note that the CPU */
    /* is not always relinquished, since if the current process   */
    /* now has the SAME priority as the highest-priority ready    */
    /* process, it doesn't want to yield the CPU. We do assume,   */
    /* though, that prior to the priority change that the current */
    /* process was (one of) the highest priority process in the   */
    /* system.                                                    */
    /*------------------------------------------------------------*/

    /*-----------------------------------------------------------*/
    /* Search through the set of all ready processes to identify */
    /* the one with the highest priority. There will (or should) */
    /* always be at least two at this point -- the idle process  */
    /* (which never calls setprio) and the process that called   */
    /* setprio. Q. What happens if there are no ready processes? */
    /*-----------------------------------------------------------*/
    /* Search the set of ready process for a process with a      */
    /* priority higher than 'newprio'. On exit from this loop,   */
    /* 'prio' will be greater than 'newprio' if a context switch */
    /* is indicated. Otherwise 'prio' will equal 'newprio'.      */
    /*-----------------------------------------------------------*/
    for (prio = HIGHEST_PRIORITY; prio > newprio; prio--)
	if (readyList[prio+1].head != NULL) break;

    /*-----------------------------------------------------------*/
    /* If a context switch is required, move the current process */
    /* back to the ready state, place it on the ready queue, and */
    /* set the reschedule flag.                                  */
    /*-----------------------------------------------------------*/
    if (prio > newprio) {
	_addready(activeProcess);
	_rs = 1;
    }
    return NOERROR;
}

/*********************************************************/
/*********************************************************/
/********* System Call 12: Create a new process. *********/
/*********************************************************/
/*********************************************************/
int _newproca (void *args[])
{
    /*------------------------*/
    /* system call parameters */
    /*------------------------*/
    int (*rootFnPtr)(void);	/* pointer to root fn */
    int priority;		/* priority */
    unsigned int stackSize;	/* user stack size, in pages */
    unsigned int nargs;		/* # of arguments */
    unsigned char **a;		/* ptr to array of arg strings */

    /*-----------------------*/
    /* other local variables */
    /*-----------------------*/
    struct Proc *p;		/* proctab entry to be used for this process */
    int i;
    unsigned int eflags;	/* eflags register on entry */
    unsigned int *stackPointer;	/* init. stack ptr for process */
    unsigned int *ksp;		/* kernel stack pointer */
    int targlen, tptrlen;	/* total argument, argument ptr length */
    unsigned char *parg;
    unsigned char **pptr;
    unsigned char *dptr;
    unsigned int *iptr;
    unsigned int ptndx;		/* index to proctab for this process */

    /*-----------------------------------*/
    /* Find an unused process table slot */
    /*-----------------------------------*/
    for (i=0;i<NPROC;i++) {
	if (proctab[i].state == PROCESS_FREE) break;
    }
    if (i == NPROC) return PROCTBLFULL;
    ptndx = i;
    p = &proctab[i];		/* save address of free proctab entry */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    rootFnPtr = (int (*)(void))args[0];
    priority = (int)args[1];
    stackSize = (unsigned int)args[2];
    nargs = (unsigned int)args[3];
    a = (unsigned char **)args[4];

    if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY)
	return BADPRIO;

    p->tag = TAG_PROCESS;
    p->priority = priority;
    p->pid = nextpid++;

    p->ptaddr = 0;	/* this will be a thread */

    if (activeProcess->ptaddr != 0) {	/* invoked from "new-style" process? */
	unsigned int a;
	p->ptaddr = activeProcess->ptaddr;
	a = (unsigned int)p->ptaddr;
	pgmap[a>>12]++;			/* increase ref count for page table */

	/*--------------------------------------------------------------*/
	/* Increase the reference count for all other pages used by the */
	/* active process EXCEPT its stack page(s).                     */
	/*--------------------------------------------------------------*/
	for (i=0;i<1023;i++) {
	    a = p->ptaddr[i];
	    pgmap[a>>12]++;
	}
    }

    /*-----------------------------------------------------*/
    /* Allocate and initialize a suitably-sized user stack */
    /*-----------------------------------------------------*/
    /*-----------------------------------------------------------------*/
    /* XXX Actually, we may want to consider the size of the arguments */
    /*     and their pointers as additional stack space requirements,  */
    /*     and increase 'stackSize' if a significant amount of stack   */
    /*     space is required by the process arguments. For most (all?) */
    /*     of the programs used with Tempo, even a 4K (1 page) stack   */
    /*     should be sufficient unless gargantuan arguments are used.  */
    /*-----------------------------------------------------------------*/
    /* XXX In any event, we should verify that the arguments we're     */
    /*     installing on the stack here don't exceed the available     */
    /*     space. If that case should arise, then we should report it  */
    /*     with a (perhaps new?) error code.                           */
    /*-----------------------------------------------------------------*/
    if (stackSize < 1) stackSize = 1;
    stackPointer = allocStack(stackSize,ptndx);
    if (stackPointer == NULL) return NOSTACKSPACE;	/* no stack space */
    p->stkbase = stackPointer;
    p->stksize = stackSize;

    /*---------------------------------------*/
    /* User stack organization               */
    /* Top of stack (highest address):       */
    /*    arg[N-1]                           */
    /*    ...                                */
    /*    arg[1]                             */
    /*    arg[0]                             */
    /*    padding to a 4-byte boundary       */
    /*    null pointer                       */
    /*    pointer to arg[N-1]                */
    /*    ...                                */
    /*    pointer to arg[1]                  */
    /* X: pointer to arg[0]                  */
    /*    X (addr of ptr array base)         */
    /*    N                                  */
    /*    pointer to processDone function    */
    /*---------------------------------------*/

    /*--------------------------------------------*/
    /* Determine the size of the string arguments */
    /*--------------------------------------------*/
    targlen = 0;
    for (i=0;i<nargs;i++) {
	if (a[i] != NULL) targlen += strlen(a[i]) + 1;  /* include nulls */
    }
    targlen = (targlen + 4) & ~3;			/* round up */
    tptrlen = (nargs + 1) * sizeof(char *);		/* ptr array size */
    parg = 4 + (unsigned char *)stackPointer;		/* ptr to stk top */
    parg -= targlen;					/* ptr to arg strs */
    pptr = (unsigned char **)(parg - tptrlen);		/* ptr to ptr array */
    dptr = parg - tptrlen;

    iptr = (unsigned int *)dptr;
    iptr--;
    *iptr = (unsigned int)dptr;
    iptr--;
    *iptr = (unsigned int)nargs;
    iptr--;
    *iptr = (unsigned int)processDone;

    /*--------------------------------------------------------------*/
    /* Copy nargs strings from a[] to parg, saving pointers at pptr */
    /*--------------------------------------------------------------*/
    /* If the caller included a NULL pointer as an argument pointer */
    /* we simply pass it along to the new process.                  */
    /*--------------------------------------------------------------*/
    for (i=0;i<nargs;i++) {
	if (a[i] != NULL) strcpy(parg,a[i]);
	else a[i] = NULL;
	*pptr++ = parg;
	if (a[i] != NULL) parg += strlen(a[i]) + 1;
    }
    *pptr = NULL;		/* install null pointer after last arg ptr */

    /*----------------------------------------------------------------*/
    /* Allocate and initialize the kernel-mode stack for this process */
    /*----------------------------------------------------------------*/
    ksp = allocStack(1,ptndx);		/* allocate a page for kernel stack */
    if (ksp == NULL) {			/* check for no more stack space */
	unsigned int start;
	start = (((unsigned int)activeProcess->stkbase) >> 12)
	    + 1 - activeProcess->stksize;	/* free user-mode stack */
	freepages(start,activeProcess->stksize);
	return NOSTACKSPACE;
    }
    p->kstkbase = ksp;
    p->kstkbase++;	/* ... different interpretation than user stack base */

    /*---------------------------------------*/
    /* Kernel stack organization             */
    /* Top of stack (highest address):       */
    /*    edi                                */
    /*    esi                                */
    /*    ebp                                */
    /*    esp (actually ignored)             */
    /*    ebx                                */
    /*    edx                                */
    /*    ecx                                */
    /*    eax                                */
    /*    ds                                 */
    /*    es                                 */
    /*    fs                                 */
    /*    gs                                 */
    /*    eip                                */
    /*    cs                                 */
    /*    eflags                             */
    /*    esp                                */
    /*    ss                                 */
    /*---------------------------------------*/

    /*-------------------------------------------------------*/
    /* Initialize the kernel mode stack. Some of the initial */
    /* register values are arbitrary, so we select values    */
    /* for them that might make debugging easier.            */
    /*-------------------------------------------------------*/
    *ksp-- = USER_DATA_SEL;		/* ss */
    *ksp-- = (unsigned int)iptr;	/* esp */
    *ksp-- = 0x200;			/* eflags */
    *ksp-- = USER_CODE_SEL;		/* cs */
    *ksp-- = (unsigned int)rootFnPtr;	/* eip */

    *ksp-- = 0xffffffff;		/* mirror push done on kernel entry */

    *ksp-- = USER_DATA_SEL;		/* gs */
    *ksp-- = USER_DATA_SEL;		/* fs */
    *ksp-- = USER_DATA_SEL;		/* es */
    *ksp-- = USER_DATA_SEL;		/* ds */

    *ksp-- = 0x12340001;		/* eax */
    *ksp-- = 0x12340002;		/* ecx */
    *ksp-- = 0x12340003;		/* edx */
    *ksp-- = 0x12340004;		/* ebx */
    *ksp-- = 0x12340005;		/* esp (ignored later) */
    *ksp-- = 0x12340006;		/* ebp */
    *ksp-- = 0x12340007;		/* esi */
    *ksp   = 0x12340008;		/* edi */

    p->ksp = ksp;

    /*------------------------------------------*/
    /* Initialize event queues for this process */
    /*------------------------------------------*/
    for (i = 0; i < NQUEUE; i++) {
	p->eventQueue[i].count= 0;
	p->eventQueue[i].mask = UNMASKED;
	p->eventQueue[i].head = NULL;
	p->eventQueue[i].tail = NULL;
    }

    for (i=0;i<2;i++) {			/* file descriptors 0/1 dup caller's */
	p->fd[i].how = activeProcess->fd[i].how;
	p->fd[i].fdescnr = activeProcess->fd[i].fdescnr;
    }
    for(i=2;i<NFD;i++) p->fd[i].fdescnr = -1;	/* others are available */

    (p->environ)[0] = '\0';		/* environment is empty */
    if ((activeProcess->workdir)[0] == '/')
	strcpy(p->workdir,activeProcess->workdir);
    else strcpy(p->workdir,"/");

    p->signaledOn = -1;
    numprocesses++;
    _addready(p);

    /*---------------------------------------------------------*/
    /* If the newly created process has a priority higher than */
    /* that of the current process, then yield the CPU to it.  */
    /*---------------------------------------------------------*/
    if (priority > activeProcess->priority) {
	_addready(activeProcess);
	_rs = 1;			/* reschedule the CPU */
    }
    return p->pid;
}

/******************************************************************/
/******************************************************************/
/********* System Call 13: Terminate the current process. *********/
/******************************************************************/
/******************************************************************/
int _exit (int status)
{
    /*-----------------------------------------------------------*/
    /* We need to communicate the exit status of this process to */
    /* other processes that may be waiting on it, but we need to */
    /* do most of the termination work after switching stacks.   */
    /* We use the 'exitstatus' field of the proctab entry to     */
    /* save the status temporarily. This is normally the status  */
    /* of a process on which another (different) process waited. */
    /*-----------------------------------------------------------*/
    activeProcess->exitstatus = status;
    _rs = 2;
    return NOERROR;		/* _xcleanup does most of the work */
}

/*----------------------------------------------------------------*/
/* _xcleanup handles wakeup of processes awaiting the termination */
/* of a process and reclamation of resources. It *MUST* run on a  */
/* stack other than that belonging to the terminating process, as */
/* those stacks are reclaimed here.                               */
/*								  */
/* activeProcess must still identify the terminating process.     */
/*----------------------------------------------------------------*/
int _xcleanup (void)
{
    int i;
    unsigned int start;
    struct MsgNode *node;
    unsigned int pte;		/* a page table entry */

    /*------------------------------------------------------------*/
    /* Awaken any processes waiting for the process to terminate. */
    /*------------------------------------------------------------*/
    for (i=1;i<NPROC;i++) {		/* skip checking the idle process */
	if (proctab[i].state == PROCESS_WAIT &&
	    proctab[i].waitingon == activeProcess->pid) {
	    proctab[i].exitstatus = activeProcess->exitstatus; /* see _exit */
	    _addready(&proctab[i]);
	}
    }

    /*---------------------------------------------------------------*/
    /* Reclaim any message nodes still queued to the process queues. */
    /*---------------------------------------------------------------*/
    for (i=0;i<NQUEUE;i++) {
	for (node = activeProcess->eventQueue[i].head;
	     node != NULL; node = node->next) {
	    node->sender = NULL;
	}
    }

    /*-----------------------------------------------------------*/
    /* If this is process (started with run), then reclaim the   */
    /* pages allocated (code, data, heap, stack) and the page    */
    /* table page. We must also determine if any of the pages    */
    /* being used are shmem-created/attached pages. If so, the   */
    /* reference count for each such page must be reduced, and   */
    /* if that goes to 0, the page is then returned to the pool  */
    /* of free pages.                                            */
    /*-----------------------------------------------------------*/
    if (activeProcess->ptaddr != 0) {
	freeptents(activeProcess->ptaddr);
    } else {
	/*-------------------------------------*/
	/* Free the stack pages for the thread */
	/*-------------------------------------*/
	start = (((unsigned int)activeProcess->stkbase) >> 12)
	    + 1 - activeProcess->stksize;
	freepages(start,activeProcess->stksize);
    }

    /*---------------------------------------------*/
    /* Free the kernel stack page for the process. */
    /*---------------------------------------------*/
    start = ((unsigned int)activeProcess->kstkbase) >> 12;
    pgmap[start-1] = 0;
    _invtlb();

    /*------------------------------------------*/
    /* Close any files that might still be open */
    /*------------------------------------------*/
    for (i=0;i<NFD;i++) {
	if (activeProcess->fd[i].fdescnr == -1) continue;
	if (activeProcess->fd[i].how < 0) continue;		/* console */
		/* XXX - We might need to change this if other */
		/*       types of consoles (e.g. serial ports) are added */
	freedref(activeProcess->fd[i].fdescnr);
    }

    /*------------------------------------*/
    /* Mark process table entry as unused */
    /*------------------------------------*/
    activeProcess->state = PROCESS_FREE;

    numprocesses--;
    if (numprocesses == 1) {	/* if only the idle process remains... */
	sync();			/* write remaining dirty buffers */
	quit(NULL);		/* hang... */
    }
}

/************************************************************************/
/************************************************************************/
/********* System Call 14: Allocate and initialize a semaphore. *********/
/************************************************************************/
/************************************************************************/
sem_t _newsema(int count)
{
    int i;

    /*-----------------------------------------------*/
    /* Verify initial semaphore count is acceptable. */
    /*-----------------------------------------------*/
    if (count < 0) return BADSEMCOUNT;

    /*--------------------------------------*/
    /* Find an unused semaphore table entry */
    /*--------------------------------------*/
    for (i=0;i<NSEMA;i++)
	if (_semtab[i].count == -1) break;	/* found an unused entry */
    if (i == NSEMA) return SEMTBLFULL;		/* no semaphores available */

#ifdef VALIDATE
    if (_semtab[i].tag != TAG_SEMAPHORE) quit("newsema: semaphore tag invalid");
#endif

    _semtab[i].count = count;
    _semtab[i].head = _semtab[i].tail = NULL;
    return i+1;				/* SEE NOTE IN sid2a FUNCTION */
}

/***************************************************************/
/***************************************************************/
/********* System Call 15: Do a "down" on a semaphore. *********/
/***************************************************************/
/***************************************************************/
int _down(int *args)
{
    sem_t s;			/* semaphore ID */
    int timeout;		/* timeout specification */
    struct Sem *sema;		/* ptr to the semaphore structure */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    s = (sem_t)args[0];
    timeout = args[1];

    sema = sid2a(s);
    if (sema == NULL) return BADSEMA;

#ifdef VALIDATE
    if (sema->tag != TAG_SEMAPHORE) quit("up: semaphore tag invalid");
#endif

    activeProcess->timedOut = FALSE;

    /*------------------------------------------------*/
    /* If the semaphore's count is greater than zero, */
    /* then just decrement it and return 0.           */
    /*------------------------------------------------*/
    if (sema->count > 0) {
	sema->count--;
	return NOERROR;
    }

    /*-----------------------------------------------*/
    /* If count is 0 and timeout is 0, the caller is */
    /* polling, so just return TIMEOUT.              */
    /*-----------------------------------------------*/
    if (timeout == 0) return TIMEOUT;

    /*--------------------------------------------------*/
    /* Otherwise the process must block, so we place it */
    /* on the semaphore's queue. We may also have to    */
    /* put it on the delta queue, if timeout > 0.       */
    /*--------------------------------------------------*/
    activeProcess->queue = (struct Queue *)sema;
    activeProcess->next = NULL;
    if (sema->head == NULL) {
	sema->head = sema->tail = activeProcess;
	activeProcess->prev = NULL;
    } else {
	sema->tail->next = activeProcess;
	activeProcess->prev = sema->tail;
	sema->tail = activeProcess;
    }

    if (timeout < 0) activeProcess->state = PROCESS_BLOCKED;
    else {
	activeProcess->state = SEM_TIMED_BLOCKED;
	DeltaEnqueue(activeProcess, timeout);
    }

    _block();

    /*-------------------------------------------------------*/
    /* Set badSema in the process table entry appropriately. */
    /* If the semaphore is deallocated while we're waiting,  */
    /* then freesema will set it to TRUE.                    */
    /*-------------------------------------------------------*/
    activeProcess->badSema = FALSE;

    /*---------------------------------------------------*/
    /* After 'up' or timeout, the process continues here */
    /*---------------------------------------------------*/
    if (activeProcess->timedOut) return TIMEOUT;
    else if (activeProcess->badSema) return BADSEMA;
    else return NOERROR;
}

/**************************************************************/
/**************************************************************/
/********* System Call 16: Do an "up" on a semaphore. *********/
/**************************************************************/
/**************************************************************/
int _up(sem_t s)
{
    struct Sem *sema;		/* ptr to the semaphore structure */
    int status;
    Process p;

    sema = sid2a(s);
    if (sema == NULL) return BADSEMA;

#ifdef VALIDATE
    if (sema->tag != TAG_SEMAPHORE) quit("up: semaphore tag invalid");
#endif

    /*--------------------------------------------------------------*/
    /* If there are no blocked processes, just increment the count. */
    /*--------------------------------------------------------------*/
    if (sema->head == NULL) {
	sema->count++;
	return NOERROR;
    }

    /*------------------------------------------------------------*/
    /* Awaken the first blocked process on the semaphore's queue. */
    /*------------------------------------------------------------*/
    p = sema->head;
    sema->head = sema->head->next;
    if (sema->head == NULL) sema->tail = NULL;

    /*------------------------------------------------------------*/
    /* If the process specified a timeout on the 'down' operation */
    /* then we must remove it from the delta queue.               */
    /*------------------------------------------------------------*/
    if (p->state == SEM_TIMED_BLOCKED) _DeltaRemoveElement(p);

    /*----------------------------------------------------*/
    /* Clear "badSema" flag in process table (necessary?) */
    /*----------------------------------------------------*/
    p->badSema = FALSE;

    /*------------------------------------*/
    /* Awaken the process (make it ready) */
    /*------------------------------------*/
    _addready(p);

    /*------------------------------------------------------------------*/
    /* Check for and handle preemption of the currently-running process */
    /*------------------------------------------------------------------*/
    if (p->priority > activeProcess->priority) {
	_addready(activeProcess);
	_rs = 1;
    }
    return NOERROR;
}

/*****************************************************/
/*****************************************************/
/********* System Call 17: Free a semaphore. *********/
/*****************************************************/
/*****************************************************/
int _freesema(sem_t s)
{
    struct Sem *sema;
    unsigned int eflags;
    Process p;

    sema = sid2a(s);
    if (sema == NULL) return BADSEMA;	/* bad or unused semaphore ID */

#ifdef VALIDATE
    if (sema->tag != TAG_SEMAPHORE) quit("freesema: semaphore tag invalid");
#endif

    sema->count = -1;			/* mark semaphore unused */

    /*-------------------------------------------------------------*/
    /* Go through the semaphore queue and arrange for each blocked */
    /* process to be awakened in such a manner that the 'down'     */
    /* call returns BADSEMA.                                       */
    /*-------------------------------------------------------------*/
    _rs = 0;
    while (sema->head != NULL) {
	p = sema->head;		/* remove first process from queue */
	sema->head = sema->head->next;
	if (sema->head == NULL) sema->tail = NULL;

	/*------------------------------------------------------------*/
	/* If the process specified a timeout on the 'down' operation */
	/* then we must remove it from the delta queue.               */
	/*------------------------------------------------------------*/
	if (p->state == SEM_TIMED_BLOCKED) _DeltaRemoveElement(p);

	/*--------------------------------------------------------------*/
	/* Awaken the process, but make the 'down' call return BADSEMA. */
	/*--------------------------------------------------------------*/
	p->badSema = TRUE;
	_addready(p);

	/*------------------------------------------------------------------*/
	/* Check for and handle preemption of the currently-running process */
	/*------------------------------------------------------------------*/
	if (p->priority > activeProcess->priority) _rs = 1;
    }
    if (_rs == 0) return NOERROR;

    /*--------------------------------------------------*/
    /* Put the current process back in the ready queue. */
    /*--------------------------------------------------*/
    activeProcess->state = PROCESS_READY;
    _addready(activeProcess);
    return NOERROR;
}

/**************************************************************************/
/**************************************************************************/
/********* System Call 18: Sleep for at least nticks clock ticks. *********/
/**************************************************************************/
/**************************************************************************/
int _sleep (unsigned int time)
{
    if (time > 0) {
	activeProcess->state = SLEEP_BLOCKED;
	DeltaEnqueue(activeProcess, time);
	_block();
    }
    return NOERROR;
}

/*******************************************************/
/*******************************************************/
/********* System Call 19: Yield the processor. ********/
/*******************************************************/
/*******************************************************/
int _yield(void *unused)
{
    _addready(activeProcess);
    _rs = 1;
    return NOERROR;
}

/**************************************************/
/**************************************************/
/********* System Call 20: Kill a process. ********/
/**************************************************/
/**************************************************/
int _kill(pid_t pid)
{
    unsigned int start;
    int i, awakenprio;
    Process p;		/* ptr to process table entry */
    Process prev, curr;	/* used in remove process from semaphore's queue */
    Semaphore s;	/* semaphore on which process is blocked, if any */

int status;


    /* if (activeProcess->pid == pid) exit(0); */
    p = pid2a(pid);
    if (p == NULL) return NOSUCHPROCESS;	/* bad pid */

    switch(p->state) {
	case PROCESS_READY:		/* not on delta or semaphore queue */
	    removep(p);
	    break;

	case PROCESS_CURRENT:		/* currently running process */
	    exit(0);			    /* --> simple case */

	case EVENT_TIMED_WAIT:
	    p->eventaddr = 0;

	case QUEUE_TIMED_BLOCKED:	/* only on the delta queue */
	case SLEEP_BLOCKED:		/* only on the delta queue */
	case PROCESS_TIMED_WAIT:	/* ... */
	    _DeltaRemoveElement(p);
	    break;

	case SEM_TIMED_BLOCKED:		/* on semaphore and delta queues */
	    _DeltaRemoveElement(p);
	    /* fall through to remove from semaphore queue */

	case PROCESS_BLOCKED:		/* on a semaphore's queue */
	    s = (Semaphore)p->queue;
	    prev = NULL;
	    curr = s->head;
	    while (curr != p) {
		prev = curr;
		curr = curr->next;
	    }
	    if (prev == NULL) s->head = curr->next;
	    else prev->next = curr->next;
	    break;

	case QUEUE_BLOCKED:		/* on no queues at all */
	    break;

	case PROCESS_WAIT:		/* ... */
	    break;

	case DISK_BLOCKED:		/* waiting for disk I/O */
	    /* This'll require more work. */
	    break;

	case EVENT_WAIT:
	    p->eventaddr = 0;
	    break;

	case WAKEUP_BLOCKED:
	    cancelwakeup(pid);		/* cancel the pending wakeup */
	    removep(p);			/* remove it from the ready queue */
dprintf("Returned from cancelwakeup with status %d\r\n",status);
	    break;

	default:
	    quit("kill() called for process in unkown state!");
    }

    /*------------------------------*/
    /* Reclaim unread message nodes */
    /*------------------------------*/
    for (i=0;i<NQUEUE;i++) {
	struct MsgNode *node;
	for (node = p->eventQueue[i].head; node != NULL; node = node->next) {
	    node->sender = NULL;
	}
    }

    /*--------------------------------------------------*/
    /* Reclaim pages occupied by user and kernel stacks */
    /*--------------------------------------------------*/
/* XXX We still need to handle "new-style" processes here */
    start = (((unsigned int)p->stkbase) >> 12) + 1 - p->stksize;
    freepages(start,p->stksize);
    start = ((unsigned int)p->kstkbase) >> 12;
    pgmap[start-1] = 0;

    /*------------------------------*/
    /* Free the process table entry */
    /*------------------------------*/
    p->state = PROCESS_FREE;

    /*-----------------------------------------------------------*/
    /* Awaken any processes waiting on this process to terminate */
    /*-----------------------------------------------------------*/
    awakenprio = -1;
    for (i=0;i<NPROC;i++) {
	if (proctab[i].state == PROCESS_WAIT &&
	    proctab[i].waitingon == p->pid) {
	    proctab[i].waitingon = 0;	/* is this necessary? Initialize it? */
	    proctab[i].exitstatus = PROCESS_KILLED;	/* really -1 */
	    _addready(&proctab[i]);
	    if (proctab[i].priority > awakenprio)
		awakenprio = proctab[i].priority;
	}
    }

    /*---------------------------*/
    /* Close any open disk files */
    /*---------------------------*/
	/* XXX TO BE ADDED */

    /*------------------*/
    /* In conclusion... */
    /*------------------*/
    numprocesses--;
    if (numprocesses == 1) quit(NULL);	/* only idle process left */

    if (activeProcess->priority < awakenprio) {
	_addready(activeProcess);
	_rs = 1;
    }

    return NOERROR;
}

/**********************************************************************/
/**********************************************************************/
/********* System Call 21: Read a character from the keyboard. ********/
/**********************************************************************/
/**********************************************************************/
int _rdc(int *args)
{
    int con;
    int timeout;
    int result;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    con = args[0];
    timeout = args[1];

    if (con < 0 || con >= NVPG) return BADVAL;
    if (down(_keysem+con,timeout) == TIMEOUT) return TIMEOUT;
    result = kbdata[con][frstkey[con]++];
    if (frstkey[con] == NKEYS) frstkey[con] = 0;
    return result;
}

/**********************************************************/
/**********************************************************/
/********* System Call 22: Unmask a process queue. ********/
/**********************************************************/
/**********************************************************/
int _unmaskq (int qn)
{
    int result;

    if (qn < 0 || qn >= NQUEUE) return NOSUCHQUEUE;
    result = activeProcess->eventQueue[qn].mask;
    activeProcess->eventQueue[qn].mask = UNMASKED;
    return result;
}

/********************************************************/
/********************************************************/
/********* System Call 23: Mask a process queue. ********/
/********************************************************/
/********************************************************/
int _maskq (int qn)
{
    int result;

    if (qn < 0 || qn >= NQUEUE) return NOSUCHQUEUE;
    result = activeProcess->eventQueue[qn].mask;
    activeProcess->eventQueue[qn].mask = MASKED;
    return result;
}

/*******************************************************************/
/*******************************************************************/
/********* System Call 24: Wait for a process to terminate. ********/
/*******************************************************************/
/*******************************************************************/
/* There is a design flag in this call. Its typical intended use   */
/* is in a shell, where the shell creates a process and then wants */
/* to wait for it to terminate. If the new process has a higher    */
/* priority than the shell it might run and terminate before the   */
/* shell has a change to execute the waitproc system call to wait  */
/* on its termination. UNIX does it right. Consider redesign!      */
/*******************************************************************/
int _waitproc(int *args)
{
    pid_t pid;
    int *exitstatus;
    struct Proc *p;
    int timeout;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    pid = (pid_t)args[0];
    exitstatus = (int *)args[1];
    timeout = (int)args[2];

    p = pid2a(pid);
    if (p == NULL) return NOSUCHPROCESS;	/* bad pid */
    if (timeout == 0) return TIMEOUT;		/* don't wait */
    activeProcess->waitingon = pid;
    if (timeout == INFINITE) activeProcess->state = PROCESS_WAIT;
    else {
	activeProcess->timedOut = FALSE;
	activeProcess->state = PROCESS_TIMED_WAIT;
	DeltaEnqueue(activeProcess, timeout);
    }

    _block();

    if (activeProcess->timedOut) return TIMEOUT;
    *exitstatus = activeProcess->exitstatus;
    return NOERROR;
}

/****************************************************************/
/****************************************************************/
/********* System Call 25: Wait for a signal on a queue. ********/
/****************************************************************/
/****************************************************************/
int _wait (int timeout)
{
    int i;
    int signaled;
    int status;
    int nm = 0;			/* # of masked queues */

    activeProcess->timedOut = FALSE;

    /*-----------------------------------------------------------*/
    /* Check each queue in increasing queue number order to find */
    /* (a) how many are masked, and (b) if an unmasked queue has */
    /* a waiting signal.                                         */
    /*-----------------------------------------------------------*/
    for (i = 0; i < NQUEUE; i++) {

	/*---------------------------------------*/
	/* If the queue is masked, just count it */
	/*---------------------------------------*/
	if (activeProcess->eventQueue[i].mask == MASKED) {
	    nm++;
	    continue;
	}

	/*---------------------------------------------------*/
	/* If the queue has a waiting signal, then return it */
	/*---------------------------------------------------*/
	if (activeProcess->eventQueue[i].count > 0) {
	    activeProcess->eventQueue[i].count--;
	    return i;
	}
    }

    /*-----------------------------------------------------*/
    /* If all queues are masked and timeout is INFINITE... */
    /*-----------------------------------------------------*/
    if (nm == NQUEUE && timeout < 0) return ALLQMASK;

    /*-----------------------------*/
    /* If no signal was pending... */
    /*-----------------------------*/
    if (timeout < 0) {                  		/* INFINITE timeout */
	activeProcess->state = QUEUE_BLOCKED;
	_block();
	signaled = activeProcess->signaledOn;
    } else if (timeout == 0) return TIMEOUT;		/* non-blocking call */
    else {   	                         		/* finite timeout */
	DeltaEnqueue(activeProcess, timeout);
	activeProcess->state = QUEUE_TIMED_BLOCKED;
	_block();
	if (activeProcess->timedOut) signaled = TIMEOUT;
	else signaled = activeProcess->signaledOn;
    }
    activeProcess->signaledOn = -1;
    return signaled;
}

/***************************************************************/
/***************************************************************/
/********* System Call 26: Deliver a signal to a queue. ********/
/***************************************************************/
/***************************************************************/
int _signal (int *args)
{
    pid_t pid;
    int qn;
    Process p;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    pid = (pid_t)args[0];
    qn = (int)args[1];

    p = pid2a(pid);
    if (p == NULL) return NOSUCHPROCESS;
    if (qn < 0 || qn >= NQUEUE) return NOSUCHQUEUE;

#ifdef VALIDATE
    if (p->tag != TAG_PROCESS) quit("signal: invalid process argument");
#endif

    if ((p->state == QUEUE_BLOCKED || p->state == QUEUE_TIMED_BLOCKED) &&
	(p->eventQueue[qn].mask == UNMASKED)) {

	if (p->state == QUEUE_TIMED_BLOCKED) _DeltaRemoveElement(p);
	p->signaledOn = qn;
	_addready(p);
	if (p->priority > activeProcess->priority) {
	    _addready(activeProcess);
	    _rs = 1;
	}
    } else p->eventQueue[qn].count++;
    return NOERROR;
}

/***************************************************************/
/***************************************************************/
/********* System Call 27: Send a message to a process. ********/
/***************************************************************/
/***************************************************************/
int _send (int *args)
{
    pid_t pid;
    int qn;
    void *msg;
    int ack_queue;

    int i;
    struct MsgNode *node;
    struct Proc *p;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    pid = (pid_t)args[0];
    qn = (int)args[1];
    msg = (void *)args[2];
    ack_queue = (int)args[3];

    p = pid2a(pid);
    if (p == NULL) return NOSUCHPROCESS;
    if (qn < 0 || qn >= NQUEUE) return NOSUCHQUEUE;

#ifdef VALIDATE
    if (p->tag != TAG_PROCESS) quit("send: invalid process argument");
#endif

    /*-------------------------------------------------*/
    /* Get a message node for this message and fill it */
    /*-------------------------------------------------*/
    for (i=0;i<NMSGS;i++) if (msgtab[i].sender == NULL) break;
    if (i == NMSGS) return NOMSGNODES;
    node = &msgtab[i];
    node->msg = msg;
    node->ack_queue = ack_queue;
    node->sender = activeProcess;	/* shouldn't this be sender's pid? */
    node->next = NULL;

    /*--------------------------------------------------------*/
    /* Add the node to the end of the appropriate event queue */
    /*--------------------------------------------------------*/
    if (p->eventQueue[qn].head == NULL) {
	p->eventQueue[qn].head = node;          /* queue was empty */
	p->eventQueue[qn].tail = node;
	node->prev = NULL;
    } else {
	p->eventQueue[qn].tail->next = node;    /* queue was non-empty */
	node->prev = p->eventQueue[qn].tail;
	p->eventQueue[qn].tail = node;
    }

    /*-----------------------------------------------------------------------*/
    /* If the receiving process was blocked waiting on a signal or a message */
    /* then make it ready to run, removing it from the sleep queue if it was */
    /* doing a receive or wait with a finite timeout period.  If the process */
    /* awakened has a higher priority than the sender, then reschedule.      */
    /*-----------------------------------------------------------------------*/
    if ((p->state == QUEUE_BLOCKED || p->state == QUEUE_TIMED_BLOCKED) &&
	(p->eventQueue[qn].mask == UNMASKED)) {

	if (p->state == QUEUE_TIMED_BLOCKED) _DeltaRemoveElement(p);

	_addready(p);
	if (p->priority > activeProcess->priority) {
	    _addready(activeProcess);
	    _rs = 1;
	}
    }
    return NOERROR;
}

/*****************************************************************/
/*****************************************************************/
/********* System Call 28: Receive a signal or a message. ********/
/*****************************************************************/
/*****************************************************************/

/*****************************************************************/
/* Wait for a signal or a message from any process.  If a signal */
/* is received, return the queue number (0..NQUEUE-1) on which   */
/* the signal was received, with the msg, sender, and            */
/* ack_queue pointers set to NULL.  If no signal is pending, a   */
/* check is made for a message. If a message was found, return   */
/* the queue number with the msg, sender, and ack_queue          */
/* pointers set appropriately.  Otherwise (if no signal or       */
/* message was found) block if an infinite or finite timeout was */
/* specified, or just return TIMEOUT.  After unblocking, return  */
/* appropriately.                                                */
/*****************************************************************/
int _receive (int *args)
{
    void **msg;
    pid_t *sender;
    int *ack_queue;
    int timeout;

    unsigned int eflags;
    int i;
    struct MsgNode *node;
    int signaled;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    msg = (void **)args[0];
    sender = (pid_t *)args[1];
    ack_queue = (int *)args[2];
    timeout = (int)args[3];

    if (msg == NULL) return NULLPARM;
    if (sender == NULL) return NULLPARM;
    if (ack_queue == NULL) return NULLPARM;

    activeProcess->timedOut = FALSE;

    /*-----------------------------------------------------------*/
    /* Check first for a signal, which is indicated by count > 0 */
    /*-----------------------------------------------------------*/
    for (i = 0; i < NQUEUE; i++) {
	if (activeProcess->eventQueue[i].mask == MASKED) continue;
	if (activeProcess->eventQueue[i].count == 0) continue;

	/*---------------------------------------------------*/
	/* A signal is available, so reduce the signal count */
	/* and return an indication of signal reception.     */
	/*---------------------------------------------------*/
	activeProcess->eventQueue[i].count--;

	*msg = NULL;
	*sender = -1;
	*ack_queue = NO_ACK;
	return i;
    }

search_again:

    /*--------------------------------------------------------------------*/
    /* No signals, so check for a message, indicated by a non-empty queue */
    /*--------------------------------------------------------------------*/
    for (i = 0; i < NQUEUE; i++) {
	if (activeProcess->eventQueue[i].mask == MASKED) continue;
	if (activeProcess->eventQueue[i].head == NULL) continue;

	/*----------------------------------------------*/
	/* Remove the message node from the event queue */
	/*----------------------------------------------*/
	node = activeProcess->eventQueue[i].head;
	activeProcess->eventQueue[i].head = node->next;
	if (node->next == NULL) activeProcess->eventQueue[i].tail = NULL;

	/*-------------------------------------------*/
	/* Extract and return the message components */
	/*-------------------------------------------*/
	*msg = node->msg;
	*sender = node->sender->pid;
	*ack_queue = node->ack_queue;
	node->sender = NULL;		/* make the node available */
	return i;
    }

    /*--------------------------------------------------------------*/
    /* No signal or message was available; determine how to proceed */
    /*--------------------------------------------------------------*/

    if (timeout < 0)
	activeProcess->state = QUEUE_BLOCKED;	/* INFINITE timeout */

    else if (timeout == 0) {         		/* nonblocking call */
	*msg = NULL;
	*sender = -1;
	*ack_queue = NO_ACK;
	return TIMEOUT;

    } else {  				        /* finite timeout */
	activeProcess->state = QUEUE_TIMED_BLOCKED;
	DeltaEnqueue(activeProcess, timeout);
    }

    _block();

    /*----------------------------------------------*/
    /* After timeout, signal, or message arrival,   */
    /* the process will continue execution here.    */
    /*----------------------------------------------*/
    if (activeProcess->timedOut) {              /* operation timed out */
	*msg = NULL;
	*sender = -1;
	*ack_queue = NO_ACK;
	return TIMEOUT;
    }

    if (activeProcess->signaledOn != -1) {      /* signal arrived */
	signaled = activeProcess->signaledOn;
	activeProcess->signaledOn = -1;
	*msg = NULL;
	*sender = -1;
	*ack_queue = -1;
	return signaled;
    }

    goto search_again;                          /* message arrived */
}

/**************************************************************/
/**************************************************************/
/********* System Call 29: Perform low-level disk I/O. ********/
/**************************************************************/
/**************************************************************/
int _diskio(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int rw;			/* read = 0, write = 1 */
    unsigned int blockno;	/* requested block number */
    char *buffer;		/* buffer address */
    int nblk;			/* number of blocks */

    if (!_diskpresent) return NODISK;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    rw = args[0];			/* non-zero means write */
    blockno = (unsigned int)args[1];	/* logical block number */
    buffer = (char *)args[2];		/* user's buffer address */
    nblk = args[3];			/* # of blocks to process */

    /*----------------------*/
    /* Validate the request */
    /*----------------------*/
    if (rw < 0 || rw > 1) return NOSUCHFUNC;
    if (buffer == NULL) return NULLPARM;
    if (blockno > maxblk) return NOSUCHBLOCK;
    if (nblk < 1) return BADVAL;	/* should there be a maximum? */

    /*------------------------------------------------------------*/
    /* We should verify that the address of the last byte in the  */
    /* user's buffer is legitimately in the user's address space. */
    /*------------------------------------------------------------*/

/***********************************************************************/
/* XXX - The next line must be changed. If there are no free disk I/O  */
/*       request structures, then the process making this request must */
/*       block until one becomes free.                                 */
/***********************************************************************/
    if (IOfree == NULL) return NOIOREQ;

    /*-----------------------------*/
    /* Prepare a request structure */
    /*-----------------------------*/
    request = IOfree;
    IOfree = IOfree->next;
    if (rw == 0) request->op = DSK_READ;
    else request->op = DSK_WRITE;
    spc = nheads * nsects;                      /* sectors per cylinder */
    request->xc = blockno / spc;                /* cylinder */
    request->xh = (blockno % spc) / nsects;     /* head */
    request->xs = blockno % nsects + 1;         /* sector */
    request->buffer = buffer;
    request->proc = activeProcess;
    request->next = NULL;

#ifdef NONO
    /*-----------------------------------------------------*/
    /* Add the request to the queue. We currently use FIFO */
    /* scheduling, but other choices could be implemented. */
    /*-----------------------------------------------------*/
    needstart = (IOhead == NULL);
    if (needstart) IOhead = IOtail = request;
    else {
	IOtail->next = request;
	IOtail = request;
    }

    /*-------------------------------------------------*/
    /* If no I/O is in progress (needstart == 1), then */
    /* "kick start" the disk to process the request.   */
    /*-------------------------------------------------*/
    if (needstart) startdiskcmd();
#endif

    /*-------------------------------------------------------------*/
    /* If no disk I/O is in progress (IOhead == NULL), then create */
    /* a queue with the current request and "kick start" the disk. */
    /* Otherwise just add the current request to the end of the    */
    /* queue, since we're using simplistic FIFO disk scheduling.   */
    /* In the future, better disk scheduling algorithms might be   */
    /* employed (perhaps as a class assignment?)...                */
    /*-------------------------------------------------------------*/
    if (IOhead == NULL) {
	IOhead = IOtail = request;
	startdiskcmd();
    } else {
	IOtail->next = request;
	IOtail = request;
    }

    activeProcess->state = DISK_BLOCKED;

    _block();		/* wait for the I/O to complete */

    return NOERROR;
}

/*********************************************************/
/*********************************************************/
/********* System Call 30: Get System Parameters. ********/
/*********************************************************/
/*********************************************************/
int _getsysparm(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int index;			/* starting parameter number */
    int n;			/* number of parameters */
    int *p;			/* result array location */
    int np, i;			/* used in calculations */
    struct IOreq *IOp;		/* used in counting IOreq blocks */
    int nsem;
    int nmsg;

    int rv = 0;			/* return value */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    index = args[0];
    n = args[1];
    p = (int *)args[2];

    if (n <= 0) return 0;		/* no parameters requested!? */
    if (p == NULL) return NULLPARM;	/* bad pointer */
    if (index > MAXINDEX) return BADVAL;/* no parameters with this index */
    if (index < 0) return BADVAL;	/* no parameters with index < 0 */

    while (n > 0 && index <= MAXINDEX) {
	switch(index) {
	    case SYSPARM_MAXINDEX:	/* number of parameters available */
		*p++ = MAXINDEX; break;
	    case SYSPARM_NPROC:		/* size of proctab */
		*p++ = NPROC; break;
	    case SYSPARM_NSEMA:		/* size of semaphore pool */
		*p++ = NSEMA; break;
	    case SYSPARM_NSECT:		/* # blocks on hard disk */
		*p++ = maxblk; break;
	    case SYSPARM_NVPG:		/* # of video pages available */
		*p++ = NVPG; break;
	    case SYSPARM_LPRIO:		/* lowest process priority */
		*p++ = LOWEST_PRIORITY; break;
	    case SYSPARM_HPRIO:		/* highest process priority */
		*p++ = HIGHEST_PRIORITY; break;
	    case SYSPARM_MSGPOOL:	/* size of message pool */
		*p++ = NMSGS; break;
	    case SYSPARM_NQUEUES:	/* message queues per process */
		*p++ = NQUEUE; break;
	    case SYSPARM_MAXFILES:	/* max open files per process */
		*p++ = NFD; break;
	    case SYSPARM_SYSMAXFILES:	/* max open files in the system */
		*p++ = NFDESC; break;
	    case SYSPARM_PGSINUSE:	/* # pages marked in 'pgmap' */
		np = 0;
		for (i=0;i<4096;i++) if (pgmap[i] != 0) np++;
		*p++ = np;
		break;
	    case SYSPARM_NIORQFREE:	/* # of disk I/O request blocks free */
		np = 0;
		for (IOp=IOfree;IOp!=NULL;IOp=IOp->next) np++;
		*p++ = np;
		break;
	    case SYSPARM_NIORQUSED:	/* # of disk I/O request blocks used */
		np = 0;
		for (IOp=IOhead;IOp!=NULL;IOp=IOp->next) np++;
		*p++ = np;
		break;
	    case SYSPARM_NUMNIC:	/* # of NICs in the system */
		*p++ = _numnic;
		break;
	    case SYSPARM_SEMSINUSE:
		nsem = 0;
		for (i=0;i<NSEMA;i++)
		    if (_semtab[i].count != -1) nsem++;
		*p++ = nsem;
		break;
	    case SYSPARM_MSGSINUSE:
		nmsg = 0;
		for (i=0;i<NMSGS;i++)
		    if (msgtab[i].sender != NULL) nmsg++;
		*p++ = nmsg;
		break;
	}
	n--;
	index++;
	rv++;
    }
    return rv;
}

/****************************************************/
/****************************************************/
/********* System Call 31: Open a disk file. ********/
/****************************************************/
/****************************************************/
int _open(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    char *path;
    int how;

    int i, fdesci, status;
    char lpath[MAXPATH+1];	/* absolute path with working dir prefix */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    path = (char *)args[0];
    how = args[1];

    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;
    if (how < 0 || how > 2) return BADHOW;

    /*---------------------------------------------------------------*/
    /* Verify space exists in proc's fd array for another descriptor */
    /*---------------------------------------------------------------*/
    for (i=0;i<NFD;i++) if (activeProcess->fd[i].fdescnr == -1) break;
    if (i == NFD) return PROCFILELIMIT;

    if ((status = abspath(path,lpath)) < 0) return status;
    fdesci = dget(lpath);
    if (fdesci < 0) return fdesci;

    /*-----------------------------------------------------------*/
    /* Verify user not trying to write or read/write a directory */
    /*-----------------------------------------------------------*/
    if ((fdesc[fdesci].de.dflag & DE_ISDIR) && how != 0) {
	 freedref(fdesci);		/* reduce reference count */
	 return BADHOW;
    }

    /*-----------------------------------*/
    /* Setup the process' fd array entry */
    /*-----------------------------------*/
    activeProcess->fd[i].how = how;
    activeProcess->fd[i].fdescnr = fdesci;
    activeProcess->fd[i].offset = 0L;

    return i;
}

/**************************************************************/
/**************************************************************/
/********* System Call 32: Create a regular disk file. ********/
/**************************************************************/
/**************************************************************/
int _creat(char *path)
{
    int i;
    int fdesci;
    int status;
    struct dirent *de;
    char lpath[MAXPATH+1];	/* absolute path with working dir prefix */

    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;

    /*---------------------------------------------------------------*/
    /* Verify space exists in proc's fd array for another descriptor */
    /*---------------------------------------------------------------*/
    for (i=0;i<NFD;i++) if (activeProcess->fd[i].fdescnr == -1) break;
    if (i == NFD) return PROCFILELIMIT;

    /*---------------------------------------------------------*/
    /* Prefix current working directory to path if appropriate */
    /*---------------------------------------------------------*/
    if ((status = abspath(path,lpath)) < 0) return status;

    /*--------------------------------*/
    /* See if the file already exists */
    /*--------------------------------*/
    fdesci = dget(lpath);
    if (fdesci >= 0) {
	if (fdesc[fdesci].de.dflag & DE_ISDIR) {
	     freedref(fdesci);		/* reduce reference count */
	     return BADHOW;
	}

	dtrunc(fdesci);			/* truncate the file */

	/*-----------------------------------*/
	/* Setup the process' fd array entry */
	/*-----------------------------------*/
	activeProcess->fd[i].how = 1;
	activeProcess->fd[i].fdescnr = fdesci;
	activeProcess->fd[i].offset = 0L;

	return i;

    /*-----------------------------------*/
    /* If the file did not already exist */
    /*-----------------------------------*/
    } else if (fdesci == NOSUCHFILE) {
	int status, args[2];
	struct bufhd *b;
	int off;

	status = makede(lpath,&b,&off);
	if (status < 0) return status;
	de = (struct dirent *)(b->data+off);
	de->dflag = 0x01;			/* regular file */
	brelse(b);
	args[0] = (int)lpath;
	args[1] = 1;
	return _open(args);
    } else return fdesci;			/* error */
}

/******************************************************/
/******************************************************/
/********* System Call 33: Create a directory. ********/
/******************************************************/
/******************************************************/
int _mkdir(char *path)
{
    int fdesci;
    int status;
    struct bufhd *b;
    int off;
    struct dirent *de;
    char lpath[MAXPATH+1];	/* absolute path with working dir prefix */

    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;

    /*---------------------------------------------------------*/
    /* Prefix current working directory to path if appropriate */
    /*---------------------------------------------------------*/
    if ((status = abspath(path,lpath)) < 0) return status;

    /*---------------------------------------------*/
    /* See if a file with this name already exists */
    /*---------------------------------------------*/
    fdesci = dget(lpath);
    if (fdesci < 0 && fdesci != NOSUCHFILE) return fdesci;	/* error */
    if (fdesci >= 0) {
	fdesc[fdesci].nrefs--;
	return FILEEXISTS;
    }

    /*----------------------------*/
    /* Create the empty directory */
    /*----------------------------*/
    status = makede(lpath,&b,&off);
    if (status < 0) return status;
    de = (struct dirent *)(b->data+off);
    de->dflag = DE_ISDIR;
    brelse(b);
    return NOERROR;
}

/***************************************************************/
/***************************************************************/
/********* System Call 34: Read a console or disk file. ********/
/***************************************************************/
/***************************************************************/
struct rdl_t {
    char rdlbuf[MAXRDL];	/* internal line buffer */
    int rdllen;			/* length of line */
    int rdlleft;		/* unread characters */
    int rdlndx;			/* first unread character */
    int rdldw;			/* display width of line */
    int rdlnt;			/* # of tabs in rdlbuf */
    int rdltw[10];		/* width of each tab char */
} rdl[NVPG];

/*----------------------------------------*/
/* Erase the last input console character */
/*----------------------------------------*/
void rdlerase(int con)
{
    if (con < 0 || con >= NVPG) return;
    if (rdl[con].rdllen == 0) return;		/* nothing to erase */
    rdl[con].rdllen--;
    if (rdl[con].rdlbuf[rdl[con].rdllen] == TAB) {
	rdl[con].rdlnt--;
	while (rdl[con].rdltw[rdl[con].rdlnt] > 0) {
	    vcout(con,CTLH); vcout(con,' '); vcout(con,CTLH);
	    rdl[con].rdltw[rdl[con].rdlnt]--;
	    rdl[con].rdldw--;
	}
    } else {
	vcout(con,CTLH); vcout(con,' '); vcout(con,CTLH);
	rdl[con].rdldw--;
    }
}

int _read(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int fd;
    char *buffp;
    size_t len;

    unsigned long offset;	/* file position */
    unsigned int fsize;		/* file size */
    int fdesci;			/* index to fdesc */
    int nread;			/* # of bytes xfer'd to user buff */
    int status;
    int i;
    unsigned int fsbn;		/* block number */
    unsigned int bbo;		/* offset to block */
    unsigned int bib;		/* bytes in block at and beyond bbo */
    struct bufhd *b;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    fd = args[0];
    buffp = (char *)args[1];
    len = args[2];

    /*------------------------------------------------*/
    /* Verify the parameters and handle special cases */
    /*------------------------------------------------*/
    if (len == 0) return 0;	/* nothing to be read */
    if (buffp == NULL) return NULLPARM;		/* bad buffer parameter */
    /* We should also verify the buffer is entirely in the user's addr space */
    if (fd < 0 || fd >= NFD) return BADFD;	/* bad file descriptor */
    if (activeProcess->fd[fd].fdescnr == -1) return BADFD;  /* ditto */

    /*---------------*/
    /* Console input */
    /*---------------*/
    if (activeProcess->fd[fd].how < 0) {
	int mode;	/* 0=raw, 1=cooked */
	int con;	/* which console */

	mode = activeProcess->fd[fd].fdescnr;
	con = -activeProcess->fd[fd].how - 1;

	if (mode == 0) {			/* raw mode input */
	    for (i=0;i<len;i++) buffp[i] = rdc(con,INFINITE);
	    return len;

	} else {				/* cooked mode input */
	    while (rdl[con].rdlleft == 0) {	/* if no edited input avail */
		int c;
		unsigned char ac;

		c = rdc(con,INFINITE);	/* block awaiting console input */
		ac = c & 0x7f;		/* get ASCII code, if any */
/* We could treat the left arrow as a backspace key here */
		if (ac != c) {
		    bell();		/* non-ASCII input alert */
		    continue;
		}
		if (ac == CTLH || ac == DEL) {	/* delete or backspace? */
		    rdlerase(con);
		    continue;
		}
		if (ac == CTLU) {		/* line delete? */
		    while (rdl[con].rdllen > 0) rdlerase(con);
		    continue;
		}
		if (ac == TAB) {
		    if (rdl[con].rdldw > 73) {	/* tab beyond console margin */
			bell();
			continue;
		    }
		    rdl[con].rdlbuf[rdl[con].rdllen++] = TAB;
		    rdl[con].rdltw[rdl[con].rdlnt] = 0;
		    do {
			conout(con,' ');
			rdl[con].rdldw++;
			rdl[con].rdltw[rdl[con].rdlnt]++;
		    } while ((rdl[con].rdldw & 7) != 0);
		    rdl[con].rdlnt++;
		    continue;
		}
		if (ac == CTLM) {	/* end of line? (consider ^J as well) */
		    conout(con,CTLJ);
		    conout(con,CTLM);
		    rdl[con].rdlbuf[rdl[con].rdllen++] = CTLJ;	/* '\n' */
		    rdl[con].rdlleft = rdl[con].rdllen;
		    break;
		}
		if (ac >= ' ' && ac <= '~') {		/* printable char */
		    if (rdl[con].rdllen == MAXRDL-1) {
			bell();
			continue;
		    }
		    rdl[con].rdlbuf[rdl[con].rdllen++] = ac;
		    conout(con,ac);
		    rdl[con].rdldw++;
		    continue;
		}
/*--------------------------------------------------------------------------*/
/* The character used to represent an end of file can be handled in several */
/* ways. In most cases, the end of file character can mark the end of line, */
/* but whether it also causes an end of file (returned value of 0) on the   */
/* NEXT read, or not, depends on the OS. Linux ignores an end of file       */
/* character unless it is the first character in a line. We'll use that     */
/* interpretation here. Beware, however, that this can differ from system   */
/* to system. So much for standardization!                                  */
/*--------------------------------------------------------------------------*/
		if (ac == EOFCH) {
		    conout(con,CTLM);			/* line feed only! */
		    if (rdl[con].rdllen == 0) rdl[con].rdlleft = 0; /* eof */
		    else rdl[con].rdlleft = rdl[con].rdllen;
		    break;
		}
		/* Everything else is ignored as bad input */
	    }

	    if (len > rdl[con].rdlleft) len = rdl[con].rdlleft;
	    for (i=0;i<len;i++) buffp[i] = rdl[con].rdlbuf[rdl[con].rdlndx+i];
	    rdl[con].rdlleft -= len;
	    rdl[con].rdlndx += len;
	    if (rdl[con].rdlleft == 0) {	/* if this line is all used */
		rdl[con].rdllen = 0;
		rdl[con].rdlndx = 0;
		rdl[con].rdldw = 0;
		rdl[con].rdlnt = 0;
	    }
	    return len;
	}
    }

    /*-----------------*/
    /* disk file input */
    /*-----------------*/
    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;
    offset = activeProcess->fd[fd].offset;
    fdesci = activeProcess->fd[fd].fdescnr;
    if (fdesci < 0) return BADFD;		/* file not open */
    if (activeProcess->fd[fd].how != 0 && activeProcess->fd[fd].how != 2)
	return BADFD;				/* not open for reading */
#ifdef VALIDATE
    if (fdesci >= NFDESC) quit("Bad fdesc index in _read");
#endif
    /* lock fdesc entry */
    fsize = fdesc[fdesci].de.fsize;
    if (offset > fsize) return BADPOS;  /* shouldn't happen */
    if (len > fsize - offset) len = fsize - offset;
    nread = 0;

    while (nread < len) {
	status = bmap(&fdesc[fdesci].de,offset,&fsbn,&bbo);
	if (status < 0) {
	    /* unlock fdesc entry */
	    return status;
	}
	bib = 512 - bbo;
	if (bib > len - nread) bib = len - nread;
	b = bread(fsbn);
	memcpy((void *)buffp+nread,(void *)b->data+bbo,bib);
	nread += bib;
	offset += bib;
	brelse(b);
    }
    /* unlock fdesc entry */
    activeProcess->fd[fd].offset = offset;
    return nread;
}

/**************************/
/* Debugging dump utility */
/**************************/
void fsdump (unsigned char *p, int len)
{
    int i, c;
    unsigned int offset;

    offset = 0;
    while (offset < len) {
	kprintf("%04x  ", offset);
	for (i=0;i<16;i++) printf("%02x ",p[offset+i]);
	kprintf(" ");
	for (i=0;i<16;i++) {
	    c = p[offset+i];
	    if (c < ' ' || c > '~') conout(0,'.');
	    else conout(0,c);
	}
	kprintf("\r\n");
	offset += 16;
    }
}

/************************************************************************/
/************************************************************************/
/********* System Call 35: Write a console or regular disk file. ********/
/************************************************************************/
/************************************************************************/
int _write(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int fd;
    char *buffp;
    size_t len;

    unsigned long offset;	/* file position */
    unsigned int fsize;		/* file size */
    int fdesci;			/* index to fdesc */
    int nwritten;		/* # of bytes xfer'd from user buff */
    int status;			/* value from bmap */
    unsigned int fsbn;		/* next block number where writing may occur */
    unsigned int bbo;		/* offset to block */
    unsigned int bib;		/* bytes in block at and beyond bbo */
    struct bufhd *b;		/* ptr to buf hdr from bread, getblk, allocnb */
    int i;
    unsigned int n;
    unsigned int charno;
    char ch;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    fd = args[0];
    buffp = (char *)args[1];
    len = args[2];

    if (len == 0) return 0;
    if (buffp == NULL) return NULLPARM;
    if (fd < 0 || fd >= NFD) return BADFD;

    if (activeProcess->fd[fd].fdescnr == -1) return BADFD;

    /*----------------*/
    /* console output */
    /*----------------*/
    if (activeProcess->fd[fd].how < 0) {
	int mode;	/* console mode */
	int con;	/* which console */

	mode = activeProcess->fd[fd].fdescnr;
	con = -activeProcess->fd[fd].how - 1;

	for (i=0;i<len;i++) {
	    ch = buffp[i];
	    if (mode == 1 /* cooked */ && ch == '\n') conout(con,'\r');
	    conout(con,ch);
	}
	return len;
    }
    
    /*------------------*/
    /* disk file output */
    /*------------------*/
    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;
    offset = activeProcess->fd[fd].offset;
    fdesci = activeProcess->fd[fd].fdescnr;
    if (fdesci < 0) return BADFD;		/* file not open */
    if (activeProcess->fd[fd].how != 1 && activeProcess->fd[fd].how != 2)
	return BADFD;				/* not open for writing */
#ifdef VALIDATE
    if (fdesci >= NFDESC) quit("Bad fdesc index in _write");
#endif
    /* lock fdesc entry? */
    fsize = fdesc[fdesci].de.fsize;
#ifdef VALIDATE
    if (offset > fsize) return BADPOS;  /* shouldn't happen */
#endif

    /*-----------------------------------------------------*/
    /* Reduce len if it would exceed the maximum file size */
    /* This is evident to the caller as a returned value   */
    /* that is less than the 'len' argument.               */
    /*-----------------------------------------------------*/
    if (len > MAXFSIZE - offset) len = MAXFSIZE - offset;
    nwritten = 0;
    if (len == 0) return 0;

    /*-------------------------------------------------*/
    /* Find block and offset where write will commence */
    /*-------------------------------------------------*/
    status = bmap(&fdesc[fdesci].de,offset,&fsbn,&bbo);
    if (status < 0) {
	/* unlock fdesc entry */
	return status;
    }
    if (fsbn == 0) goto New;

    /*---------------------------------------------------------------*/
    /* Fill all or part of the space at the end of an existing block */
    /*---------------------------------------------------------------*/
    bib = 512 - bbo;		/* bytes left in block */
    b = bread(fsbn);
    n = len;
    if (n > bib) n = bib;	/* n = min(len,bib) */
    memcpy((void *)b->data+bbo,(void *)buffp,n);
    nwritten += n;
    len -= n;
    b->status |= BCS_DIRTY;
    brelse(b);
    if (len == 0) goto Exit;

    /*----------------------------------------------*/
    /* Write full blocks to existing blocks, if any */
    /*----------------------------------------------*/
    while (len > 512) {
	status = bmap(&fdesc[fdesci].de,offset+nwritten,&fsbn,&bbo);
	if (status < 0) return status;		/* XXX? */
	if (fsbn == 0) goto New;
	b = bread(fsbn);
	memcpy((void *)b->data,(void *)buffp+nwritten,512);
	len -= 512;
	nwritten += 512;
	b->status |= BCS_DIRTY;
	brelse(b);
    }
    if (len == 0) goto Exit;

    /*-----------------------------------------------*/
    /* Write remaining data (less than 512 bytes) to */
    /* a possibly existing block.                    */
    /*-----------------------------------------------*/
    status = bmap(&fdesc[fdesci].de,offset+nwritten,&fsbn,&bbo);
    if (status < 0) return status;		/* XXX? */
    if (fsbn == 0) goto New;
    b = bread(fsbn);
    memcpy((void *)b->data,(void *)buffp+nwritten,len);
    nwritten += len;
    len = 0;
    b->status |= BCS_DIRTY;
    brelse(b);

    /*------------------------------------------------*/
    /* Write remaining data to newly-allocated blocks */
    /*------------------------------------------------*/
    New:
    while (len > 0) {
	b = allocnb(fdesci);
	n = 512;
	if (n > len) n = len;		/* n = min(len,512) */
	memcpy((void *)b->data,(void *)buffp+nwritten,n);
	nwritten += n;
	len -= n;
	b->status |= BCS_DIRTY;
	brelse(b);
    }

    Exit:
    offset += nwritten;
    activeProcess->fd[fd].offset = offset;

    /*-----------------------------------------------------------------*/
    /* If the file increased in size, mark the change in the directory */
    /* entry and propogate it to the correct block.                    */
    /*-----------------------------------------------------------------*/
    if (offset > fsize) {
	fdesc[fdesci].de.fsize = offset;
	fdesc[fdesci].flags |= FDE_DIRTY;
	upddir(fdesc[fdesci].blockno, fdesc[fdesci].offset, &fdesc[fdesci].de);
    }
    /* unlock fdesc entry */
    return nwritten;
}

/********************************************************/
/********************************************************/
/********* System Call 36: Position a disk file. ********/
/********************************************************/
/********************************************************/
int _seek(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int fd;
    int xoffset;
    unsigned int start;

    int fdesci;			/* index to fdesc */
    int newpos;			/* new file position */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    fd = args[0];
    xoffset = args[1];
    start = (unsigned int)args[2];

    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;
    if (fd < 0 || fd >= NFD) return BADFD;
    if (start < 0 || start > 2) return BADPOS;
    fdesci = activeProcess->fd[fd].fdescnr;
    if (fdesci < 0) return BADFD;		/* file not open */
#ifdef VALIDATE
    if (fdesci >= NFDESC) quit("Bad fdesc index in _read");
#endif
    /* lock fdesc entry */
    switch(start) {
	case 0: newpos = 0; break;
	case 1: newpos = activeProcess->fd[fd].offset; break;
	case 2: newpos = fdesc[fdesci].de.fsize; break;
	default:
	    /* unlock fdesc entry */
	    return BADPOS;
    }
    newpos += xoffset;
    if (newpos < 0 || newpos > fdesc[fdesci].de.fsize) {
	/* unlock fdesc entry */
	return BADPOS;
    }
    activeProcess->fd[fd].offset = newpos;
    return newpos;
}

/******************************************************/
/******************************************************/
/********* System Call 37: Close an open file. ********/
/******************************************************/
/******************************************************/
int _close(int fd)
{
    int fdesci;
    struct dirent *de;
    struct bufhd *b;

    if (fd < 0 || fd >= NFD) return BADFD;
    if (activeProcess->fd[fd].fdescnr == -1) return BADFD;

    /*-----------------*/
    /* Close a console */
    /*-----------------*/
    if (activeProcess->fd[fd].how < 0) {	/* was == -1 */
	activeProcess->fd[fd].fdescnr = -1;
	return NOERROR;
    }

    /*--------------------*/
    /* ... or a disk file */
    /*--------------------*/
    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;
    fdesci = activeProcess->fd[fd].fdescnr;
    if (fdesci < 0) return BADFD;		/* file not open */
#ifdef VALIDATE
    if (fdesci >= NFDESC) quit("Bad fdesc index in _close");
    if (fdesc[fdesci].nrefs <= 0) quit("close: bad nrefs in fdesc entry");
#endif

    /*---------------------------------------------------------*/
    /* Reduce the reference count. If not zero, return NOERROR */
    /* after marking the process' fd entry available.          */
    /*---------------------------------------------------------*/
    /* XXX Q. Do we need to lock the fdesc entry? */
#define PREVCLOSE
#ifdef PREVCLOSE
    fdesc[fdesci].nrefs--;
    activeProcess->fd[fd].fdescnr = -1;
    if (fdesc[fdesci].nrefs > 0) return NOERROR;

    /*-----------------------------------*/
    /* If a remove is pending, do it now */
    /*-----------------------------------*/
    if (fdesc[fdesci].flags & FDE_RMPEND) {
	/*------------------------------------------------*/
	/* Perhaps  make this a separate function in fs.c */
	/*------------------------------------------------*/
	dtrunc(fdesci);			/* reclaim all data/indirect blocks */
	b = bread(fdesc[fdesci].blockno);
	de = (struct dirent *)(b->data+fdesc[fdesci].offset);
	de->dflag = 0x00;			/* mark directory entry free */
	b->status |= (BCS_HASDATA | BCS_DIRTY);
	brelse(b);
	fdesc[fdesci].nrefs = 0;
	return NOERROR;
    }
#else
    freedref(fdesci);
#endif

    /*-------------------------------------------------------*/
    /* If the entry is dirty, write it back to the directory */
    /*-------------------------------------------------------*/
    if (fdesc[fdesci].flags & FDE_DIRTY) {
	b = bread(fdesc[fdesci].blockno);
	memcpy((void *)b->data+fdesc[fdesci].offset,
               (void *)&fdesc[fdesci].de,
               sizeof(struct dirent));
	b->status |= BCS_DIRTY;
	brelse(b);
    }
    return NOERROR;
}

/******************************************************/
/******************************************************/
/********* System Call 38: Remove a disk file. ********/
/******************************************************/
/******************************************************/
int _remove(char *path)
{
    struct dirent *de;
    struct bufhd *b;
    int fdesci;
    int status;
    char lpath[MAXPATH+1];	/* absolute path with working dir prefix */

    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;

    if ((status = abspath(path,lpath)) < 0) return status;
    fdesci = dget(lpath);
    if (fdesci < 0) return fdesci;		/* error */

    if (fdesc[fdesci].nrefs > 1) {		/* if it's open */
	fdesc[fdesci].flags |= FDE_RMPEND;	/* mark for removal on close */
	fdesc[fdesci].nrefs--;			/* remove our reference */
	return NOERROR;				/* and return */
    }

    /*--------------------------------------------------*/
    /* Verify it's a regular file or an empty directory */
    /*--------------------------------------------------*/
    if (fdesc[fdesci].de.dflag & DE_ISDIR) {
	if (_dcount(&fdesc[fdesci].de) > 0) {
	    fdesc[fdesci].nrefs = 0;
	    return DIRNOTEMPTY;
	}
    }

    dtrunc(fdesci);			/* reclaim all data/indirect blocks */
    b = bread(fdesc[fdesci].blockno);
    de = (struct dirent *)(b->data+fdesc[fdesci].offset);
    de->dflag = 0x00;			/* mark directory entry free */
    b->status |= (BCS_HASDATA | BCS_DIRTY);
    brelse(b);
    fdesc[fdesci].nrefs = 0;
    return NOERROR;
}

/**********************************************************/
/**********************************************************/
/********* System Call 39: Get metainfo from path. ********/
/**********************************************************/
/**********************************************************/
int _stat(int *args)
{
    char *path;
    char lpath[MAXPATH+1];	/* absolute path with working dir prefix */
    int fdesci;
    struct stat *sb;
    int status;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    path = (char *)args[0];
    sb = (struct stat *)args[1];
    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;

    if ((status = abspath(path,lpath)) < 0) return status;
    fdesci = dget(lpath);
    if (fdesci < 0) return fdesci;
    sb->st_size = fdesc[fdesci].de.fsize;
    sb->st_type = fdesc[fdesci].de.dflag & 0x03;
    fdesc[fdesci].nrefs--;	/* can't possibly need a rewrite */
    return NOERROR;
}

/****************************************************************/
/****************************************************************/
/********* System Call 40: Get metainfo from descriptor. ********/
/****************************************************************/
/****************************************************************/
int _fstat(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int fd;
    struct stat *sb;

    int fdesci;			/* index to fdesc */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    fd = args[0];
    sb = (struct stat *)args[1];

    if (fd < 0 || fd >= NFD) return BADFD;
    if (activeProcess->fd[fd].how < 0) {	/* it's a console */
	sb->st_size = 0;
	sb->st_type = DE_ISTTY;
	sb->st_cnum = -activeProcess->fd[fd].how - 1;
	return NOERROR;
    }
    if (!_diskpresent) return NODISK;
    if (!_fspresent) return NOFILESYSTEM;
    fdesci = activeProcess->fd[fd].fdescnr;
    if (fdesci < 0) return BADFD;		/* file not open */
#ifdef VALIDATE
    if (fdesci >= NFDESC) quit("Bad fdesc index in _read");
#endif
    sb->st_size = fdesc[fdesci].de.fsize;
    sb->st_type = fdesc[fdesci].de.dflag & 0x03;
    return NOERROR;
}

/********************************************************************/
/********************************************************************/
/********* System Call 41: Open a console for input/output. *********/
/********************************************************************/
/********************************************************************/
int _opencon(int cnum)
{
    int i;

    /*---------------------------------------------------------------*/
    /* Verify space exists in proc's fd array for another descriptor */
    /*---------------------------------------------------------------*/
    if (cnum < 0 || cnum >= NVPG) return NOSUCHCON;
    for (i=0;i<NFD;i++) if (activeProcess->fd[i].fdescnr == -1) break;
    if (i == NFD) return PROCFILELIMIT;
    activeProcess->fd[i].how = -1-cnum;	/* mark as open for console I/O */
    activeProcess->fd[i].fdescnr = 1;	/* using "cooked" mode */
    return i;
}

/*********************************************************************/
/*********************************************************************/
/********* System Call 42: Set a console's mode (raw/cooked) *********/
/*********************************************************************/
/*********************************************************************/
int _setconmode(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int fd;
    int mode;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    fd = args[0];
    mode = args[1];

    if (fd < 0 || fd >= NFD) return BADFD;
    if (activeProcess->fd[fd].fdescnr == -1) return BADFD;
    if (activeProcess->fd[fd].how >= 0) return BADFD;	/* not a console */
    if (mode < 0 || mode > 1) return BADMODE;
    activeProcess->fd[fd].fdescnr = mode;
    return NOERROR;
}

/************************************************************************/
/************************************************************************/
/********* System Call 43: Get/set mfree field of proctab entry *********/
/************************************************************************/
/************************************************************************/
int _mptracc(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int how;
    struct m_header **a;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    how = args[0];
    a = (struct m_header **)args[1];

    if (how == 0) *a = activeProcess->mfree;
    else activeProcess->mfree = *a;
    return NOERROR;
}

/*******************************************************/
/*******************************************************/
/********* System Call 44: Rename a disk file. *********/
/*******************************************************/
/*******************************************************/
/* XXX - Modify to handle relative paths correctly. */
int _rename(int *args)
{
    int i, fdesci;
    struct bufhd *b;

    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    char *old;
    char *new;

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    old = (char *)args[0];
    new = (char *)args[1];

    if (old[0] == '\0' || new[0] == '\0') return BADPATHNAME;


    fdesci = dget(old);			/* get locked dirent */
    if (fdesci < 0) return fdesci;	/* error */
    for (i=0;i<FS1NAMELEN;i++) {
	fdesc[fdesci].de.fname[i] = new[i];
	if (new[i] == '\0') break;
    }
    for(;i<FS1NAMELEN;i++) fdesc[fdesci].de.fname[i] = '\0';
    fdesc[fdesci].flags |= FDE_DIRTY;	/* mark entry dirty */
    fdesc[fdesci].nrefs--;		/* reduce number of refs */
    fdesc[fdesci].flags &= ~FDE_LOCKED;	/* unlock the entry */

    if (fdesc[fdesci].nrefs == 0) {	/* if no remaining references */
	b = bread(fdesc[fdesci].blockno);
	memcpy((void *)b->data+fdesc[fdesci].offset,
               (void *)&fdesc[fdesci].de,
               sizeof(struct dirent));
	b->status |= BCS_DIRTY;
	brelse(b);
    }
    return NOERROR;
}

/***********************************************************/
/***********************************************************/
/********* System Call 45: Write to a serial port. *********/
/***********************************************************/
/***********************************************************/
int _comput(int *args)
{
    /* This version only writes to com1, without interrupts */
    
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int port;			/* port (1,2,...) */
    char c;			/* character to write */

    int uart_base = 0x3f8;	/* base address of COM1 */

    port = args[0];
    c = (char)args[1];

    /* Wait for ability to send */
    while ( (inb(uart_base+5) & 0x20) == 0) ;
    outb(uart_base,(int)c);
    return NOERROR;
}

/***************************************************************/
/***************************************************************/
/********* System Call 46: Read from to a serial port. *********/
/***************************************************************/
/***************************************************************/
int _comget(int *args)
{
    
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int port;			/* port (1,2,...) */
    int timeout;

    int uart_base = 0x3f8;	/* base address of COM1 */
    unsigned int count;		/* primitive timeout counter */
    int rv = 0;			/* returned value */
    unsigned int status;

    port = args[0];
    timeout = args[1];

    /* This version has a fixed timeout */
    for (count=0xffffff;count!=0;count--) {
	status = inb(uart_base+5);		/* line control register */
	if ((status & 0x9f) == 0) continue;	/* no errors, no data */
	if (status & 0x01) rv = inb(uart_base);	/* got data? */
	rv |= (status << 8);			/* return status, too! */
	return rv;
    }
    return TIMEOUT;
}

/***********************************************************************/
/***********************************************************************/
/********* System Call 47: Create a new process to run a file. *********/
/***********************************************************************/
/***********************************************************************/
int _run (void *args[])
{
    /*------------------------*/
    /* system call parameters */
    /*------------------------*/
    char *path;			/* null-terminated path of executable */
    struct runinf *ri;		/* ptr to runinfo structure */
    unsigned int priority;	/* priority (from runinf) */
    unsigned int flags;		/* flags (from runinf) */
    int pfd[3];			/* parent's fd numbers (from runinf) */
    char *environ;		/* environment pointer (fron runinf) */
    char *workdir;		/* working directory (from runinf) */
    int nargs;			/* number of parameters */
    unsigned char **a;		/* ptr to array of arguments */

    /*-----------------*/
    /* Other variables */
    /*-----------------*/
    struct Proc *p;		/* proctab entry to be used for this process */
    int i, n, k;
    int fd;
    unsigned int eflags;	/* eflags register on entry */
    unsigned int *stackPointer;	/* init. stack ptr for process */
    unsigned int *ksp;		/* kernel stack pointer */
    int targlen, tptrlen;	/* total argument, argument ptr length */

    unsigned char *parg;	/* phys addr of string arguments */
    unsigned char *varg;	/* virt addr of string arguments */

    unsigned char **pptr;	/* phys addr of ptr array to string args */
    unsigned char **vptr;	/* virt addr of ptr array to string args */

    unsigned char *dptr;
    unsigned int *iptr;
    unsigned int uvmsp;		/* user's VM stack pointer */
    unsigned int *codeorg;
    unsigned int *dataorg;
    unsigned int ptndx;		/* index to proctab array for new process */
    unsigned int *pte;		/* ptr to page table entry */
    unsigned int seglen[3];	/* seg len: stack, code, data */

    /*-----------------------------------*/
    /* Find an unused process table slot */
    /*-----------------------------------*/
    for (i=0;i<NPROC;i++) {
	if (proctab[i].state == PROCESS_FREE) break;
    }
    if (i == NPROC) return PROCTBLFULL;
    ptndx = i;
    p = &proctab[i];		/* save address of free proctab entry */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    path = (char *)args[0];
    ri = (struct runinf *)args[1];
    nargs = (unsigned int)args[2];
    a = (unsigned char **)args[3];

    /*-----------------------------------------------------------------*/
    /* Expand the runinf struct components, or copy caller's proc info */
    /*-----------------------------------------------------------------*/
    if (ri != NULL) {
	priority = ri->prio;
	if (ri->flags & RI_STDIN) pfd[0] = ri->fd[0]; else ri->fd[0] = -1;
	if (ri->flags & RI_STDOUT) pfd[1] = ri->fd[1]; else ri->fd[1] = -1;
	if (ri->flags & RI_STDERR) pfd[2] = ri->fd[2]; else ri->fd[2] = -1;
	for (i=0;i<3;i++)
	    if (pfd[i] < -1 || pfd[i] >= NFD) return BADFD;
	environ = ri->environ;
	workdir = ri->workdir;
    } else {
	priority = activeProcess->priority;
	pfd[0] = 0;
	pfd[1] = 1;
	pfd[2] = 2;
	environ = activeProcess->environ;
	workdir = activeProcess->workdir;
    }

    /*------------------------------------------------*/
    /* Verify the new process priority is acceptable. */
    /*------------------------------------------------*/
    if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY)
	return BADPRIO;

    p->tag = TAG_PROCESS;
    p->priority = priority;
    p->pid = nextpid++;

    /*----------------------------------------------------------*/
    /* Allocate a page of physical memory for a user page table */
    /* Clear all the entries in the page.                       */
    /*----------------------------------------------------------*/
    p->ptaddr = allocpage(ptndx,1);
    if (p->ptaddr == NULL) {
	nextpid--;
	return NOMEM;		/* no space */
    }

    /*--------------------------*/
    /* Open the executable file */
    /*--------------------------*/
    fd = open(path,0);		/* open the executable file */
    if (fd < 0) {
	freepage(p->ptaddr);	/* free page table page */
	nextpid--;
	return fd;
    }

    /*--------------------------*/
    /* Load the executable file */
    /*--------------------------*/
    uvmmap();		/* We may also need to do this at process exit */

    seglen[0] = 0;		/* default stack size */
    if (loadELF(fd,ptndx,seglen) < 0) {	/* try "elf" format (gcc/gas) */
	if (loadPE(fd,ptndx,seglen) < 0) {	    /* try "pe" (Cygwin) */
	    freepage(p->ptaddr);	/* free page table page */
	    nextpid--;
	    close(fd);
	    return BADEXEC;
	}
    }

    close(fd);

    /*--------------------------------------------------*/
    /* Display the user page table (used entries only). */
    /*--------------------------------------------------*/
    if (kd_Flag & DEBUG_RUN) {
	int i, skipping;
	unsigned int va;		/* virtual address */
	unsigned int pte;

	dprintf("_run: User Page Table:\n");
	va = USERVMA;
	skipping = 0;
	dprintf("Virtual  PTE\n");
	for (i=0;i<1024;i++) {
	    pte = p->ptaddr[i];
	    if (pte) {
		dprintf("%08x %08x\n", va, pte);
		skipping = 0;
	    } else {
		if (!skipping) {
		    dprintf("...\n");
		    skipping = 1;
		}
	    }
	    va += 4096;
	}
	dprintf("-----------------\n");
    }

    /*------------------------------------------------------*/
    /* Stack initialization...                              */
    /* p->stksize for "old" processes contained the number  */
    /* of contiguous pages of physmem used for the stack.   */
    /* --- BEWARE OF THE FOLLOWING REMARK ----------------- */
    /* We don't need that to identify the stack space for   */
    /* "new" processes, since we can just count to entries  */
    /* at the top of the process' page table (if required). */
    /*------------------------------------------------------*/
    p->stkbase = (unsigned int *)(USERVMA + 0x400000 - 4);
    stackPointer = p->stkbase;
    p->stksize = 1;

    /*--------------------------------------------*/
    /* Determine the size of the string arguments */
    /* and the array of pointers to them.         */
    /*--------------------------------------------*/
    targlen = 0;					/* total arg len */
    for (i=0;i<nargs;i++)
	targlen += strlen(a[i]) + 1;			/* include nulls */
    targlen = (targlen + 3) & ~3;			/* round up */
    tptrlen = (nargs + 1) * sizeof(char *);		/* ptr array size */

    parg = 4096 + (unsigned char *)p->ptaddr[1023];	/* stk top phys addr */
    varg = (unsigned char *)(USERVMA + 0x400000);	/* stk top virt addr */

    if (kd_Flag & DEBUG_RUN) {
	dprintf("_run setup: parg = 0x%08x, varg = 0x%08x\n", parg, varg);
	dprintf("            targlen = %d\n", targlen);
	dprintf("            tptrlen = %d\n", tptrlen);
	dprintf("            nargs = %d\n", nargs);
    }

    parg -= targlen;					/* arg strs phys addr */
    varg -= targlen;					/* arg strs virt addr */

    pptr = (unsigned char **)(parg - tptrlen);		/* ptr arr. phys addr */
    dptr = varg - tptrlen;				/* ptr arr. virt addr */

    iptr = (unsigned int *)pptr;
    iptr--;
    *iptr = (unsigned int)dptr;		/* va of pointer array 0th entry */
    iptr--;
    *iptr = (unsigned int)nargs;	/* # args */
    iptr--;
    *iptr = (unsigned int)processDone;	/* XXX is this correct? check it out. */

    /*------------------------------------------------*/
    /* Copy nargs strings from a[] to parg, and       */
    /* Store corresponding virtual addresses at pptr. */
    /*------------------------------------------------*/
    for (i=0;i<nargs;i++) {
	strcpy(parg,a[i]);
	*pptr++ = varg;
	parg += strlen(a[i]) + 1;
	varg += strlen(a[i]) + 1;
    }
    *pptr = NULL;		/* install null pointer after last arg ptr */

    if (kd_Flag & DEBUG_RUN) {
	unsigned int va;		/* virtual address */
	unsigned char *pa;		/* physical address */
	unsigned int k;

	pa = 4092 + (unsigned char *)p->ptaddr[1023];
	va = USERVMA + 0x400000 - 4;
	dprintf("Physical Virtual  Contents\n");
	k = 0;
	while (pa >= (unsigned char *)iptr && k < 1024) {
	    dprintf("%08x %08x %08x\n", pa, va, *(unsigned int *)pa);
	    pa -= 4;
	    va -= 4;
	    k++;
	}
	dprintf("--------------------------\n");
    }

    /*----------------------------------*/
    /* Display contents of user memory. */
    /*----------------------------------*/
    if (kd_Flag & DEBUG_RUN) {
	unsigned int i;
	unsigned int va;
	unsigned char *pa;
	int done1;		/* true if at least one line displayed */
	int dup1;		/* true if no ... shown for current dup */
	int dup;		/* true if current line is a dup */
	unsigned char prev[16];
	unsigned char c;

	dprintf("_run: User Memory:\n");
	va = USERVMA;
	done1 = 0;
	dup1 = 1;
	while (va < USERVMA + 0x400000) {
	    /*---------------------------------------------------------------*/
	    /* Map virtual address va to the corresponding physical address. */
	    /*---------------------------------------------------------------*/
	    if ((va & 0xfff) == 0) {
		i = (va - USERVMA) >> 12;	/* index to page table */
		pa = (unsigned char *)p->ptaddr[i];

		/*--------------------------------------*/
		/* If this is unmapped memory, skip it. */
		/*--------------------------------------*/
		if (pa == 0) {
		    done1 = 0;
		    dup1 = 1;
		    va += 4096;
		    continue;
		}
	    }

	    /*---------------------------------------------------------*/
	    /* Will the next line be a duplicate of the previous line? */
	    /*---------------------------------------------------------*/
	    if (done1) {
		dup = 1;
		for (i=0;i<16;i++)
		    if (pa[i] != prev[i]) {
			dup = 0;
			break;
		}
		if (dup) {			/* yes, it's a duplicate */
		    if (dup1) {			/* first one? */
			dup1 = 0;
			dprintf("...\n");
		    }

		    /*-------------------------------------------*/
		    /* If this is the last line, show it anyway. */
		    /*-------------------------------------------*/
		    if (va + 16 < USERVMA + 0x400000) {
			va += 16;
			pa += 16;
			continue;
		    }
		}
	    }

	    /*-----------------------------------*/
	    /* Not a duplicate line; display it. */
	    /*-----------------------------------*/
	    dprintf("%08x  ", va);
	    for (i=0;i<16;i++) {
		prev[i] = pa[i];
		dprintf("%02x ", pa[i]);
	    }
	    dprintf(" ");
	    for (i=0;i<16;i++) {
		c = pa[i];
		if (c < ' ' || c > '~')
		    c = '.';
		dprintf("%c",c);
	    }
	    dprintf("\n");
	    va += 16;
	    pa += 16;
	    done1 = 1;		/* did one line, now start dup checking */
	    dup1 = 1;		/* no dups (yet) for last line */
	}
	dprintf("-----------------\n");
    }

    /*-----------------------------------------------*/
    /* Allocate a physical page for the kernel stack */
    /* NB. Not in the user's virtual address space.  */
    /*-----------------------------------------------*/
    p->kstkbase = allocpage(ptndx,0);	/* allocate kernel stack (1 page) */
					/* XXX - verify allocation! */
    ksp = p->kstkbase + 1023;		/* unsigned int *, dude */
    p->kstkbase += 1024;

    /*-------------------------------------------------------*/
    /* Initialize the kernel mode stack. Some of the initial */
    /* register values are arbitrary, so we select values    */
    /* for them that might make debugging easier.            */
    /*-------------------------------------------------------*/
    *ksp-- = USER_DATA_SEL;		/* ss */

    uvmsp = USERVMA + 1023 * 0x1000;	/* vm addr bottom page of user stack */
    uvmsp |= ((unsigned int)iptr) & 0xfff;
    *ksp-- = uvmsp;

    *ksp-- = 0x200;			/* eflags */
    *ksp-- = USER_CODE_SEL;		/* cs */
    *ksp-- = p->staddr;			/* eip */

    *ksp-- = 0xffffffff;		/* mirror push done on kernel entry */

    *ksp-- = USER_DATA_SEL;		/* gs */
    *ksp-- = USER_DATA_SEL;		/* fs */
    *ksp-- = USER_DATA_SEL;		/* es */
    *ksp-- = USER_DATA_SEL;		/* ds */

    *ksp-- = 0x12340001;		/* eax */
    *ksp-- = 0x12340002;		/* ecx */
    *ksp-- = 0x12340003;		/* edx */
    *ksp-- = 0x12340004;		/* ebx */
    *ksp-- = 0x12340005;		/* esp (ignored later) */
    *ksp-- = 0x12340006;		/* ebp */
    *ksp-- = 0x12340007;		/* esi */
    *ksp   = 0x12340008;		/* edi */

    p->ksp = ksp;

    /*---------------------------------------------------------------------*/
    /* Set U/S, RW, and Presence bits appropriately for page table entries */
    /*---------------------------------------------------------------------*/
    /* XXX - This should probably be done by the loadXXX function, since   */
    /* only it is in a position to know which pages should be executable,  */
    /* readable, and/or writable.                                          */
    /*---------------------------------------------------------------------*/
    pte = p->ptaddr;
    for (i=0;i<1024;i++) {
	if (*pte != 0) *pte |= 7;
	pte++;
    }

    /*------------------------------------------*/
    /* Initialize event queues for this process */
    /*------------------------------------------*/
    for (i = 0; i < NQUEUE; i++) {
	p->eventQueue[i].count= 0;
	p->eventQueue[i].mask = UNMASKED;
	p->eventQueue[i].head = NULL;
	p->eventQueue[i].tail = NULL;
    }

    /*---------------------------------*/
    /* Initialize the file descriptors */
    /*---------------------------------*/
    for (i=0;i<3;i++) {		/* file descriptors 0-2 duplicate caller's */
	if (pfd[i] == -1) p->fd[i].fdescnr = -1;
	else {
	    p->fd[i].how = activeProcess->fd[pfd[i]].how;
	    p->fd[i].fdescnr = activeProcess->fd[pfd[i]].fdescnr;
	    if (p->fd[i].fdescnr != -1 && p->fd[i].how >= 0) {	/* disk */
		/* Increase reference count for file */
		fdesc[p->fd[i].fdescnr].nrefs++;
		p->fd[i].offset = 0;		/* set offset to 0 */
	    }
	}
    }
    for(i=3;i<NFD;i++) p->fd[i].fdescnr = -1;	/* others are available */

    /*--------------------------*/
    /* Copy environ and workdir */
    /*--------------------------*/
    strcpy(p->workdir,workdir);
    strcpy(p->environ,environ);

    p->signaledOn = -1;
    numprocesses++;
    _addready(p);

    /*-------------------------------------------------------------*/
    /* N.B. A "strategic" flaw in the system call design for Tempo */
    /* is that it is possible -- in some cases -- for the newly-   */
    /* created process to complete execution before the creating   */
    /* process has an opportunity to execute the waitproc system   */
    /* call. One way to solve that problem is to produce another   */
    /* system call, perhaps named "runwait", that does everything  */
    /* run does, but before actually returning, it does what the   */
    /* waitproc system call does.                                  */
    /*-------------------------------------------------------------*/

    /*---------------------------------------------------------*/
    /* If the newly created process has a priority higher than */
    /* that of the current process, then yield the CPU to it.  */
    /*---------------------------------------------------------*/
    if (priority > activeProcess->priority) {
	_addready(activeProcess);
	_rs = 1;	/* indicate we need to reschedule */
    }
    return p->pid;
}

/***********************************************************/
/***********************************************************/
/********* System Call 48: Get process information *********/
/***********************************************************/
/***********************************************************/
int _getprocinfo (void *args[])
{
    /*------------------------*/
    /* system call parameters */
    /*------------------------*/
    int n;
    struct pinfo *p;

    /*-----------------*/
    /* Other variables */
    /*-----------------*/
    int i, j;
    int nret;
    int npages;

    /*--------------------*/
    /* Extract parameters */
    /*--------------------*/
    n = (int)args[0];
    p = (struct pinfo *)args[1];

    if (n <= 0) return BADVAL;
    if (p == NULL) return NULLPARM;

    /*----------------------------*/
    /* Obtain process information */
    /*----------------------------*/
    nret = 0;
    for (i=0;i<NPROC;i++) {
	if (proctab[i].state == PROCESS_FREE) continue;
	p->pid = proctab[i].pid;
	p->priority = proctab[i].priority;
	p->state = proctab[i].state;

	/* Compute number of allocated pages */
	npages = 0;
	for (j=0;j<4096;j++) if (pgmap[j] == i+1) npages++;
	p->npages = npages;

	nret++;
	p++;
	if (nret == n) break;
    }
    return nret;
}

/***********************************************************************/
/***********************************************************************/
/********* System Call 49: Adjust highest data segment address *********/
/***********************************************************************/
/***********************************************************************/
int _brk (void *arg)
{
    char *a;
    unsigned int *pte;			/* ptr to page table entry */
    unsigned int ap, cp;		/* new, current break (rounded) */
    unsigned int npgs;			/* # of pages to change */
    unsigned int px;			/* index to page table */
    unsigned int procndx;		/* index of process in proctab */
    unsigned int *np;			/* core addr of a new page */
    int i;

    a = (char *)arg;

    pte = activeProcess->ptaddr;
    if (pte == 0) return BADEXEC;	/* not started with run */

    if (a < activeProcess->brkbase)	/* new address is too small */
	return BADVAL;

    /*-------------------------------------------------*/
    /* Get page numbers for argument and current break */
    /*-------------------------------------------------*/
    ap = ((unsigned int)a + 0xfff) >> 12;
    cp = ((unsigned int)activeProcess->brkcurr + 0xfff) >> 12;

    /*---------------------------------------------------------------*/
    /* If changing break doesn't require adding or removing pages... */
    /*---------------------------------------------------------------*/
    if (ap == cp) {
	activeProcess->brkcurr = a;
	return NOERROR;
    }

    /*-------------------------------------------------*/
    /* If an additional page (or pages) is required... */
    /*-------------------------------------------------*/
    if (ap > cp) {
	npgs = ap - cp;			/* # of pages needed */
#ifdef NONO
	px = cp - 0x8000;		/* ptbl ndx of first needed page */
#else
	px = cp - (USERVMA >> 12);
#endif

	/*------------------------------------------------*/
	/* Verify the needed page table slots are unused. */
	/* If not, return NOMEM error code.               */
	/*------------------------------------------------*/
	for (i=0;i<npgs;i++) if (pte[px+i] != 0) {
	    return NOMEM;
	}

	/*-------------------------------------------------*/
	/* Allocate the needed physical pages and populate */
	/* the page table slots. On completion, np is 0 if */
	/* all needed physical memory isn't available.     */
	/*-------------------------------------------------*/
	procndx = activeProcess - proctab;	/* index of proc in proctab */
	for (i=0;i<npgs;i++) {			/* allocate needed pages */
	    np = allocpage(procndx,1);
	    if (np == 0) break;			/* insufficient real memory */
	    pte[px+i] = (unsigned int)np;	/* save phys addr in page tbl */
	}

	/*--------------------------------------------------*/
	/* If insufficient physical memory, deallocate the  */
	/* pages we were able to allocate and return NOMEM. */
	/*--------------------------------------------------*/
	if (np == 0) {
	    while (i >= 0) {
		freepage((unsigned int *)pte[px+i]);
		i--;
	    }
	    return NOMEM;
	}

	/*--------------------------------------------------------*/
	/* Mark the pages allocated: present + read/write + user. */
	/* Then invalidate the translation lookaside buffer (?).  */
	/*--------------------------------------------------------*/
	for (i=0;i<npgs;i++) pte[px+i] |= 7;
	_invtlb();

	/*-----------------------------------------------*/
	/* Save the new break address and return NOERROR */
	/*-----------------------------------------------*/
	activeProcess->brkcurr = a;
	return NOERROR;
    } else {				/* break decrease desired */
	kprintf("break decrease not yet implemented.\r\n"); /* XXX */
	return NOERROR;
    }
    return NOERROR;
}

/******************************************************************/
/******************************************************************/
/******** System Call 63: Allocate or free shared memory. *********/
/******************************************************************/
/******************************************************************/
int _shmem(void *args[])
{
    int i;			/* _shmtbl index */
    int j;			/* process page table index */
    int key;			/* key identifying the shared region */
    int func;			/* 0 = free, 1 = allocate/attach */
    void **loc;			/* where to return user's virtual address */
    int unused;			/* index of first unused _shmtbl slot */
    unsigned int *pt;		/* pointer to process page table */
    int found;			/* boolean flag: did we find the PTE? */
    int lstk;			/* index of lowest stack PTE */
    int theap;			/* index of PTE at top of heap */
    int ptex;			/* index of PTE to use for new reference */
    unsigned int *paddr;	/* physical address of an allocated frame */

    /*------------------------*/
    /* Extract the arguments. */
    /*------------------------*/
    key = (int)args[0];
    func = (int)args[1];  //number of pages of shared memory desired
    loc = args[2];

    /*------------------------------------------------*/
    /* Verify the function (action) is either 0 or 1. */
    /*------------------------------------------------*/
    //if (func != 0 && func != 1)
	//return NOSUCHFUNC;	/* function must be 0 or 1 */
 
    /*------------------------------------------------*/
    /* Modified for PROGRAM 2                         */
    /* Verify the function (action) is either 0       */
    /* greater than or equal to 1.                    */
    /*------------------------------------------------*/
    if ( func < 0 )
    {
        return NOSUCHFUNC;
    }
    

    /*-----------------------------------------------------*/
    /* Verify the process was started with 'run'. That is, */
    /* it must have a page table.                          */
    /*-----------------------------------------------------*/
    if ((pt = activeProcess->ptaddr) == 0)
	return NOPAGETBL;

    /*------------------------------------------------*/
    /* Search _shmtbl for an active entry with 'key'. */
    /* Also locate an unused table entry, if any.     */
    /* At the end of the loop, if i < NSHMEM we have  */
    /* found an entry with the key.                   */
    /*------------------------------------------------*/
    unused = -1;
    
    for (i=0;i<NSHMEM;i++)
    {
        if (_shmtbl[i].nrefs == 0)
        {
            if (unused == -1)
            {
                unused = i;
            }
            continue;
        }
        if (_shmtbl[i].key == key)
        {
            break;
        }
    }
/*______________________________________________________________________*/
    /*-----------------------------------------------*/
    /* Handle a request to "detach" from the region. */
    /*-----------------------------------------------*/
    if (func == 0)
    {
        if (i == NSHMEM)
            return NOSUCHKEY;		/* no region with this key */

	
    
        /*----------------------------------------------------*/
        /* Deallocate the region from this process. We search */
        /* for the first (lowest) page table entry that has   */
        /* the address of the shared page. This behavior is   */
        /* not necessarily what's really wanted, and we might */
        /* change it in the future. That is, suppose the page */
        /* frame of shared memory was mapped into the process */
        /* address space several times. The process should be */
        /* allowed to explicitly say which of the instances   */
        /* is to be unmapped.                                 */
        /*----------------------------------------------------*/
        found = 0;
        
        for (j=0;j<1024;j++)
        {
            if ((pt[j] & 0xfffff000) ==
                ((unsigned int)_shmtbl[i].addr & 0xfffff000))
            {
                found = 1;
                break;
            }
        }

        
        /*---------------------------------------------------*/
        /* Sanity check: verify we found an appropriate PTE. */
        /*---------------------------------------------------*/
        if (found == 0)
            return NOSUCHPAGE;

        /*-----------------------------*/
        /* Clear the page table entry. */
        /*-----------------------------*/
        pt[j] = 0;
        /*---------------------------------------------------------*/
        /* Either invalidate the entire TLB, or just the TLB entry */
        /* mapping the page whose PTE we just cleared.             */
        /*---------------------------------------------------------*/
        _invtlb();

        /*----------------------------------------------------------------*/
        /* Reduce the reference count and reclaim the page if now unused. */
        /*----------------------------------------------------------------*/
        if (--_shmtbl[i].nrefs == 0)
        {
            freepage(_shmtbl[i].addr);
        }

        return 0;
    }//end "detach"

    /*---------------------------------------------------------------------------------*/
    
    
    /*-----------------------------------------------------*/
    /* Handle a request to create or attach to the region. */
    /*-----------------------------------------------------*/
    if (func > 0)
    {

        /*--------------------------------------------*/
        /* Determine the page table entry to be used. */
        /* We work downward from the top of the user  */
        /* memory to find the PTE containing the top  */
        /* of the stack.  Need to find func number    */
        /* of PTEs
        /*--------------------------------------------*/
        for (j=1023;j>=0;j--)
        {
            if (pt[j] == 0)
            {
                break;
            }
        }
        
        // j will be -1 if the above loop has gone all the way
        // through
        if (j < 0)
        {
            return PTBLFULL;		/* no unused PTEs */
        }
        
        lstk = j+1;			/* index of lowest stack PTE */

        /*--------------------------------------------*/
        /* Now we use the current break address to    */
        /* identify the page at the top of the heap.  */
        /*--------------------------------------------*/
        theap = (((int)activeProcess->brkcurr) >> 12) - (USERVMA >> 12);

        /*-----------------------------*/
        /* tstk - theap is at least 2. */
        /*-----------------------------*/
        ptex = theap + (lstk - theap) / 2;

        /*----------------------------------------------------*/
        /* Find the first unused PTE in the page table region */
        /* centered at ptex. We're guaranteed there will be   */
        /* such an entry from our earlier search for a 0 PTE. */
        /*----------------------------------------------------*/
        if (pt[ptex] != 0)
        {
            for (j=1;;j++)
            {
                if (pt[ptex+j] == 0)
                {
                    ptex += j;
                    break;
                }
                if (pt[ptex-j] == 0)
                {
                    ptex -= j;
                    break;
                }
            }
        }


        if (i == NSHMEM)
        {
            /*-----------------------------------------*/
            /* New key; allocate an unused page frame. */
            /*-----------------------------------------*/
            if (unused == -1)
            return NOSHMEM;			/* no table space */
            i = unused;
            paddr = allocpage(0xff,1);		/* allocate 0-filled page */
            if (paddr == 0)
            return NOSHMEM;			/* no free page frames */
            _shmtbl[i].nrefs = 0;
            _shmtbl[i].addr =
            (unsigned int *)((unsigned int)(paddr) & 0xfffff000);
            _shmtbl[i].key = key;
        }
        else
        {
            /*----------------------------------------------------*/
            /* Existing key; attach to page previously allocated. */
            /*----------------------------------------------------*/
            paddr =
            (unsigned int *)((unsigned int)_shmtbl[i].addr & 0xfffff000);
        }

        _shmtbl[i].nrefs++;		/* increase ref count */
        pt[ptex] = (unsigned int)paddr;
        pt[ptex] |= 7;			/* user, r/w, present */
        *loc = (void *)(USERVMA + ptex * 4096);
    }//end create or attach
    
    return 0;
    
}//end shmem

/******************************************************************/
/******************************************************************/
/********* System Call 50: Get current working directory. *********/
/******************************************************************/
/******************************************************************/
/* Actually returns char * */
int _getcwd (void *args[])
{
/* XXX Returns an ABSOLUTE path for the current working directory */
/*     into the buffer (1st arg). The buffer has the size given   */
/*     by the second arg (check for accessability). If the buffer */
/*     is too small, return NULL. Otherwise return the address of */
/*     the buffer.                                                */

    /* Parameters */
    char *buff;
    size_t bufflen;
    int s0, s1;

    buff = (char *)args[0];
    bufflen = (size_t)args[1];

    if (bufflen < strlen(activeProcess->workdir)+1) return NULL;
    if ((s0 = chkaddr((unsigned)buff)) == 0) return EFAULT;
    if ((s1 = chkaddr((unsigned)buff+bufflen-1)) == 0) return EFAULT;
    if (s0 != s1) return EFAULT;
    strcpy(buff,activeProcess->workdir);
    return (int)buff;
}

/******************************************************************/
/******************************************************************/
/********* System Call 51: Set current working directory. *********/
/******************************************************************/
/******************************************************************/
int _chdir (char *path)
{
    int len, status, fdesci;
    unsigned int apath;
    char lpath[MAXPATH+1];

    status = abspath(path,lpath);
    if (status < 0) return status;

    /*------------------------------*/
    /* Verify the directory exists. */
    /*------------------------------*/
    fdesci = dget(lpath);
    if (fdesci < 0) return fdesci;
    if ((fdesc[fdesci].de.dflag & DE_ISDIR) == 0) {
	freedref(fdesci);
	return ENOTDIR;
    }
    freedref(fdesci);

    /*------------------------------------------------*/
    /* Copy the new path into the process table entry */
    /*------------------------------------------------*/
    strcpy(activeProcess->workdir,lpath);
    return NOERROR;
}

/************************************************************/
/************************************************************/
/********* System Call 52: Get video page contents. *********/
/************************************************************/
/************************************************************/
int _getvpc (void *args[])
{
    unsigned int con;		/* console number */
    unsigned char *pp;		/* ptr to user storage area */

    void *vbase;

    con = (unsigned int)args[0];

    if (con < 0 || con > NVPG-1) return NOSUCHCON;
    vbase = (void *)(0xb8000 + con * 80 * 25 * 2);
    memcpy(args[1],vbase,4000);
    return NOERROR;
}

/************************************************************/
/************************************************************/
/********* System Call 53: Set video page contents. *********/
/************************************************************/
/************************************************************/

/* Do we really need this if we've got vccaout? */

int _setvpc (void *args[])
{
    unsigned int con;		/* console number */
    unsigned char *pp;		/* ptr to user storage area */

    void *vbase;

    con = (unsigned int)args[0];

    if (con < 0 || con > NVPG-1) return NOSUCHCON;
    vbase = (void *)(0xb8000 + con * 80 * 25 * 2);
    memcpy(vbase,args[1],4000);
    return NOERROR;
}

/*********************************************************/
/*********************************************************/
/********* System Call 54: Display chars/attrs  **********/
/*********************************************************/
/*********************************************************/
/****************************************************************************/
/* Display, without interpretation, the characters and attributes at chratt */
/* at the starting specified character position (0-origin row and column)   */
/* on the specified console page. The cursor position is not modified. On   */
/* success returns NOERROR. If row/col is bad, or nchars is too large, the  */
/* system call returns BADVAL. If con is bad, returns NOSUCHCON.            */
/****************************************************************************/
int _vccaout (void *args[])
{
    /*------------------------*/
    /* system call parameters */
    /*------------------------*/
    int con;				/* selected console number */
    unsigned int nchars;		/* # of char/attr pairs */
    unsigned char *chratt;		/* address of char/attr pair array */
    int row, col;			/* starting position on console */

    unsigned int offset;		/* byte pair offset of video page */
    unsigned char *vbase;		/* base of RAM for video page */

    /*--------------------------*/
    /* Extract parameter values */
    /*--------------------------*/
    con = (int)args[0];
    nchars = (unsigned int)args[1];
    chratt = (unsigned char *)args[2];
    row = (unsigned int)args[3];
    col = (unsigned int)args[4];

    if (con < 0 || con > NVPG-1) return NOSUCHCON;
    if (row < 1 || row > 24) return BADVAL;
    if (col < 1 || col > 80) return BADVAL;
    if (nchars > 25 * 80 - (row - 1) * 80 + col - 1) return BADVAL;

    offset = con * 80 * 25;		/* offset to video page start */
    vbase = (unsigned char *)0xb8000 + 2 * (offset + (row - 1) * 80 + col - 1);
    memcpy(vbase,chratt,nchars*2);
    return NOERROR;
}

/********************************************************/
/********************************************************/
/********* System Call 55: Get cursor position. *********/
/********************************************************/
/********************************************************/
int _getcurpos(void *args[])
{
    int con;
    int *row, *col;

    con = (int)args[0];
    row = (int *)args[1];
    col = (int *)args[2];

    if (row == NULL || col == NULL) return NULLPARM;

    if (con < 0 || con > NVPG-1) return NOSUCHCON;

    *row = vidrow[con] + 1;
    *col = vidcol[con] + 1;
    return NOERROR;
}

/*************************************************************************/
/*************************************************************************/
/********* System Call 56: Get/set console character attributes. *********/
/*************************************************************************/
/*************************************************************************/
int _conattr(void *args[])
{
    int con, newattr;
    int *oldattr;

    con = (int)args[0];
    newattr = (int)args[1];
    oldattr = (int *)args[2];

    if (con < 0 || con > NVPG-1) return NOSUCHCON;

    /* Not yet implemented */
    return UNIMPLEMENTED;
}

/********************************************************************/
/********************************************************************/
/********* System Call 57: Get date and time from RTC chip. *********/
/********************************************************************/
/********************************************************************/
int _getrtc(void *args[])
{
    unsigned int *date, *time;	/* MMDDYYYY, HHMMSS */
    unsigned char statusB;
    unsigned char val;

    date = (unsigned int *)args[0];
    time = (unsigned int *)args[1];

    /*---------------------------------------------------------------*/
    /* Set the SET bit in status register B to prevent update cycles */
    /*---------------------------------------------------------------*/
    outb(0x70,11);		/* select status register B */
    statusB = inb(0x71);	/* get its current value */
    outb(0x70,11);		/* select status register B again */
    outb(0x71,statusB | 0x80);	/* turn on the SET bit */

    /*------------------------------*/
    /* Build the date, byte by byte */
    /*------------------------------*/
    if (date != NULL) {
	outb(0x70,8); val = inb(0x71);	/* month, in BCD format */
	*date = (val >> 4) * 10 + (val & 0xf);

	outb(0x70,7); val = inb(0x71);	/* day of month, in BCD format */
	*date *= 100;
	*date += (val >> 4) * 10 + (val & 0xf);

	outb(0x70,50); val = inb(0x71);	/* century, in BCD format */
	*date *= 100;
	*date += (val >> 4) * 10 + (val & 0xf);

	outb(0x70,9); val = inb(0x71);	/* year, in BCD format */
	*date *= 100;
	*date += (val >> 4) * 10 + (val & 0xf);
    }

    /*----------------*/
    /* Build the time */
    /*----------------*/
    if (time != NULL) {
	outb(0x70,4); val = inb(0x71);	/* hours, in BCD format */
	*time = (val >> 4) * 10 + (val & 0xf);

	outb(0x70,2); val = inb(0x71);	/* minutes, in BCD format */
	*time *= 100;
	*time += (val >> 4) * 10 + (val & 0xf);

	outb(0x70,0); val = inb(0x71);	/* seconds, in BCD format */
	*time *= 100;
	*time += (val >> 4) * 10 + (val & 0xf);
    }

    /*--------------------------------------------------*/
    /* Restore status register B to allow update cycles */
    /*--------------------------------------------------*/
    outb(0x70,11);		/* select status register B again */
    outb(0x71,statusB);		/* rewrite the original value */
    
    return NOERROR;
}

/**************************************************************************/
/**************************************************************************/
/********* System Call 58: Block process until specified time.  ***********/
/**************************************************************************/
/**************************************************************************/

/*************************************************************/
/* Helper function for wakeup and cancelwakeup system calls. */
/* Assume the SET bit in status register B is 1 on entry.    */
/* Then set the alarm time (bytes 1, 3, and 5) to the time   */
/* in the first entry on awakeq. The alarm bit (bit 5) in    */
/* status register B must also be set, but we leave that to  */
/* the system call, since it has the original copy of the    */
/* value from status register B saved already.               */
/*************************************************************/
static void setRTCalarm(void)
{
    unsigned char at, bcdat;			/* alarm byte, binary/bcd */
    unsigned int temp;

    temp = awakeq->delta;			/* alarm time, hhmmss */

dprintf("Setting alarm bytes in RTC: ");
    at = temp % 100;				/* set second */
    bcdat = ((at / 10) << 4) | (at % 10);
    outb(0x70,1);
    outb(0x71,bcdat);
dprintf("seconds = %02x, ", bcdat);

    at = (temp / 100) % 100;			/* set minute */
    bcdat = ((at / 10) << 4) | (at % 10);
    outb(0x70,3);
    outb(0x71,bcdat);
dprintf("minutes = %02x, ", bcdat);

    at = temp / 10000;				/* set hour */
    bcdat = ((at / 10) << 4) | (at % 10);
    outb(0x70,5);
    outb(0x71,bcdat);
dprintf("hours = %02x\r\n", bcdat);
}

/*****************************************************************/
/* Given the current time 'c' and two other times 't1' and 't2', */
/* return an indication of which of t1 and t2 will be reached    */
/* first. All times have decimal formats like HHMMSS on a 24-hr  */
/* clock. Return -1 if t1 will be reached first, +1 if t2 will   */
/* be reached first, and 0 if t1 and t2 are the same time.       */
/*****************************************************************/
int ewake(unsigned int c, unsigned int t1, unsigned int t2)
{
    if (t1 <= c) t1 += 240000;		/* next day */
    if (t2 <= c) t2 += 240000;		/* next day */
    if (t1 < t2) return -1;
    if (t1 == t2) return 0;
    return 1;
}

static void showawakeq()
{
    struct Proc *p;

    if (awakeq == NULL) dprintf("Awakeq is empty\r\n");
    else {
	dprintf("Awakeq:\r\n");
	for(p = awakeq;p!=NULL;p=p->next)
	    dprintf("    pid %d, delta = %d\r\n", p->pid, p->delta);
    }
}

int _wakeup(unsigned int waketime)
{
    unsigned char wakesec, wakemin, wakehr;	/* broken-out parmeter */
    unsigned char cursec, curmin, curhr;	/* current time */
    unsigned char val;
    unsigned char statusB;
    unsigned char change;			/* 1 if RTC alarm must be set */
    int waketemp;
    int curtime;
    int ptemp;
    struct Proc *p, *q;				/* current, prev proc on list */

    /*------------------------------------*/
    /* Validate the requested wakeup time */
    /*------------------------------------*/
    if (waketime > 235959) return BADTIME;
    wakesec = waketime % 100;
    waketemp = waketime / 100;
    wakemin = waketemp % 100;
    wakehr = waketemp / 100;
    if (wakesec > 59 || wakemin > 59 || wakehr > 23) return BADTIME;

    /*---------------------------------------------------------------*/
    /* Set the SET bit in status register B to prevent update cycles */
    /*---------------------------------------------------------------*/
    outb(0x70,11);		/* select status register B */
    statusB = inb(0x71);	/* get its current value */
    outb(0x70,11);		/* select status register B again */
    outb(0x71,statusB | 0x80);	/* turn on the SET bit */

    /*----------------------*/
    /* Get the current time */
    /*----------------------*/
    outb(0x70,4); val = inb(0x71);	/* hours, in BCD format */
    curhr = (val >> 4) * 10 + (val & 0xf);

    outb(0x70,2); val = inb(0x71);	/* minutes, in BCD format */
    curmin = (val >> 4) * 10 + (val & 0xf);

    outb(0x70,0); val = inb(0x71);	/* seconds, in BCD format */
    cursec = (val >> 4) * 10 + (val & 0xf);

    curtime = (curhr * 100 + curmin) * 100 + cursec;
dprintf("wakeup: current time = %06d\n", curtime);
dprintf("wakeup time: %02d:%02d:%02d\n", wakehr, wakemin, wakesec);

    /*------------------------------------------------------*/
    /* If wakeup isn't for a time in the future, return now */
    /*------------------------------------------------------*/
    if (curtime == waketime) {
	outb(0x70,11);		/* select status register B again */
	outb(0x71,statusB);	/* rewrite the original value */
	return NOERROR;		/* wakeup now, so don't go to sleep! */
    }

    /*----------------------------------------------------------------*/
    /* Add this process to the linked list of those awaiting a wakeup */
    /*----------------------------------------------------------------*/
    activeProcess->delta = waketime;
    activeProcess->state = WAKEUP_BLOCKED;
    change = 0;				/* assume no RTC changes req'd */

    if (awakeq == NULL) {		/* queue is empty */
	activeProcess->next = activeProcess->prev = NULL;
	awakeq = activeProcess;
	change = 1;			/* RTC alarm needs change */

    } else {
	q = NULL;
	p = awakeq;
	while (p != NULL && ewake(curtime,waketime,p->delta) == 1) {
	    q = p;
	    p = p->next;
	}
	if (q == NULL) {		/* new head of list */
	    change = 1;			/* RTC alarm needs change */
	    activeProcess->next = p;
	    activeProcess->prev = NULL;
	    p->prev = activeProcess;
	    awakeq = activeProcess;
	} else {			/* NOT new head of list */
    	    activeProcess->next = p;
	    activeProcess->prev = q;
	    q->next = p->prev = activeProcess;
	}
    }
dprintf("wakeup: change = %d\r\n", change);
    if (change) setRTCalarm();
    outb(0x70,11);		/* write statusB with alarm bit set, SET clr */
    outb(0x71,statusB | 0x20);
    activeProcess->wakeupstat = 0;
showawakeq();
    _block();			/* wait for the wakeup... */

dprintf("wakeup occurred for process %d; wakeupstat = %d\n",
activeProcess->pid, activeProcess->wakeupstat);

    if (activeProcess->wakeupstat) return CANCELLED;
    return NOERROR;
}

/********************************************************************/
/********************************************************************/
/********* System Call 59: Cancel a pending wakeup call.  ***********/
/********************************************************************/
/********************************************************************/
int _cancelwakeup(pid_t pid)
{
    struct Proc *rmproc;	/* ptr to proctab w/ wakeup to cancel */
    unsigned char first;	/* set if proc is first on awakeq */
    unsigned char statusB;	/* copy of RTC status register B */

    /*---------------------------------------------------*/
    /* Verify process exists and is in appropriate state */
    /*---------------------------------------------------*/
    rmproc = pid2a(pid);
    if (rmproc == 0) return NOSUCHPROCESS;
    if (rmproc->state != WAKEUP_BLOCKED) return NOSUCHPROCESS;

    /*----------------------------------------------------------*/
    /* Remove process from awakeq, noting if it's the first one */
    /* (which will necessitate a change in the RTC alarm time). */
    /*----------------------------------------------------------*/
    first = awakeq == rmproc;

    if (first) {		/* remove first entry from queue */
	awakeq = rmproc->next;
	if (awakeq != NULL) {
	    awakeq->prev = NULL;
	    if (rmproc->delta != awakeq->delta) {	/* reset RTC alarm? */
		outb(0x70,11);				/* save status B */
		statusB = inb(0x71);
		outb(0x70,11);
		outb(0x71,statusB | 0x80);
		setRTCalarm();
		outb(0x70,11);				/* restore status B */
		outb(0x71,statusB);
	    }
	}
    } else {
	if (rmproc->next != NULL) {	/* remove from middle of queue */
	    rmproc->next->prev = rmproc->prev;
	}
	rmproc->prev->next = rmproc->next;
    }

    /*-------------------------------------*/
    /* Turn off AIE if awakeq is empty now */
    /*-------------------------------------*/
    if (awakeq == NULL) {
	/* turn off AIE bit */
	outb(0x70,11);
	statusB = inb(0x71);
	outb(0x70,11);
	outb(0x71,statusB & ~0x20);
    }

    /*----------------------------------*/
    /* Unblock, reschedule if necessary */
    /*----------------------------------*/
    rmproc->wakeupstat = 1;
    _addready(rmproc);
    if (rmproc->priority > activeProcess->priority) {
	_addready(activeProcess);
	_rs = 1;
    }
dprintf("About to exit cancelwakeup.\r\n");
showawakeq();

    return NOERROR;
}

/*********************************************************/
/*********************************************************/
/********* System Call 60: Reboot the system.  ***********/
/*********************************************************/
/*********************************************************/
int _reboot(void)
{
    bios_reboot();

    /*-------------------------------------------------------*/
    /* Although this call should never return to the caller, */
    /* we include a return to (a) avoid compiler warnings,   */
    /* and (b) anticipate potential reboot failure. (?!)     */
    /*-------------------------------------------------------*/
    return NOERROR;
}

/***********************************************************/
/***********************************************************/
/********* System Call 61: Read Ethernet frame.  ***********/
/***********************************************************/
/***********************************************************/
int _nicread(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int nicnum;
    char *buffp;
    int timeout;

    struct nic *pnic;			/* ptr to selected NIC */
    int i, bufndx, len;
    unsigned char *bufaddr;
    sem_t s;				/* read semaphore for the NIC */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    nicnum = args[0];
    buffp = (char *)args[1];
    timeout = args[2];

#if MAXNIC>0
    if (nicnum < 0 || nicnum >= _numnic) return NOSUCHNIC;
    if (buffp == NULL) return NULLPARM;

    activeProcess->timedOut = FALSE;

    pnic = _nicdev[nicnum];

    if (pnic->nic_speed == NIC_0) return NICINOP;	/* no operating */

    s = pnic->nic_readsem;

    /*----------------------------------------------*/
    /* Wait for a frame to be ready for consumption */
    /*----------------------------------------------*/
    if (down(s,timeout) == TIMEOUT) return TIMEOUT;

    /*--------------------/
    /* Deliver the frame */
    /*--------------------/
    /* assert: pnic->nic_ninq > 0 */
    bufndx = pnic->nic_inq[0].buffx;	/* get buffer index */
    bufaddr = pnic->inqbuff[bufndx];	/* get ptr to buffer */
    len = pnic->nic_inq[0].len;		/* get frame length */
    memcpy(buffp,bufaddr,len);		/* copy frame to user's buff */

    /*-------------------------------------------------------*/
    /* Move remaining entries up one position in the "queue" */
    /*-------------------------------------------------------*/
    for (i=1;i<pnic->nic_ninq;i++) {
	pnic->nic_inq[i-1].len = pnic->nic_inq[i].len;
	pnic->nic_inq[i-1].buffx = pnic->nic_inq[i].buffx;
    }

    /*---------------------------------*/
    /* Mark the buffer as free for use */
    /*---------------------------------*/
    pnic->bfree[bufndx] = 1;

    /*-------------------------------*/
    /* Reduce count of queued frames */
    /*-------------------------------*/
    pnic->nic_ninq--;

    /*---------------------------*/
    /* Return length to the user */
    /*---------------------------*/
    return len;

#else
    return NONETSUP;
#endif
}

/************************************************************/
/************************************************************/
/********* System Call 62: Write Ethernet frame.  ***********/
/************************************************************/
/************************************************************/
int _nicwrite(int *args)
{
    /*------------------------*/
    /* System call parameters */
    /*------------------------*/
    int nicnum;
    char *buffp;
    size_t len;

    struct nic *pnic;			/* ptr to selected NIC */
    sem_t s;				/* NIC's write semaphore */

    /*------------------------------------*/
    /* Extract the system call parameters */
    /*------------------------------------*/
    nicnum = args[0];
    buffp = (char *)args[1];
    len = args[2];

    if (nicnum < 0 || nicnum >= _numnic) return NOSUCHNIC;
    if (buffp == NULL) return NULLPARM;
    if (len < 60 || len > 1514) return BADVAL;

    pnic = _nicdev[nicnum];
    if (pnic->nic_speed == NIC_0) return NICINOP;

    s = pnic->nic_writesem;

    /*-------------------------*/
    /* Wait until we can write */
    /*-------------------------*/
    down(s,INFINITE);		/* (we could add a timeout parameter) */

    /*-----------------*/
    /* Start the write */
    /*-----------------*/
    (*pnic->nic_write)(pnic,buffp,len);

    return NOERROR;
}

/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/
/*    E N D   O F   S Y S T E M   C A L L   I M P L E M E N T A T I O N    */
/*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*/

/***************************************************************/
/* Each function appearing below this point is used to support */
/* the system calls. They are NOT system calls by themselves,  */
/* and are not intended to be called from user processes.      */
/***************************************************************/

/***************************************/
/* Load an ELF format executable file. */
/***************************************/
int loadELF(int fd, unsigned int ptndx, unsigned int *seglen)
{
    struct elf_hdr ehdr;	/* ELF file header */
    struct elf_phdr phdr;	/* program header element */
    unsigned int virt_end;
    int i, j, n, nleft, nr;
    unsigned int offset, pg_start, pg_end, maxpg;
    unsigned int *pte;		/* ptr to page table entry */
    unsigned int *np;		/* ptr to newly allocated page */
    struct Proc *p;		/* ptr to proctab entry */
    unsigned int va;
    unsigned int pgoff;

    p = &proctab[ptndx];
    seglen[1] = seglen[2] = 0;	/* code, data pages */
    maxpg = 0;			/* max page number used */

    seek(fd,0,0);		/* "rewind" the file */

    n = read(fd,(char *)&ehdr,sizeof(struct elf_hdr));
    if (n != sizeof(struct elf_hdr)) return BADEXEC;
    if (ehdr.magic != 0x464c457f) return BADEXEC;
    if (ehdr.endian != 1) return BADEXEC;
    if (ehdr.elf_ver_1 != 1) return BADEXEC;
    if (ehdr.file_type != 2) return BADEXEC;
    if (ehdr.machine != 3) return BADEXEC;
    if (ehdr.elf_ver_2 != 1) return BADEXEC;
    p->staddr = ehdr.entry;

    /*---------------------------------*/
    /* Now process the program headers */
    /*---------------------------------*/
    seek(fd,ehdr.phtab_offset,0);
    for (i=0;i<ehdr.num_ph;i++) {
	n = read(fd,(void *)&phdr,sizeof(struct elf_phdr));
	if (n != sizeof(struct elf_phdr))
	    return BADEXEC;
	if (phdr.type == PT_DYNAMIC)
	    return BADEXEC;
	if (phdr.type == PT_SHLIB)
	    return BADEXEC;
	if (phdr.type != PT_LOAD)	/* ignore all others */
	    continue;

	/*--------------------------------------------------------*/
	/* 'virt_adr' = location at which data at 'offset' is to  */
	/* be loaded. 'mem_size' indicates size of region. It can */
	/* be larger than 'disk_size', the number of bytes to be  */
	/* copied from the file. In this case, the extra bytes    */
	/* are to be zeroed.                                      */
	/*--------------------------------------------------------*/
	/* Verify the virtual start and end addresses are allowed */
	/* in the region. Then verify that memory is allocated or */
	/* allocate it as necessary, and load the code/data.      */
	/*--------------------------------------------------------*/
	if (kd_Flag & DEBUG_ELF) {
	    dprintf("Loading ELF-format file section.\n");
	    dprintf("  VMA = 0x%08x\n", phdr.virt_adr);
	    dprintf("  Size = 0x%08x\n", phdr.mem_size);
	    dprintf("  Disk = 0x%08x\n", phdr.disk_size);
	}

	pte = p->ptaddr;
	if (phdr.virt_adr < USERVMA)
	    return NOMEM;
	virt_end = phdr.virt_adr + phdr.mem_size - 1;
	if (virt_end >= USERVMA + 0x400000)
	    return NOMEM;
	pg_start = (phdr.virt_adr - USERVMA) >> 12;
	pg_end = (virt_end - USERVMA) >> 12;
	if (pg_end > maxpg)
	    maxpg = pg_end;
	offset = seek(fd,0,1);		/* get current position */

	/*---------------------------------------------*/
	/* Allocate the pages needed for this section. */
	/*---------------------------------------------*/
	for (j=pg_start;j<=pg_end;j++) {
	    if (pte[j] != 0)		/* already allocated */
		continue;
	    np = allocpage(ptndx,1);
	    if (np == NULL) {
		freeptents(p->ptaddr);	/* free all allocated mem */
		return NOMEM;
	    }
	    pte[j] = (unsigned int)np;
	    if (phdr.flags & PF_X)	/* code page */
		seglen[1]++;
	    else			/* data page */
	        seglen[2]++;
	}

	/*----------------------------------------*/
	/* Copy the section contents into memory. */
	/*----------------------------------------*/
	seek(fd,phdr.offset,0);
	nleft = phdr.disk_size;		/* bytes left to load */
	j = pg_start;
	va = phdr.virt_adr;
	while (nleft > 0) {
	    pgoff = va & 0xfff;		/* starting offset to load in page */
	    nr = 0x1000 - pgoff;	/* # bytes to load in this page */
	    if (nr > nleft)
		nr = nleft;
	    n = read(fd,(void *)(((unsigned int)pte[j])+pgoff),nr);
	    if (n != nr) {
		freeptents(p->ptaddr);
		return BADEXEC;		/* actually some I/O problem */
	    }
	    nleft -= nr;
	    j++;
	    va += nr;
	}
	seek(fd,offset,0);		/* return to phdr table */
    }

    p->brkbase = (char *)((maxpg + 1) * 0x1000 + USERVMA);
    p->brkcurr = p->brkbase;

    /*------------------------------------------------*/
    /* Allocate and clear one page for the user stack */
    /*------------------------------------------------*/
    pte = p->ptaddr + 1023;		/* pte points to last word in pagetbl */
    np = allocpage(ptndx,1);
    if (np == NULL) {
	freeptents(p->ptaddr);	/* free all allocated mem */
	return NOMEM;
    }
    *pte = (unsigned int)np;

    return NOERROR;
}

/*************************************/
/* Load a PE format executable file. */
/*************************************/
int loadPE(int fd, unsigned int ptndx, unsigned int *seglen)
{
    int i, j, n, nleft, nr;
    unsigned int offset, pg_start, pg_end, maxpg;
    unsigned int imagebase;	/* preferred virtual load address */
    unsigned int pgoff;
    unsigned int virt_end;	/* ending virtual address */
    unsigned int *pte;		/* ptr to page table entry */
    unsigned int *np;		/* ptr to newly allocated page */
    struct Proc *p;		/* ptr to proctab entry */
    unsigned int va;
    unsigned int pesigoff;	/* file offset to PE signature */
    unsigned int fileoff;	/* file offset (for various purposes) */
    unsigned short machine;	/* for which machine was file prepared? */
    unsigned short nsect;	/* # of sections in file */
    unsigned char *fp;		/* ptr to file contents */
    unsigned char buff[512];	/* small buffer for reading file */
    struct pesecthdr *sh;	/* ptr to a section header */

    p = &proctab[ptndx];
    seglen[1] = seglen[2] = 0;	/* code, data pages */
    maxpg = 0;			/* max page number used */
    pte = p->ptaddr;

    seek(fd,0,0);		/* "rewind" the file */

    n = read(fd,buff,512);
    if (n != 512) return BADEXEC;

dprintf("Checking for MZ\n");
    if (buff[0] != 'M' || buff[1] != 'Z') return BADEXEC;  /* no DOS-header */

    pesigoff = *(unsigned short *)&buff[60];

    fp = &buff[pesigoff];

dprintf("Checking for PE signature\n");
    if (*(unsigned long *)fp != 0x00004550) return BADEXEC;

    machine = *(unsigned short *)(fp+4);
    if (machine < 0x014c || machine > 0x14e) return BADEXEC;

    nsect = *(unsigned short *)(fp+6);

dprintf("Checking for executable bit in 'Characteristics'\n");
    /* Check for executable bit in 'Characteristics' */
    if ((*(unsigned short *)(fp+22) & 0x02) == 0) return BADEXEC;

dprintf("Checking for magic number\n");
    /* Check for 'magic' number */
    if (*(unsigned short *)(fp+24) != 0x010b) return BADEXEC;

    /* Get the starting address; convert from RVA to VA */
    p->staddr = *(unsigned long *)(fp+40) + USERVMA;

    /* Get the preferred image base address */
    imagebase = *(unsigned long *)(fp+52);

    /*------------------------------------------------------*/
    /* WE REQUIRE THE IMAGE BASE ADDRESS TO MATCH 'USERVMA' */
    /*------------------------------------------------------*/
dprintf("Checking for proper image base address\n");
dprintf("    USERVMA = 0x%08x, imagebase = 0x%08x\n", USERVMA, imagebase);
    if (imagebase != USERVMA) return BADEXEC;

    /* Process the sections */
    fileoff = pesigoff + 248;	/* is this ALWAYS correct? */
    sh = (struct pesecthdr *)buff;
    for (i=0;i<nsect;i++) {
	seek(fd,fileoff,0);		/* seek to the header */
	n = read(fd,(void *)sh,sizeof(struct pesecthdr)); /* read header */
	if (n != sizeof(struct pesecthdr)) {
	    /* free up any pages we've allocated */
	    return BADEXEC;
	}
	if (sh->virtualsize == 0) continue;	/* nothing to load */

	virt_end = sh->virtualaddr + sh->virtualsize - 1;
	if (virt_end >= 0x400000) return NOMEM;
	pg_start = sh->virtualaddr >> 12;
	pg_end = virt_end >> 12;
	if (pg_end > maxpg) maxpg = pg_end;

	/* Allocate needed pages */
	for (j=pg_start;j<=pg_end;j++) {
	    if (pte[j] != 0) continue;		/* already allocated */
	    np = allocpage(ptndx,1);
	    if (np == NULL) {
		freeptents(p->ptaddr);	/* free all allocated mem */
		return NOMEM;
	    }
	    pte[j] = (unsigned int)np;
	    if (sh->characteristics & 0x20000000) seglen[1]++;	/* code */
	    else seglen[2]++;				/* data page */
	}

	/* Load the section's content into memory */
	seek(fd,sh->ptrtorawdata,0);
	nleft = sh->sizeofrawdata;		/* bytes left to load */
	j = pg_start;
	va = sh->virtualaddr;
	while (nleft > 0) {
	    pgoff = va & 0xfff;		/* starting offset to load in page */
	    nr = 0x1000 - pgoff;	/* # bytes to load in this page */
	    if (nr > nleft) nr = nleft;
	    n = read(fd,(void *)(((unsigned int)pte[j])+pgoff),nr);
	    if (n != nr) {
		freeptents(p->ptaddr);
		return BADEXEC;		/* actually some I/O problem */
	    }
	    nleft -= nr;
	    j++;
	    va += nr;
	}

	fileoff += sizeof(struct pesecthdr);
    }

    p->brkbase = (char *)((maxpg + 1) * 0x1000 + 0x08000000);
    p->brkcurr = p->brkbase;

    /*------------------------------------------------*/
    /* Allocate and clear one page for the user stack */
    /*------------------------------------------------*/
    pte = p->ptaddr + 1023;	/* pte points to last page table entry */
    np = allocpage(ptndx,1);
    if (np == NULL) {
	freeptents(p->ptaddr);	/* free all allocated mem */
	return NOMEM;
    }
    *pte = (unsigned int)np;	/* save core addr of stack page in page tbl */

    return NOERROR;
}

/*********************************************/
/* Compute a checksum of user virtual memory */
/*********************************************/
unsigned int uservmck(struct Proc *p)
{
    unsigned int *page;		/* pointer to a page */
    unsigned int ck;
    int i, j;

    ck = 0;
    for (i=0;i<1024;i++) {	/* checksum all allocated pages */
	page = (unsigned int *)((unsigned int)p->ptaddr[i] & ~0xfff);
	if (page == 0) continue;
	for (j=0;j<1024;j++) ck += page[j];
    }
    return ck;
}

/**************************************************************/
/* Schedule asynchronous read/write for the block with buffer */
/* cache entry at b. Do not block.                            */
/**************************************************************/
/* Asynchronous requests are identified by a 'proc' value of  */
/* zero. In such cases, the 'buffer' pointer in the request   */
/* is really the pointer to the bufhd for the cache entry.    */
/* When a write completes, the buffer is marked clean and is  */
/* released (which could wakeup processes waiting on a free   */
/* buffer). When a read completes, processes waiting on the   */
/* event corresponding to the address of the bufhd struct are */
/* awakened.                                                  */
/**************************************************************/
void _asynchio(int rw, struct bufhd *b)
{
    if (!_diskpresent) return;		/* probably should not happen */
    if (IOfree == NULL) quit("Out of I/O request buffers!");
    request = IOfree;
    IOfree = IOfree->next;
    if (rw == 0) request->op = DSK_READ;
    else request->op = DSK_WRITE;
    spc = nheads * nsects;                      /* sectors per cylinder */
    request->xc = b->blockno / spc;             /* cylinder */
    request->xh = (b->blockno % spc) / nsects;  /* head */
    request->xs = b->blockno % nsects + 1;      /* sector */
    request->nblk = 1;				/* XXX for now, 1 block */
    request->buffer = b->data;
    request->bh = b;
    request->proc = (Process)0;			/* flag as asynch I/O rqst */
    request->next = NULL;
    b->status |= BCS_IOACT;			/* show I/O active for block */

    needstart = (IOhead == NULL);
    if (needstart) IOhead = IOtail = request;
    else {
	IOtail->next = request;
	IOtail = request;
    }
    if (needstart) startdiskcmd();
}

/*************************************************************************/
/* Wait for disk controller not busy. Return 0 on success, 1 on timeout. */
/*************************************************************************/
#define WNBPERIOD 0x1000000		/* XXX */
#define WDRQPERIOD 0x1000000
int waitnotbusy(void)
{
    int i;
    unsigned char st;			/* status register value */

    for (i=0;i<WNBPERIOD;i++) {
	st = inb(DSK_BASE + DSK_STATUS);
	if (st & DSK_BUSY) continue;
	return 0;
    }
    return 1;
}
    
/*****************************************************************/
/* Start a disk command for the request at the head of the queue */
/*****************************************************************/
static void startdiskcmd(void)
{
    if (waitnotbusy()) {
	kprintf("Disk controller timeout before command start\r\n");
xx1: goto xx1;
    }
    outb(DSK_BASE + DSK_HEAD,0xa0 + IOhead->xh);
    if (waitnotbusy()) {
	kprintf("Disk controller timeout after drive select\r\n");
xx2: goto xx2;
    }
    outb(DSK_BASE + DSK_CTL, 0x80);	/* disable retries, enable interrupts */
    outb(DSK_BASE + DSK_PRECOMP, 0);
    outb(DSK_BASE + DSK_COUNT, 1);
    outb(DSK_BASE + DSK_SECTOR, IOhead->xs);
    outb(DSK_BASE + DSK_CYLLO, IOhead->xc & 0xff);
    outb(DSK_BASE + DSK_CYLHI, IOhead->xc >> 8);
    outb(DSK_BASE + DSK_CMD, IOhead->op);

    /*----------------------------------------------------------------*/
    /* For a write command, wait for the status register (DSK_STATUS) */
    /* to include the DSK_DRQ bit, indicating data is requested. Then */
    /* copy data to the I/O port.                                     */
    /*----------------------------------------------------------------*/
    if (IOhead->op == DSK_WRITE) {
	for(;;) {		/* for real drives, we'll need a timeout */
	    iostat = inb(DSK_BASE + DSK_STATUS) & DSK_DRQ;
	    if (iostat == DSK_DRQ) break;
	}
	_port_write(DSK_BASE + DSK_DATA, IOhead->buffer, 512);
	/* Wait for an interrupt */
    }
}

/*****************************************************************/
/*                Delta Queue Management Functions               */
/*---------------------------------------------------------------*/
/* "Delta queues" are similar to the callout queues in UNIX-like */
/* systems in that each queue entry contains a delay time, the   */
/* necessary queue links, and the identification of some code to */
/* be executed when the specified delay has occurred.  In Tempo, */
/* the delays are in units of "ticks," or system timer clock     */
/* interrupt intervals (about 18.2 per second).  Instead of      */
/* identifying a function to be executed (as in UNIX), Tempo's   */
/* delta queue elements (DQEs) identify a blocked process that   */
/* is to be made ready when the specified time has elapsed.      */
/* The queue is ordered from the entry with the shortest delay   */
/* to the entry with the longest delay.  The 'delta' field in    */
/* each queue entry is the number of ticks that should elapse    */
/* after the process identified in the previous DQE entry is     */
/* reactivated.                                                  */
/*****************************************************************/

struct DQE {
    Process p;              /* identifies the PD of the blocked process */
    struct DQE *next;       /* identifies the next DQE on the sleep queue */
    unsigned int delta;     /* how many ticks until p becomes ready */
};

/*****************************************************************/
/* Add the process with PD at p to the sleepq with delay = delta */
/* It is expected that interrupts are disabled during execution. */
/*****************************************************************/
static void DeltaEnqueue (Process p, unsigned int delta)
{
    Process current, old;

    p->eventaddr = 0;
    p->dnext = NULL;
    p->delta = delta;

    /*--------------------------------*/
    /* Add the new entry to the queue */
    /*--------------------------------*/
    if (sleepq == NULL) sleepq = p;   /* if previously empty */

    else {
	current = sleepq;
	old = NULL;

	while (current != NULL && current->delta < p->delta) {
	    p->delta = p->delta - current->delta;
	    old = current;
	    current = current->dnext;
	}

	/*--------------------*/
	/* New head of queue? */
	/*--------------------*/
	if (old == NULL) {
	    if (current->delta < p->delta) {
		/* Insert after first entry */
		p->delta = p->delta - current->delta;
		p->dnext = current->dnext;
		current->dnext = p;
	    } else {
		/* Insert before first entry */
		current->delta = current->delta - p->delta;
		p->dnext = current;
		sleepq = p;
	    }

	/*------------------------*/
	/* New last sleepq entry? */
	/*------------------------*/
	} else if (current == NULL) old->dnext = p;

	/*-------------------------*/
	/* Somewhere in the middle */
	/*-------------------------*/
	else {
	    current->delta = current->delta - p->delta;
	    old->dnext = p;
	    p->dnext = current;
	}
    }
}

/*****************************************************/
/* Remove and return the first element in the sleepq */
/* if its delta is zero.  Otherwise return NULL.     */
/* Caller guarantees interrupts are disabled.        */
/*****************************************************/
Process DeltaDequeue (void)
{
    Process current;

    current = sleepq;                   /* start at the head of the queue */
    if (current != NULL) {              /* Is there an entry on the queue? */
	if (current->delta == 0) {      /* and is it's delta zero? */
	    sleepq = current->dnext;    /* Yes! Adjust the sleepq ptr */
	    return current;		/* return process ID */
	}
    }

    return NULL;			/* no entries ready for wakeup */
}

/*********************************************************************/
/* Remove the DQE for the process with PD at p from the sleep queue. */
/* Return 0 on success and 1 otherwise.  This function is used to    */
/* cancel the timeout action for processes that were blocked as a    */
/* result of a wait, receive, or down call with a finite             */
/* timeout specified, and that were subsequently made ready by the   */
/* operation succeeding before the timeout occurred. It is also used */
/* by the kill() system call to remove processes being terminated    */
/* from the delta queue.                                             */
/*********************************************************************/
unsigned int _DeltaRemoveElement (Process p)
{
    unsigned int status;                /* 1 if p not found in sleepq */
    Process prev, nextp, current;

    status = 1;
    current = sleepq;                   /* start at the top of the queue */
    prev = NULL;

    while (current != NULL) {
	if (current == p) {             /* is this the one to remove? */
	    status = 0;                 /* yes */
	    if (prev == NULL) sleepq = current->dnext;
	    else prev->dnext = current->dnext;
	    nextp = current->dnext;
	    if (nextp != NULL) nextp->delta = nextp->delta + current->delta;
	    break;
	} else {
	    prev = current;             /* no -- keep going */
	    current = current->dnext;
	}
    }
    return status;
}

/***********************************/
/* Display the system boot message */
/***********************************/
void _bootmsg(void)
{
    _vtxt("Tempo, version ");
    _vtxt(VERSION);
    _vtxt(" (");
    _vtxt(SYSDATE);
    _vtxt(")\r\n\r\n");
}

/*********************************************************************/
/*********************************************************************/
/* tempo - setup idle and Main processes, then run the Main process. */
/* Interrupts are disabled on entry.                                 */
/*********************************************************************/
/*********************************************************************/
void tempo(void)
{
    int i;
    unsigned int r;
    Process p;
    unsigned int *ksp;		/* kernel stack pointer */
    unsigned int *usp;		/* user stack pointer */
    unsigned int *user_esp_loc;

    /*------------------------------------------*/
    /* Mark all process table entries as unused */
    /*------------------------------------------*/
    for (i=0;i<NPROC;i++) {
	proctab[i].tag = TAG_PROCESS;
	proctab[i].state = PROCESS_FREE;
    }

    /*----------------------------------------------------------*/
    /* Allocate semaphore with index 0 to support the CS macro. */
    /*----------------------------------------------------------*/
    _semtab[0].tag = TAG_SEMAPHORE;
    _semtab[0].count = 1;
    _semtab[0].head = _semtab[0].tail = NULL;
    Tempo_mutex = 1;	/* NB. Semaphore IDs are one larger than index */

    /*--------------------------------------------------------------*/
    /* Allocate semaphores with indices 1..NVPG to block callers if */
    /* no keyboard input is available.                              */
    /*--------------------------------------------------------------*/
    for (i=1;i<=NVPG;i++) {
	_semtab[i].tag = TAG_SEMAPHORE;
	_semtab[i].count = 0;
	_semtab[i].head = _semtab[i].tail = NULL;
    }
    _keysem = 2;		/* sem_t value (semaphore ID) for console 0 */

    /*-------------------------------------------------------*/
    /* Mark remaining semaphores as available for allocation */
    /*-------------------------------------------------------*/
    for (; i<NSEMA; i++) {
	_semtab[i].tag = TAG_SEMAPHORE;
	_semtab[i].count = -1;		/* -1 means semaphore available */
    }

    /*---------------------------------------------------------------*/
    /* Initialize frstkey and nxtkey for each console's input buffer */
    /*---------------------------------------------------------------*/
    for (i=0;i<NVPG;i++) frstkey[i] = nxtkey[i] = 0;

    /*------------------------------------------------*/
    /* Initialize actcon and the vidcol/vidrow arrays */
    /*------------------------------------------------*/
    actcon = 0;
    for (i=0;i<NVPG;i++) vidrow[i] = vidcol[i] = 0;
    vidrow[0] = 1;		/* 2007.02.08 SAW */

    /*-----------------------------------------------------------*/
    /* Initialize edited keyboard input buffers, one per console */
    /*-----------------------------------------------------------*/
    for (i=0;i<NVPG;i++) {
	rdl[i].rdllen = 0;
	rdl[i].rdlleft = 0;
	rdl[i].rdlndx = 0;
	rdl[i].rdldw = 0;
	rdl[i].rdlnt = 0;
    }

    /*------------------------------------------*/
    /* Create a pool of available message nodes */
    /*------------------------------------------*/
    for (i=0; i<NMSGS; i++) {
	msgtab[i].tag = TAG_MSGNODE;
	msgtab[i].sender = NULL;
    }

    /*--------------------------------*/
    /* Clear the ready process queues */
    /*--------------------------------*/
    for (i=0;i<PRIORITY_LEVELS;i++) {
	readyList[i].tag = TAG_RDYQ;
	readyList[i].head = NULL;
	readyList[i].tail = NULL;
    }

    /*---------------------------------------*/
    /* Mark all entries in the shmtab unused */
    /*---------------------------------------*/
    for (i=0;i<NSHMEM;i++)
	_shmtbl[i].nrefs = 0;

    _diskpresent = _fspresent = 0;	/* assume no disk or filesystem */
    maxblk = 0;


#ifdef ENABLEDISK
    /*--------------------------------------------------------*/
    /* Determine if a disk is present, and if so, get the CHS */
    /* information and determine if a filesystem is present.  */
    /*--------------------------------------------------------*/
    r = inb(DSK_BASE + DSK_CYLLO);		/* get current value */
    outb(DSK_BASE + DSK_CYLLO,~r);		/* write different value */
    if (inb(DSK_BASE + DSK_CYLLO) != r) {	/* if it changed... */
	unsigned char buff[512];		/* temporary buffer */

	_diskpresent = 1;			/* mark it present */


	/*-----------------------------------------------*/
	/* Build a queue of free disk I/O request blocks */
	/*-----------------------------------------------*/
	for (i=0;i<NDISKRQ;i++) {
	    if (i == NDISKRQ-1) IORQ[i].next = NULL;	/* last link is NULL */
	    else IORQ[i].next = &IORQ[i+1];	/* others point to successor */
	}
	IOfree = &IORQ[0];			/* ptr to 1st free IOreq */

	outb(DSK_BASE + DSK_CTL, 0x04);		/* reset the controller */
	for (i=0;i<100000;i++) { i = i + 1; i = i - 1; }	/* delay */
	outb(DSK_BASE + DSK_CTL, 0x00);

	/*-------------------------------------------------*/
	/* Identify disk params (assume an ATA controller) */
	/*-------------------------------------------------*/
	if (waitnotbusy())
	    quit("Disk controller timeout before identify command");
	outb(DSK_BASE + DSK_HEAD,0xa0);
	if (waitnotbusy())
	    quit("Disk controller timeout after identify disk select");
	outb(DSK_BASE + DSK_CTL, 0x82);		/* no interrupts */
	outb(DSK_BASE + DSK_PRECOMP, 0);
	outb(DSK_BASE + DSK_COUNT, 1);
	outb(DSK_BASE + DSK_SECTOR, 1);
	outb(DSK_BASE + DSK_CYLLO, 0);
	outb(DSK_BASE + DSK_CYLHI, 0);
	outb(DSK_BASE + DSK_CMD, DSK_IDENTIFY);

	/*--------------*/
	/* Wait for DRQ */
	/*--------------*/
	for(i=0;i<WDRQPERIOD;i++) {
	    r = inb(DSK_BASE + DSK_STATUS) & DSK_DRQ;
	    if (r == DSK_DRQ) break;
	}
	if (i == WDRQPERIOD) quit("Timeout waiting for DRQ");

	/*------------------------------------------------------*/
	/* Get the data and extract the desired CHS information */
	/*------------------------------------------------------*/
	_port_read(DSK_BASE + DSK_DATA, buff, 512);
	ncyls = (buff[3] << 8) | buff[2];
	nheads = (buff[7] << 8) | buff[6]; 
	nsects = (buff[13] << 8) | buff[12];
	maxblk = ncyls * nheads * nsects;

	/*-----------------------------------*/
	/* Check for a filesystem's presence */
	/*-----------------------------------*/
	if (waitnotbusy())
	    quit("Disk controller timeout before non-int read command");
	outb(DSK_BASE + DSK_HEAD,0xa0);
	if (waitnotbusy())
	    quit("Disk controller timeout after non-int read command");
	outb(DSK_BASE + DSK_CTL, 0x82);		/* no interrupts */
	outb(DSK_BASE + DSK_PRECOMP, 0);
	outb(DSK_BASE + DSK_COUNT, 1);
	outb(DSK_BASE + DSK_SECTOR, 1);
	outb(DSK_BASE + DSK_CYLLO, 0);
	outb(DSK_BASE + DSK_CYLHI, 0);
	outb(DSK_BASE + DSK_CMD, DSK_READ);

	for(;;) {	/* wait for DRQ - for real drives add a timeout */
	    r = inb(DSK_BASE + DSK_STATUS) & DSK_DRQ;
	    if (r == DSK_DRQ) break;
	}

	/*------------------------------------*/
	/* Get the data and check for FSIDENT */
	/*------------------------------------*/
	_port_read(DSK_BASE + DSK_DATA, &sblk, 512);
	if (!strcmp((char *)&sblk,FSIDENT)) {
	    _fspresent = 1;
	    _initbc();			/* initialize buffer cache */
	}

	outb(DSK_BASE + DSK_CTL, 0x04);		/* reset the controller */
	for (i=0;i<100000;i++) { i = i + 1; i = i - 1; }	/* delay */
	outb(DSK_BASE + DSK_CTL, 0x00);
    }
#endif

#if MAXNIC>0
    enetinit();				/* scan for & initialize Enet NICs */
#endif

    numprocesses = 0;			/* no processes yet */
    sleepq = NULL;			/* no sleeping processes */
    awakeq = NULL;			/* none waiting on RTC alarms either */
    IOhead = IOtail = NULL;		/* no disk I/O requests pending */
    nextpid = 0;			/* pid for first process */

    /*--------------------------------------*/
    /* Setup the idle process in proctab[0] */
    /*--------------------------------------*/
    p = &proctab[0];
    p->ptaddr = 0;
    p->kstkbase = (unsigned int *)allocStack(1,0);	/* kernel stack */
    ksp = p->kstkbase;
    p->kstkbase++;

    *ksp-- = USER_DATA_SEL;		/* ss */
    *ksp = (unsigned int)allocStack(1,0); /* esp = user stack base */
    p->stkbase = (unsigned int *)*ksp;
    ksp--;
    *ksp-- = 0x200;			/* eflags */
    *ksp-- = USER_CODE_SEL;		/* cs */
    *ksp-- = (unsigned int)idle;	/* eip */

    *ksp-- = 0xffffffff;		/* mirror item pushed on kernel entry */

    *ksp-- = USER_DATA_SEL;		/* gs */
    *ksp-- = USER_DATA_SEL;		/* fs */
    *ksp-- = USER_DATA_SEL;		/* es */
    *ksp-- = USER_DATA_SEL;		/* ds */

    *ksp-- = 0xaaaa0001;		/* eax */
    *ksp-- = 0xaaaa0002;		/* ecx */
    *ksp-- = 0xaaaa0003;		/* edx */
    *ksp-- = 0xaaaa0004;		/* ebx */
    *ksp-- = 0xaaaa0005;		/* esp (ignored later) */
    *ksp-- = 0xaaaa0006;		/* ebp */
    *ksp-- = 0xaaaa0007;		/* esi */
    *ksp   = 0xaaaa0008;		/* edi */

    p->stksize = 1;
    p->ksp = ksp;
    p->priority = -1;
    p->pid = nextpid++;
    *(unsigned int *)(p->stkbase) = (unsigned int)processDone;
    numprocesses++;
    _addready(p);
    /*------------- END OF IDLE PROCESS SETUP -------------*/



    /*------------- Setup Main in proctab[1] --------------*/
    p = &proctab[1];		/* Main always has pid 1 */
    p->ptaddr = 0;		/* and it doesn't have its own page table */

    /*--------------------------------------------------------------*/
    /* Setup the kernel stack for this process. This must look just */
    /* as if the process was about to return from a system call.    */
    /*--------------------------------------------------------------*/
    p->kstkbase = (unsigned int *)allocStack(1,1); /* allocate kernel stack */
    ksp = p->kstkbase;		/* ksp is a "utility" pointer to it */
    p->kstkbase++;

    *ksp-- = USER_DATA_SEL;	/* ss: user stack seg selector */
    user_esp_loc = ksp;		/* save loc of user's esp in kstk for later */
    ksp--;

#ifdef NONO
    *ksp = (unsigned int)allocStack(1,1);	/* esp */
    p->stkbase = (unsigned int *)*ksp--;
#endif
    *ksp-- = 0x200;		/* eflags */
    *ksp-- = USER_CODE_SEL;	/* cs */
    *ksp-- = (unsigned int)Main;/* eip */

    *ksp-- = 0xffffffff;	/* mirror item pushed on kernel entry */

    *ksp-- = USER_DATA_SEL;	/* gs */
    *ksp-- = USER_DATA_SEL;	/* fs */
    *ksp-- = USER_DATA_SEL;	/* es */
    *ksp-- = USER_DATA_SEL;	/* ds */

    *ksp-- = 0xbbbb0001;	/* eax */
    *ksp-- = 0xbbbb0002;	/* ecx */
    *ksp-- = 0xbbbb0003;	/* edx */
    *ksp-- = 0xbbbb0004;	/* ebx */
    *ksp-- = 0xbbbb0005;	/* esp (ignored later) */
    *ksp-- = 0xbbbb0006;	/* ebp */
    *ksp-- = 0xbbbb0007;	/* esi */
    *ksp   = 0xbbbb0008;	/* edi */

    for (i=0;i<2;i++) {		/* file descriptors 0/1 => console */
	p->fd[i].how = -1;
	p->fd[i].fdescnr = 1;	/* Main's console descriptors are cooked */
    }
    for(i=2;i<NFD;i++)
	p->fd[i].fdescnr = -1;	/* other descriptors are available */

    p->stksize = 1;		/* Main's user stack always 1 page long */
    p->ksp = ksp;		/* kernel stack pointer */
    p->priority = 0;		/* Main always begins at priority 0 */
    p->pid = nextpid++;		/* Main's pid */

    /*-------------------------------------------------------------------*/
    /* User stack setup. Although Main is invoked with no "command line" */
    /* arguments, we want it to be "congruent" with other processes.     */
    /* It should thus have an argc and argv argument, each equal to 0.   */
    /* These will be expected to appear on the stack just above (before) */
    /* the return address. We need to allocate the user stack, place the */
    /* appropriate values in it, and put the appropriate value in the    */
    /* kernel stack to "restore" when the process begins execution.      */
    /* So Main's user stack should look like this:                       */
    /*									 */
    /*    +-------+							 */
    /*    |   0   |	NULL pointer (for argv); p->stkbase points here	 */
    /*    +-------+							 */
    /*    |   0   |	argc						 */
    /*    +-------+							 */
    /*    |  xxx  |	"return" address (processDone)			 */
    /*    +-------+							 */
    /*									 */
    /*-------------------------------------------------------------------*/

    p->stkbase = allocStack(1,1);	/* allocate user stack */

    usp = p->stkbase;
    *usp-- = 0;		/* NULL pointer to argv array of string addrs */
    *usp-- = 0;		/* number of string arguments */
    *usp = (unsigned int)processDone;	/* "return" address */

    /*----------------------------------------------------------------*/
    /* Now patch the kernel stack location that points to the "saved" */
    /* user stack pointer (esp) value. This will be "restored" when   */
    /* the process begins execution.                                  */
    /*----------------------------------------------------------------*/
    *user_esp_loc = (unsigned int)usp;

    numprocesses++;
    _addready(p);

    /*--------------------------------------------------------------*/
    /* Perhaps later...                                             */
    /* If we have any Ethernet NICs in the system, start threads to */
    /* handle TCP/IP processing.                                    */
    /* Of course, a more appropriate approach would be to have the  */
    /* Main process handle the startup of these things based on a   */
    /* script (similar to the technique used in UNIX, for example). */
    /*--------------------------------------------------------------*/

    activeProcess = NULL;
    xmain();			/* never returns */
}

/*****************************************************/
/* Called after clock tick counter incremented.      */
/* This code runs at CPL 0 with interrupts disabled. */
/*****************************************************/
void _timerisr(void)
{
    Process wakeUp;

    if (_time_limit > 0 && _nticks >= _time_limit)
	quit("System execution time limit exceeded.");

#ifdef VALIDATE
    if (activeProcess != NULL) {
	if (activeProcess->tag != TAG_PROCESS) {
	    kprintf("timerisr: activeProcess = 0x%x\r\n", activeProcess);
	    quit("timerisr: bad activeProcess on entry");
	}
    }
#endif

    if (sleepq != NULL) --(sleepq->delta); /* reduce delta in first DQE */

    _rs = 0;			/* assume no context switch required */

    /*----------------------------------------------------------------*/
    /* Repeatedly dequeue entries at the head of the delta queue with */
    /* remaining tick counts of zero. If an entry was blocked on a    */
    /* semaphore, then remove it from the semaphore's queue. Put the  */
    /* process in the ready state on the appropriate queue. If the    */
    /* priority of an awakened process is greater than the process    */
    /* that was running when the clock interrupt occurred, then       */
    /* set _rs to force a context switch.                             */
    /*----------------------------------------------------------------*/
    while ((wakeUp = DeltaDequeue()) != NULL) {

#ifdef VALIDATE
	if (wakeUp->tag != TAG_PROCESS) quit("timerisr: bad process wakeup");
#endif

	/*----------------------------------------------*/
	/* If process timed out waiting on a semaphore, */
	/* then remove it from the semaphore's queue.   */
	/*----------------------------------------------*/
	if (wakeUp->state == SEM_TIMED_BLOCKED) {
	    Process prev, curr;
	    struct Sem *s;

	    s = (struct Sem *)wakeUp->queue;
	    prev = NULL;
	    curr = s->head;
	    while (curr != wakeUp) {
		prev = curr;
		curr = curr->next;
	    }
	    if (prev == NULL) s->head = curr->next;
	    else prev->next = curr->next;
	}

	/*---------------------------------------------*/
	/* Arrange for the process to wake up with the */
	/* appropriate return from the system call.    */
	/*---------------------------------------------*/
	wakeUp->timedOut = TRUE;
	wakeUp->badSema = FALSE;
	wakeUp->state = PROCESS_READY;
	_addready(wakeUp);

	/*----------------------------------------------*/
	/* Arrange for a context switch if the awakened */
	/* process' priority is greater than that of    */
	/* the currently active process.                */
	/*----------------------------------------------*/
	if (wakeUp->priority > activeProcess->priority) _rs = 1;
    }

    /*-------------------------------------------------------------*/
    /* Reduce the number of ticks remaining in the quantum for the */
    /* active process. If this is now zero (or negative??!!), then */
    /* force a context switch. Note that this test is done only    */
    /* AFTER all the blocked processes awakened as a result of the */
    /* clock tick have been moved to the appropriate ready queues. */
    /* This guarantees that waking a process P with the same       */
    /* priority as an active process A that experiences a quantum  */
    /* expiration at the same clock tick will put P ahead of A in  */
    /* the ready queue for their priority, letting P run before A. */
    /*-------------------------------------------------------------*/
    /* Note that we don't need to put a process with an expired    */
    /* quantum back into the ready queue here, since that's done   */
    /* later.                                                      */
    /*-------------------------------------------------------------*/
    if (_quantum > 0) {
	_ticks_left--;
	if (_ticks_left <= 0) {
	    qrunouts++;
	    _rs = 1;
	}
    }

    /*-----------------------------------------------*/
    /* If no context switch is required, just return */
    /*-----------------------------------------------*/
    if (_rs == 0) return;

    /*-------------------------------------------------*/
    /* Put the current process back in the ready queue */
    /*-------------------------------------------------*/
    if (activeProcess != NULL) {
	activeProcess->state = PROCESS_READY;
	_addready(activeProcess);
    }
    _ticks_left = _quantum;
}

/****************************************************************/
/* Queue Management Functions.                                  */
/* These are expected to run at CPL 0 with interrupts disabled. */
/****************************************************************/
/***********************************************************/
/* Add the process descriptor at p to the ready queue at q */
/***********************************************************/
static void enqueue (struct Queue *q, Process p)
{
    unsigned int eflags;
    int which;

#ifdef VALIDATE
    Process p0, p1;

    if (q->tag != TAG_RDYQ) quit("enqueue: argument not a ready queue");
    if ( (q->head == NULL && q->tail != NULL) ||
         (q->head != NULL && q->tail == NULL))
	 quit("enqueue: queue head/tail inconsistency on entry");
#endif

#ifdef VALIDATE
    p0 = q->head;
    while (p0 != NULL) {
	if (p0 == p) {
	    kprintf("enqueue: process at 0x%x (pid = %d)\r\n", p, p->pid);
	    kprintf("enqueue: process priority = %d\r\n", p->priority);
	    quit("enqueue: process already on queue");
	} else p0 = p0->next;
    }
#endif
    p->queue = q;                       /* Save "home queue" identity */
    p->next = NULL;                     /* always add at the end of the queue */
    if (q->head == NULL) {              /* if the queue was empty */
	which = 0;
	q->head = q->tail = p;
	p->prev = NULL;
    } else {                            /* or if the queue was not empty */
	which = 1;
	q->tail->next = p;
	p->prev = q->tail;
	q->tail = p;
    }
#ifdef VALIDATE
    /*---------------------------------------------------------------*/
    /* Verify that the forward and backward (next/prev) links "work" */
    /*---------------------------------------------------------------*/
    if (q->head != NULL) {
	p0 = q->head;
	while (p0 != NULL) {
	    p1 = p0->next;
	    if (p0 == p1) {
		kprintf("enqueue: q = 0x%x\r\n", q);
		kprintf("enqueue: p = 0x%x\r\n", p0);
		kprintf("enqueue: which = %d\n", which);
		quit("enqueue: circular list");
	    }
	    if (p1 == NULL) {
		if (q->tail != p0) quit("enqueue: bad tail pointer");
	    } else {
		if (p1->prev != p0) quit("enqueue: incorrect back pointer");
	    }
	    p0 = p1;
	}
    }
#endif
}

/******************************************/
/* Remove Process p from its queue        */
/* Caller guarantees interrupts disabled. */
/******************************************/
void removep (Process p)
{
    struct Queue *q;

#ifdef VALIDATE
    if (p->tag != TAG_PROCESS) {
	quit("removep: invalid argument");
    }
#endif
    q = p->queue;                       /* get the queue's identity */
    if (q == 0) {                       /* sanity check */
#ifdef NONO
	cldisk();
#endif
	quit("removep: null queue pointer");
    }

    /*--------------------------------------------------*/
    /* Adjust pointer in struct proc prior to that at p */
    /*--------------------------------------------------*/
    if (p->prev == NULL) q->head = p->next;
    else p->prev->next = p->next;

    /*---------------------------------------------------*/
    /* Adjust pointer in struct proc following that at p */
    /*---------------------------------------------------*/
    if (p->next == NULL) q->tail = p->prev;
    else p->next->prev = p->prev;

    /*----------------------------------------------------------*/
    /* "Sanitize" the pointers in the struct proc being removed */
    /*----------------------------------------------------------*/
    p->prev = p->next = NULL;
    p->queue = NULL;
}

/************************************************************/
/* Add struct proc at p to the list of ready processes.     */
/* Array 'readyList' is indexed by the process priority + 1 */
/* since a priority of -1 is used for the idle process.     */
/************************************************************/
void _addready (Process p)
{
#ifdef VALIDATE
    if (p->tag != TAG_PROCESS) quit("addready: invalid argument");
    if (p->priority < IDLE_PRIORITY) quit("addready: invalid priority");
    if (p->priority > HIGHEST_PRIORITY) quit("addready: invalid priority");
#endif
    p->state = PROCESS_READY;
    enqueue (&readyList[(p->priority)+1],p);
}

/************************************************************/
/* What should be done with this thing? It's somewhat weird */
/************************************************************/
/***********************/
/* Shutdown the system */
/***********************/
void quit(char *s)
{
    if (s != NULL) {
	kprintf("%s\r\n", s);
	dprintf("%s\n", s);
    }
    kprintf("System stop.\r\n");
    dprintf("System stop.\n");
    while(1) ;
}

/***************************************************************/
/* Select the highest-priority ready process, remove it from   */
/* its queue, and return a pointer to its process table entry. */
/* This should logically run with interrupts disabled.         */
/***************************************************************/
Process _getready(void)
{
    Process newProcess;
    int prio;

#ifdef VALIDATE
    for (prio = HIGHEST_PRIORITY; prio >= IDLE_PRIORITY; prio--) {
	if (readyList[prio+1].tag != TAG_RDYQ)
	    quit("getready: queue tag is invalid");
	if (readyList[prio+1].head == NULL &&
	    readyList[prio+1].tail != NULL)
		quit("getready: queue head is null but tail is not null");
	if (readyList[prio+1].head != NULL &&
	    readyList[prio+1].tail == NULL)
		quit("getready: queue head is null but tail is not null");
	if (readyList[prio+1].head != NULL) {
	    Process p0, p1;
	    struct Queue *q;

	    q = &readyList[prio+1];
	    p0 = q->head;
	    while (p0 != NULL) {
		if (p0->state != PROCESS_READY) {
		    kprintf("getready: process 0x%x (pid %d) not ready!\r\n",
			p0, p0->pid);
		    quit("getready: unready process on ready queue");
		}
		p1 = p0->next;
		if (p0 == p1) {
		    kprintf("getready: q = 0x%x\r\n", q);
		    kprintf("getready: p = 0x%x\r\n", p0);
		    quit("getready: circular list");
		}
		if (p1 == NULL) {
		    if (q->tail != p0) quit("enqueue: bad tail pointer");
		} else {
		    if (p1->prev != p0) quit("enqueue: incorrect back pointer");
		}
		p0 = p1;
	    }
	}
    }
#endif

    newProcess = NULL;
    for (prio = HIGHEST_PRIORITY; prio >= IDLE_PRIORITY; prio--) {
	if (readyList[prio+1].head == NULL) continue;
	newProcess = readyList[prio+1].head;
	if (newProcess->next == NULL) {
	    readyList[prio+1].head = NULL;
	    readyList[prio+1].tail = NULL;
	} else readyList[prio+1].head = newProcess->next;
	break;
    }

    if (newProcess == NULL) {
	kprintf("Idle process state is %d\r\n", proctab[0].state);
	kprintf("Active process; pid = %d, proctab at 0x%08x\r\n",
	    activeProcess->pid, activeProcess);
	kprintf("Reschedule flag is %d\r\n", _rs);
	kprintf("proc1 state is %d\r\n", proctab[1].state);
	kprintf("proc2 state is %d\r\n", proctab[2].state);
	kprintf("proc3 state is %d\r\n", proctab[3].state);
	quit("getready: no ready process found!\r\n");
    }

#ifdef VALIDATE
    if (newProcess->tag != TAG_PROCESS) quit("getready: bad process tag");
#endif

    return newProcess;
}

/***************************************************************************/
/* This function is "called" when a process returns from its root function */
/***************************************************************************/
/* This should (perhaps) be moved to kernel.s, thus eliminating the need */
/* for the "kludge" function geteax().                                   */
/*************************************************************************/
/* static */ void processDone(void)
{
    exit(geteax());
}

/*******************************************************************/
/* Technically, newproc is not a system call. Instead, it uses the */
/* newproca system call to create a new process with implied args. */
/*******************************************************************/
/******************************************************************/
/* Create a new process with default arguments (1 and "procNNNN") */
/******************************************************************/
/* Here's what the arguments must look like:                      */
/*    "procN" + a null byte                                       */
/*    padding (to a 4-byte boundary)                              */
/*    null (4 bytes of 0)                                         */
/*    address of "procN" (4 bytes)                                */
/*    1 (a 4-byte constant)                                       */
/* The argument pointer will point to the 'p' in "procN".         */
/******************************************************************/
pid_t newproc (int (*rootFnPtr)(void), int priority, unsigned stackSize)
{
    unsigned char arg[20];	/* should be large enough */
    unsigned char *a[2];

    a[0] = arg;
    a[1] = NULL;
    strcpy(arg,"proc");
    itoa(nextpid,arg+4);	/* install procID + null */
    return newproca(rootFnPtr,priority,stackSize,1,a);
}

/********************/
/* The idle process */
/********************/
int idle(void)
{
    while (1) ;
}

/**************************************/
/* Second-level RTC interrupt handler */
/**************************************/
void _rtcisr(void)
{
    unsigned char statusB;
    unsigned char curhr, curmin, cursec;
    unsigned char val;
    unsigned char resched = 0;
    unsigned int curtime;
    struct Proc *p;

    /*---------------------------------------------------------------*/
    /* Set the SET bit in status register B to prevent update cycles */
    /*---------------------------------------------------------------*/
    outb(0x70,11);		/* select status register B */
    statusB = inb(0x71);	/* get its current value */
    outb(0x70,11);		/* select status register B again */
    outb(0x71,statusB | 0x80);	/* turn on the SET bit */

    /*----------------------*/
    /* Get the current time */
    /*----------------------*/
    outb(0x70,4); val = inb(0x71);	/* hours, in BCD format */
    curhr = (val >> 4) * 10 + (val & 0xf);

    outb(0x70,2); val = inb(0x71);	/* minutes, in BCD format */
    curmin = (val >> 4) * 10 + (val & 0xf);

    outb(0x70,0); val = inb(0x71);	/* seconds, in BCD format */
    cursec = (val >> 4) * 10 + (val & 0xf);

    curtime = (curhr * 100 + curmin) * 100 + cursec;

dprintf("RTC interrupt at %06d (%d)\r\n", curtime, _nticks);
dprintf("    activeProcess: pid = %d, priority = %d\r\n",
activeProcess->pid, activeProcess->priority);


    while (awakeq != NULL) {
	p = awakeq;
dprintf("    pid = %d, delta = %d, priority = %d\r\n",
p->pid, p->delta, p->priority);
	if (p->delta == curtime) {
	    awakeq = p->next;
	    if (awakeq != NULL) awakeq->prev = NULL;
	    _addready(p);
	    if (p->priority > activeProcess->priority) resched = 1;
dprintf("    ...process added to ready queue; resched = %d\r\n", resched);
	} else {
dprintf("    ...NOT AWAKENED AT THIS TIME (resched = %d)\r\n", resched);
	    break;
	}
dprintf("    End of loop; resched = %d\r\n", resched);
    }
dprintf("After loop, resched = %d\r\n", resched);
    if (awakeq != NULL) {
	setRTCalarm();
	outb(0x70,11);
	outb(0x71,statusB);		/* SET off; AIE on */
    } else {
	outb(0x70,11);
	outb(0x71,statusB & ~0x20);	/* SET off; AIE off */
    }
dprintf("Before exit, resched = %d\r\n", resched);
    if (resched == 1) _addready(activeProcess);
    _rs = resched;
dprintf("Leaving rtcisr: _rs = %d, _nticks = %d\r\n", _rs, _nticks);
}

/***************************************/
/* Second-level disk interrupt handler */
/***************************************/
void _diskisr(void)
{
    struct IOreq *done;			/* request just completed */
    struct bufhd *b;

    if (IOhead == NULL) {
	dprintf("Ignoring disk interrupt\n");
	kprintf("Ignoring disk interrupt\r\n");
	return;		/* ignore interrupt if no I/O active */
    }

    /*-------------------------------------------------*/
    /* For a read command, copy data from the I/O port */
    /*-------------------------------------------------*/
    if (IOhead->op == DSK_READ) {
	_port_read(DSK_BASE + DSK_DATA, IOhead->buffer, 512);
    }

    /*------------------------------------------*/
    /* If this was a synchronous I/O request... */
    /*------------------------------------------*/
    if (IOhead->proc != 0) {
	_addready(IOhead->proc);	/* proc doing I/O is now ready */
	if (IOhead->proc->priority > activeProcess->priority) {
	    _addready(activeProcess);
	    _rs = 1;			/* resched CPU if necessary */
	}
    } else {
    /*--------------------------------------------*/
    /* If this was an asynchronous I/O request... */
    /*--------------------------------------------*/
	b = IOhead->bh;
	b->status &= ~BCS_IOACT;	/* say I/O no longer active */
	if (IOhead->op == DSK_READ) {
	    b->status |= BCS_HASDATA;	/* entry now has data */
	    b->status &= ~BCS_DIRTY;	/* entry is now clean */
	    awakeup((unsigned int)b);	/* wakeup waiting process(es) */
	} else {
	    b->status &= ~BCS_DIRTY;	/* entry is now clean */
	    brelse(b);
	}
    }

    /*----------------------------------------------------------*/
    /* Remove request from the queue, and return it to the pool */
    /*----------------------------------------------------------*/
    done = IOhead;
    IOhead = IOhead->next;
    if (IOhead == NULL) IOtail = NULL;
    done->next = IOfree;
    IOfree = done;

    /*-----------------------------------------------------------*/
    /* If the request queue isn't empty, start another operation */
    /*-----------------------------------------------------------*/
    if (IOhead != NULL) startdiskcmd();
}

/**************************************/
/* Wakeup processes waiting on 'addr' */
/**************************************/
void awakeup(unsigned int addr)
{
    int i;
    int maxp = -1;	/* max prio of any awakened process */

    /*--------------------------------------------*/
    /* Make ready all processes waiting on 'addr' */
    /*--------------------------------------------*/
    for (i=0;i<NPROC;i++) {
	if (proctab[i].eventaddr == addr) {
	    proctab[i].eventaddr = 0;
	    _addready(&proctab[i]);
	    if (proctab[i].priority > maxp) /* find max prio of those waking */
		maxp = proctab[i].priority;
	}
    }

    /*----------------------------------------------------------------------*/
    /* Resched if any awakened process has higher prio than current process */
    /*----------------------------------------------------------------------*/
    if (maxp > activeProcess->priority) {
	_addready(activeProcess);
	_rs = 1;
    }
}

/*******************************************************************/
/* Return 0 if the virtual address 'a' is not in the text, data or */
/* stack segment of the current process. Return 1 if it is in the  */
/* text or data, and 2 if it is in the stack.                      */
/*******************************************************************/
int chkaddr(unsigned int a)
{
    /* XXX For now, just return 1 */    return 1;
    if (a >= activeProcess->tdlo && a <= activeProcess->tdhi) return 1;
    if (a >= activeProcess->stklo && a <= activeProcess->stkhi) return 2;
    return 0;
}

void _verify(void)
{
    return;
}

/*********************************************************************/
/* "Normalize" a path by (a) prefixing the current working directory */
/* and (b) processing and removing "." and ".." components. Also     */
/* verify the accessibility of each byte in the path. Return NOERROR */
/* on success.                                                       */
/*********************************************************************/
/********************************************************************/
/* Concatenate the 'new' path to the 'old' path, putting the result */
/* in 'rslt'. 'old' must be a valid absolute path, and 'rslt' must  */
/* address a region with at least MAXPATH+1 bytes.                  */
/* Returns NOERROR on success, EFAULT if 'new' path is outside the  */
/* address space of the current process, or ENAMETOOLONG if the     */
/* result or any component of the result is too long.               */
/********************************************************************/
int abspath(char *path, char *rslt)
{
    char cwd[MAXPATH+1];	/* current working directory */
    char comp[FS1NAMELEN+1];	/* next new component */
    char *pc;			/* next component character */
    char *po;			/* null ending result */
    int clen;			/* component length */
    int rlen;			/* result length */

    /*------------------------------------------------------------*/
    /* If the path is NULL, return the current working directory. */
    /*------------------------------------------------------------*/

    /* Q. Are we certain that activeProcess->workdir is normalized? */
    /* Q. Do we know it has no "." or ".." components?              */
    if (path == NULL) {
	strcpy(rslt,activeProcess->workdir);
	return NOERROR;
    }
    /*-------------------------------------------*/
    /* Verify the first path byte is accessible. */
    /*-------------------------------------------*/
    if (chkaddr((unsigned)path) == 0) return EFAULT;

    /*--------------------------------------------------------------------*/
    /* If the path has zero length, return the current working directory. */
    /*--------------------------------------------------------------------*/
    /* XXX - See the questions above */
    if (*path == '\0') {
	strcpy(rslt,activeProcess->workdir);
	return NOERROR;
    }

    /*-----------------------------------------------------------*/
    /* If the path is absolute, begin with rslt = "/". Otherwise */
    /* begin with rslt containing the current working directory. */
    /*-----------------------------------------------------------*/
    if (*path == '/') strcpy(rslt,"/");
    else strcpy(rslt,activeProcess->workdir);
    pc = path;

    for(;;) {
	/*-----------------------------*/
	/* Skip '/' components in path */
	/*-----------------------------*/
	for(;;) {
	    if (chkaddr((unsigned)pc) == 0) return EFAULT;
	    if (*pc != '/') break;
	    pc++;
	}
	/*---------------------------------------*/
	/* If at the end of the path, we're done */
	/*---------------------------------------*/
	if (*pc == '\0') break;

	/*----------------------------------------*/
	/* Extract the next component of the path */
	/*----------------------------------------*/
	clen = 1;
	comp[0] = *pc++;
	for(;;) {
	    if (chkaddr((unsigned)pc) == 0) return EFAULT;
	    if (*pc == '/' || *pc == '\0') break;
	    if (clen == FS1NAMELEN) return ENAMETOOLONG;
	    comp[clen++] = *pc++;
	}
	comp[clen] = '\0';

	po = rslt + strlen(rslt);	/* point to null following rslt */
	rlen = strlen(rslt);

	/*----------------------------------------*/
	/* If the component is ".", just continue */
	/*----------------------------------------*/
	if (!strcmp(comp,".")) continue;

	/*-----------------------------------------------------*/
	/* If the component is "..", remove the last component */
	/* of rslt (but not the first "/") and continue.       */
	/*-----------------------------------------------------*/
	if (!strcmp(comp,"..")) {
	    while (po > rslt && *po != '/') {
		po--;
		rlen--;
	    }
	    /* Either po == rslt or *po == '/' (or both) */
	    if (po == rslt) po++;
	    *po = '\0';
	    continue;
	}

	/*----------------------------------------------*/
	/* Concatenate the new component to the result. */
	/*----------------------------------------------*/
	if (rlen > 1) {
	    if (rlen == MAXPATH) return ENAMETOOLONG;
	    *po++ = '/';
	    *po = '\0';
	    rlen++;
	}
	if (rlen + clen > MAXPATH) return ENAMETOOLONG;
	strcat(rslt,comp);
	rlen += clen;
    }
    return NOERROR;
}

/* A simple logging system. As needed, pages of memory are allocated for */
/* use as a log. The first such page is pointed to be 'ilogroot'. The    */
/* current page is identified by 'ilogpage'. The first 4 bytes of each   */
/* page point to the successor page, if any, with a NULL (0) pointer in  */
/* the last page. Log actions add 'records' to the pages, in sequential  */
/* order. Each record begins with a three-byte flag (0xa98765), followed */
/* by a one-byte count. This count indicates the number of additional    */
/* bytes that are part of the record. Logging and system operation stop  */
/* when the system runs out of memory!                                   */

unsigned char *ilogroot = NULL;		/* root of log page list */
unsigned char *ilogpage = NULL;		/* current log page */
int olog = 4096;			/* offset in current page */

/**************************************/
/* Add a fresh page to the log system */
/**************************************/
void newlogpage(void)
{
    unsigned int *np;			/* new page address */

    np = allocpage(0xff,1);
    if (np == NULL) quit("out of logging space");

    if (ilogroot == NULL) {		/* first page */
	ilogroot = ilogpage = (unsigned char *)np;
	*(unsigned int *)ilogpage = NULL;
    } else {
	*(unsigned int *)ilogpage = (unsigned int)np;	/* add-on page */
	ilogpage = (unsigned char *)np;
    }
    olog = 4;			/* logging starts at offset 4 */
}

/*****************************/
/* Add a byte to a log entry */
/*****************************/
void logbyte(unsigned char b)
{
    if (olog == 4096) newlogpage();
    *(ilogpage+olog) = b;
    olog++;
}

/***********************************************/
/* Begin logging a new entry requiring n bytes */
/***********************************************/
void newlog(unsigned int nbytes)
{
    logbyte(0xa9); logbyte(0x87); logbyte(0x65);
    logbyte((unsigned char)(nbytes & 0xff));
}

/******************************************************************/
/******************************************************************/
/****** System Call 64: Set/clear/return kernel debug flags. ******/
/******************************************************************/
/******************************************************************/
int _kset(int flag)
{
    if (flag > 32 || flag < -32)
	return BADVAL;
    if (flag == 0)
	return kd_Flag;
    if (flag > 0)
	kd_Flag |= 1 << (flag-1);
    else {
	flag = -flag;
	kd_Flag &= ~(1 << (flag-1));
    }
    return 0;
}
