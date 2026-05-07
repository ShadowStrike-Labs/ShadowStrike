Starting with the kernel programming basics.


Ring 3(User mode) --> Normal Applications(Notepad.exe , chrome.exe)
|
Ring 2 --> Not used by windows
|
Ring 1 --> Not used by windows
| 
Ring 0(Kernel Mode) -> Windows Core, drivers.


IRQL : A number from 0 to 31 that specifies which types of interrupts the CPU can handle.

#define PASSIVE_LEVEL    0   // Normal thread execution
#define LOW_LEVEL        0   // (same as PASSIVE_LEVEL)
#define APC_LEVEL        1   // Asynchronous Procedure Call
#define DISPATCH_LEVEL   2   // DPC, thread scheduler
#define PROFILE_LEVEL    27  // Profiling interrupt
#define CLOCK2_LEVEL     28  // Clock interrupt level 2
#define SYNCH_LEVEL      28  // Synchronization level
#define CLOCK1_LEVEL     28  // Clock interrupt level 1
#define POWER_LEVEL      30  // Power failure
#define HIGH_LEVEL       31  // Highest priority

PASSIVE_LEVEL = 0 Lowest : 
Normal Thread execution level.

Things you can do at this level :
- Normal function/procedure calls
- Page fault (memory page can be loaded from disk )
- Access to the Paged Pool
- Call to user-mode (DeviceIoControl)
- File Read/Write (ZwCreateFile)
- Registry Read/Write (ZwOpenKey)
- Sleep (KeWaitForSingleObject)

Things you cant do at this level :
- You cant get spinlock(You need to increase IRQL to use spinlocks)

APC_LEVEL = 1 Asynchronous Procedure Call

Things you can do at this level :
- Access to the Non-Paged Pool
- Spin lock(with KeAcquireSpinLockAtDpcLevel)

Things you cant do at this level : 
- Page fault (you cant access to the paged pool)
- Call to the User-Mode(APC_level is very high)

DISPATCH_LEVEL = 2 Most critical level : 

Thread Schedulers , DPC's(deferred procedure calls) all works in this level

Things you can do at this level :

- Spin Lock(KeAcquireSpinLockAtDpcLevel)
- Access to the Non-paged pool
- Interlocked transactions (InterlockedIncrement etc.)
- Simple,fast works

Things you SHOULDNT do at this level : 
- Page Fault(accessing to the paged pool at this IRQL level causes CRASH)
- ExAllocatePoolWithTag ( it makes page fault)
- Call to the user-mode
- File/Registry transactions
- Sleep(Kewaitforsingleobject)
- Lots of other Windows API

IMPORTANT NOTE : DPC MUST finish within 100 μs (microseconds)! Otherwise, the system will throw a "DPC_WATCHDOG" BSOD!

HIGHER LEVELS(27-31) Hardware interruptions

PROFILE_LEVEL (27): Profile interrupts
 CLOCK2_LEVEL (28): Clock interrupts (second clock)
 POWER_LEVEL (30): Power interrupt
 HIGH_LEVEL (31): Highest (non-maskable interrupt)
 ONLY hardware drivers run at these levels


IRQL RAISING/LOWERING

KIRQL oldIrql;

KeRaiseIrql(DISPATCH_LEVEL , &oldIrql); //Now we are at the dispatch_level
//Critical codes here
KeLowerIrql(oldIrql); //Switch back to the old IRQL level

//Automatic raising with spin lock
KSPIN_LOCK lock = {0};
KIRQL oldIrql;
KeAcquireSpinLock(&lock,&oldIrql); //Raises IRQL to the DISPATCH_LEVEL
//Critical codes here
KeReleaseSpinLock(&lock, oldIrql);   // Turns back to the old IRQL level

Important : While raising IRQL you are taking the risk of PAGE FAULT so you should use non-paged pool.

POOLS : NON-PAGED AND PAGED POOLS 

Physical Memory management

NON-PAGED POOL(256MB - fixed,cannot be transferred to disk)
Used at PhantomSensor contexts , DPC callbacks, datas which are protected with the spin lock

PAGED POOL(Remaining RAM - can be transferred to disk)
Used at Process names, logs, Events that will get send to the User-mode and every other thing thats used at the PASSIVE_LEVEL

LookAsideLists : Lookaside lists are providing performance for multiple allocations of the same size!

MDL(Memory Descriptor List) : MDL is used for safely reading the User-mode buffer at the kernel-mode because user-mode buffer can do instant page-faults at any time. Solution to this is using the MDL to lock the buffer.


SPIN LOCK - MUTEX - FAST MUTEX

SPIN_LOCK(DISPATCH_LEVEL) :
Fastest but requires raising IRQL. Its just for very very short transactions

FAST_MUTEX(APC_LEVEL) :
Faster than mutex but raises the IRQL to the APC_LEVEL

MUTEX(PASSIVE_LEVEL) :
Normal thread synchronization , can sleep.



What is a Worker Thread?
Worker threads allow you to defer work from HIGH IRQL to PASSIVE_LEVEL where you can do more complex operations.

IRP

What is an IRP?
IRP is the basic unit of I/O in Windows. Every I/O operation (CreateFile, ReadFile, WriteFile, DeviceIoControl) becomes an IRP.
// User-mode call:
HANDLE hFile = CreateFile("C:\\test.txt", GENERIC_READ, ...);
// ↓
// Kernel receives IRP_MJ_CREATE

// All major I/O operations have corresponding IRP major function codes:
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0A
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0B
#define IRP_MJ_DIRECTORY_CONTROL        0x0C
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0D
#define IRP_MJ_DEVICE_CONTROL           0x0E   // DeviceIoControl
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1A
#define IRP_MJ_PNP                      0x1B
#define IRP_MJ_PNP_POWER                0x1C  // Actually IRP_MJ_PNP + POWER
#define IRP_MJ_MAXIMUM_FUNCTION         0x1D

IRP STACK LOCATION
What is IRP Stack Location?
An IRP can pass through multiple drivers (e.g., File System → Volume Manager → Disk Driver). Each driver gets its own stack location.

DPC (DEFERRED PROCEDURE CALL)
What is DPC?
DPC is a mechanism to defer work from HIGH_LEVEL interrupt to DISPATCH_LEVEL.



