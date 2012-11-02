/*
* PROJECT:         ReactOS kernel-mode tests
* LICENSE:         GPLv2+ - See COPYING in the top level directory
* PURPOSE:         Kernel-Mode Test Suite Runtime library bit map test
* PROGRAMMER:      Nikolay Borisov <nib9@aber.ac.uk>
*/


#include <kmt_test.h>

#define _2gb 0x80000000
#define _1gb 0x40000000
#define ROUND_DOWN(n,align) (((ULONG_PTR)n) & ~((align) - 1l))
#define DEFAULT_ALLOC_SIZE 200
#define NO_CHECK 1
 
#define ALLOC_MEMORY_WITH_FREE(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect, RetStatus, FreeStatus)   \
    do {                                                                                                               \
    Status = ZwAllocateVirtualMemory(ProcessHandle, &BaseAddress, ZeroBits, &RegionSize, AllocationType, Protect);     \
    ok_eq_hex(Status, RetStatus);                                                                                      \
    RegionSize = 0;                                                                                                    \
    Status = ZwFreeVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize, MEM_RELEASE);                               \
    if(FreeStatus != NO_CHECK) ok_eq_hex(Status, (NTSTATUS)FreeStatus);                                                \
    BaseAddress = NULL;                                                                                                \
    RegionSize = DEFAULT_ALLOC_SIZE;                                                                                   \
    } while(0)                                                                                                         \

const char TestString[] = "TheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheW";


static BOOLEAN CheckBuffer( PVOID Buffer, SIZE_T Size, UCHAR Value)
{
    PUCHAR Array = Buffer;
    SIZE_T i;

    for (i = 0; i < Size; i++)
        if (Array[i] != Value)
        {
            trace("Expected %x, found %x at offset %lu\n", Value, Array[i], (ULONG)i);
            return FALSE;
        }

        return TRUE;
}

static SIZE_T CheckBufferRead(PVOID Source, const PVOID Destination, SIZE_T Length, NTSTATUS ExpectedStatus) 
{
    NTSTATUS ExceptionStatus;
    SIZE_T Match = 0;
    
    KmtStartSeh()
        Match = RtlCompareMemory(Source, Destination, Length);
    KmtEndSeh(ExpectedStatus);

    return Match;

}

static VOID CheckBufferReadWrite(PVOID Destination, const PVOID Source, SIZE_T Length, NTSTATUS ExpectedStatus) 
{
    //do a little bit of writing/reading to memory
    NTSTATUS ExceptionStatus;
    SIZE_T Match = 0;

    KmtStartSeh()
        RtlCopyMemory(Destination, Source, Length);
    KmtEndSeh(ExpectedStatus);

    Match =  CheckBufferRead(Source, Destination, Length, ExpectedStatus);
    ok_eq_int(Match, Length);
}


static void SimpleErrorChecks(VOID) {

    NTSTATUS Status; 
    PVOID Base = NULL;
    SIZE_T RegionSize = DEFAULT_ALLOC_SIZE;

    //HANDLE TESTS
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    ALLOC_MEMORY_WITH_FREE(NULL, Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_HANDLE, STATUS_INVALID_HANDLE);
    ALLOC_MEMORY_WITH_FREE(INVALID_HANDLE_VALUE, Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);

    //BASE ADDRESS TESTS
    Base = (PVOID)0x00567A20;
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_CONFLICTING_ADDRESSES, STATUS_FREE_VM_NOT_AT_BASE);

    Base = (PVOID) 0x60000000; 
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);

    Base = (PVOID)((char *)MmSystemRangeStart + 200);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_PARAMETER_2, STATUS_INVALID_PARAMETER_2);

    //ZERO BITS TESTS
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 21, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_NO_MEMORY, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 22, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_PARAMETER_3, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 10, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_NO_MEMORY, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, -1, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_PARAMETER_3, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 3, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);

    //REGION SIZE TESTS
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    RegionSize = -1;
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_PARAMETER_4, STATUS_MEMORY_NOT_ALLOCATED);
    RegionSize = 0;
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_PARAMETER_4, STATUS_MEMORY_NOT_ALLOCATED);
    RegionSize = _2gb * _2gb; // this is 4 gb and is invalid
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_PARAMETER_4, STATUS_MEMORY_NOT_ALLOCATED);

    //Allocation type tests
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, MEM_PHYSICAL, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESET), PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, MEM_TOP_DOWN, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_TOP_DOWN | MEM_RESET), PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_TOP_DOWN | MEM_COMMIT), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_PHYSICAL | MEM_RESERVE), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_PHYSICAL | MEM_COMMIT), PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_RESET | MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, -1, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize,  MEM_COMMIT, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize,  MEM_RESERVE, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    
    //Memory protection tests
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), 0, STATUS_INVALID_PAGE_PROTECTION, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), -1, STATUS_INVALID_PAGE_PROTECTION, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), (PAGE_NOACCESS | PAGE_GUARD), STATUS_INVALID_PAGE_PROTECTION, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), (PAGE_NOACCESS | PAGE_WRITECOMBINE), STATUS_INVALID_PAGE_PROTECTION, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize, (MEM_COMMIT | MEM_RESERVE), (PAGE_READONLY | PAGE_WRITECOMBINE), STATUS_SUCCESS, STATUS_SUCCESS);
}


static NTSTATUS SimpleAllocation(VOID) 
{

    NTSTATUS Status;
    NTSTATUS ExceptionStatus;
    PVOID Base = NULL;
    SIZE_T RegionSize = 200;

    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_eq_size(RegionSize, 4096); //this should have resulted in a single-page allocation

    //check for the zero-filled pages 
    ok_bool_true(CheckBuffer(Base, RegionSize, 0), "The buffer is not zero-filled");

    CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_SUCCESS);

    // try freeing
    RegionSize = 0;
    Status = ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_size(RegionSize, PAGE_SIZE);

    //////////////////////////////////////////////////////////////////////////
    // COMMIT AND RESERVE SCENARIO
    //////////////////////////////////////////////////////////////////////////
    //reserve and then commit
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
    CheckBufferReadWrite(Base, (PVOID)TestString, 0, STATUS_SUCCESS);

    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_SUCCESS);
    
    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    //////////////////////////////////////////////////////////////////////////
    
    //////////////////////////////////////////////////////////////////////////
    // TRY READING/WRITING TO INVALID PROTECTION PAGES
    //////////////////////////////////////////////////////////////////////////
    RegionSize = 200; 
    Base = NULL;
    ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_NOACCESS);

    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_ACCESS_VIOLATION);

    //why does this succeed?
    CheckBufferRead(Base, (PVOID)TestString, 200, STATUS_ACCESS_VIOLATION);

    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);

    ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READONLY);
    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_ACCESS_VIOLATION);

    ok_bool_true(CheckBuffer(Base, 200, 0), "Couldn't read a read-only buffer");

    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);

    //////////////////////////////////////////////////////////////////////////
    // GUARD PAGES
    //////////////////////////////////////////////////////////////////////////
    RegionSize = 1000; 
    Base = NULL;
    ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), (PAGE_GUARD | PAGE_READWRITE));

    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_GUARD_PAGE_VIOLATION);

    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_SUCCESS);

    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);

    //////////////////////////////////////////////////////////////////////////
    return Status;
}

static VOID CustomBaseAllocation(VOID) 
{

    NTSTATUS Status;  
    SIZE_T RegionSize = 200;
    PVOID Base =  (PVOID) 0x60025000;;
    PVOID ActualStartingAddress = (PVOID)ROUND_DOWN(Base, MM_ALLOCATION_GRANULARITY); //it is rounded down to the nearest allocation granularity (64k) address
    PVOID EndingAddress = (PVOID)(((ULONG_PTR)Base + RegionSize - 1) | (PAGE_SIZE - 1));
    SIZE_T ActualSize = BYTES_TO_PAGES((ULONG_PTR)EndingAddress - (ULONG_PTR)ActualStartingAddress) * PAGE_SIZE; //calculates the actual size based on the required pages

    // allocate the memory
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_size(RegionSize, ActualSize);  
    ok_eq_ulong(Base, ActualStartingAddress);  

    // try freeing
    RegionSize = 0;
    Status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&Base, &RegionSize, MEM_RELEASE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(RegionSize, ActualSize);

}

static NTSTATUS StressTesting(ULONG AllocationType) 
{

    NTSTATUS Status = STATUS_SUCCESS; 
    NTSTATUS ReturnStatus = STATUS_SUCCESS;
    static ULONG_PTR bases[1024]; //assume we are going to allocate only 5 gigs. static here means the arrays is not allocated on the stack but in the BSS segment of the driver 
    ULONG Index = 0;	
    PVOID Base = NULL;
    SIZE_T RegionSize = 5 * 1024 * 1024; // 5 megabytes; 

    for(Index = 0; NT_SUCCESS(Status); Index++) {

        Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, AllocationType, PAGE_READWRITE);

        if(Index >= RTL_NUMBER_OF(bases)) {
            trace("Reservation limit exceeded, won't free all reservations. Reservations written: %d\n", Index);
        } else {
            bases[Index] = (ULONG_PTR)Base;
            Base = NULL;
        }
    }

    trace("Finished reserving. Error code %x. Chunks allocated: %d\n", Status, Index );

    ReturnStatus = Status;

    //free the allocated memory so that we can continue with the tests
    Status = STATUS_SUCCESS;
    Index = 0;
    while(NT_SUCCESS(Status)) {
        RegionSize = 0;
        Status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID)&bases[Index], &RegionSize, MEM_RELEASE);
        bases[Index++] = (ULONG_PTR) NULL;

    }


    return ReturnStatus;
}

START_TEST(ZwAllocateVirtualMemory) 
{
    NTSTATUS Status;

    CustomBaseAllocation();

    SimpleErrorChecks();

    SimpleAllocation();

    Status = StressTesting(MEM_RESERVE);
    ok_eq_hex(Status, STATUS_NO_MEMORY);

    Status = STATUS_SUCCESS;
    Status = StressTesting(MEM_COMMIT);
    ok_eq_hex(Status, STATUS_COMMITMENT_LIMIT);

}


// UTILITY FUNCTIONS

