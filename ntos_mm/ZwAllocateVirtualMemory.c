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

const char TestString[] = "TheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheW";

static ULONG_PTR GetRandomAddress(VOID) 
{
    ULONG_PTR Address;
    ULONG Seed;
    do 
    {
        LARGE_INTEGER State = KeQueryPerformanceCounter(NULL);
        Seed = State.LowPart ^ State.HighPart;
        Address = RtlRandomEx(&Seed);
    } while (Address >= (ULONG_PTR)MmSystemRangeStart);

    return Address;
}

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

static VOID CheckBufferReadWrite(PVOID Source, const PVOID Destination, SIZE_T Length, NTSTATUS ExpectedStatus) 
{
    //do a little bit of writing/reading to memory
    NTSTATUS ExceptionStatus;
    SIZE_T Match = 0;

    KmtStartSeh()
        RtlCopyMemory(Source, Destination, Length);
        Match = RtlCompareMemory(Source, Destination, Length);
    KmtEndSeh(ExpectedStatus);

    ok_eq_int(Match, Length);
   
}


static NTSTATUS SimpleAllocation(VOID) 
{

    NTSTATUS Status;
    PVOID Base = NULL;
    SIZE_T RegionSize = 200;

    // commit
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_SUCCESS);
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
    //test reserve and then commit
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    
    CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_SUCCESS);
    
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    //////////////////////////////////////////////////////////////////////////
    return Status;
}

static NTSTATUS CustomBaseAllocation(VOID) 
{

    NTSTATUS Status;  
    SIZE_T RegionSize = 200;
    PVOID Base =  (PVOID)GetRandomAddress();
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

    return Status;
}

static NTSTATUS InvalidAllocations(VOID) 
{
    NTSTATUS Status;
    PVOID Base = NULL;
    SIZE_T RegionSize = 200;

    //invalid process handle
    Status = ZwAllocateVirtualMemory(NULL, &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_INVALID_HANDLE);

    //double reserve
    RegionSize = 200;
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize,  MEM_RESERVE, PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_CONFLICTING_ADDRESSES);


    //invalid upper address
    Base = (PVOID)((char *)MmSystemRangeStart + 200); //this is invalid 
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER_2);

    //missing MEM_RESERVE
    Base = NULL;
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_PHYSICAL), PAGE_READONLY); 
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER_5);

    //invalid page protection
    Base = NULL;
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_PHYSICAL | MEM_RESERVE ), PAGE_EXECUTE); 
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER_6);


    return Status;
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

    SimpleAllocation();

    CustomBaseAllocation();

    InvalidAllocations();

    Status = StressTesting(MEM_RESERVE);
    ok_eq_hex(Status, STATUS_NO_MEMORY);

    Status = STATUS_SUCCESS;
    Status = StressTesting(MEM_COMMIT);
    ok_eq_hex(Status, STATUS_COMMITMENT_LIMIT);

}


// UTILITY FUNCTIONS

