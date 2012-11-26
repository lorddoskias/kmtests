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
#define IGNORE -1
#define PAGE_NOPROT 0x0 //MEM_RESERVE has this type of "protection"

typedef struct _TEST_CONTEXT 
{
    HANDLE ProcessHandle;
    ULONG RegionSize;
    ULONG AllocationType;
    ULONG Protect;
    ULONG_PTR Bases[1024];
    SHORT ThreadId;
} TEST_CONTEXT, *PTEST_CONTEXT;


#define ALLOC_MEMORY_WITH_FREE(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect, RetStatus, FreeStatus)   \
    do {                                                                                                                   \
        Status = ZwAllocateVirtualMemory(ProcessHandle, &BaseAddress, ZeroBits, &RegionSize, AllocationType, Protect);     \
        ok_eq_hex(Status, RetStatus);                                                                                      \
        RegionSize = 0;                                                                                                    \
        Status = ZwFreeVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize, MEM_RELEASE);                               \
        if (FreeStatus != IGNORE) ok_eq_hex(Status, (NTSTATUS)FreeStatus);                                                 \
        BaseAddress = NULL;                                                                                                \
        RegionSize = DEFAULT_ALLOC_SIZE;                                                                                   \
    } while(0)                                                                                                             \

#define Test_NtQueryVirtualMemory(BaseAddress, Size, AllocationType, ProtectionType)            \
    do {                                                                                        \
           PKMT_RESPONSE NtQueryTest = KmtUserModeCallback(QueryVirtualMemory, BaseAddress);    \
           if (NtQueryTest != NULL)                                                             \
           {                                                                                    \
                ok_eq_hex(NtQueryTest->MemInfo.Protect, ProtectionType);                        \
                ok_eq_hex(NtQueryTest->MemInfo.State, AllocationType);                          \
                ok_eq_size(NtQueryTest->MemInfo.RegionSize, Size);                              \
                KmtFreeCallbackResponse(NtQueryTest);                                           \
           }                                                                                    \
    } while(0)                                                                                  \

const char TestString[] = "TheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheW";


static BOOLEAN CheckBuffer(PVOID Buffer, SIZE_T Size, UCHAR Value)
{
    PUCHAR Array = Buffer;
    SIZE_T i;

    for (i = 0; i < Size; i++) {
        if (Array[i] != Value)
        {
            trace("Expected %x, found %x at offset %lu\n", Value, Array[i], (ULONG)i);
            return FALSE;
        }
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

    Match = CheckBufferRead(Source, Destination, Length, ExpectedStatus);
    if (ExpectedStatus == STATUS_SUCCESS) ok_eq_int(Match, Length);
    
}


static void SimpleErrorChecks(VOID) 
{

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
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize,  MEM_RESERVE, PAGE_WRITECOPY, STATUS_INVALID_PAGE_PROTECTION, STATUS_MEMORY_NOT_ALLOCATED);
    ALLOC_MEMORY_WITH_FREE(NtCurrentProcess(), Base, 0, RegionSize,  MEM_RESERVE, PAGE_EXECUTE_WRITECOPY, STATUS_INVALID_PAGE_PROTECTION, STATUS_MEMORY_NOT_ALLOCATED);

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

    //////////////////////////////////////////////////////////////////////////
    //Normal operation
    //////////////////////////////////////////////////////////////////////////
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    ok_eq_size(RegionSize, 4096);

    //check for the zero-filled pages 
    ok_bool_true(CheckBuffer(Base, RegionSize, 0), "The buffer is not zero-filled");

    CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_SUCCESS);

    // try freeing
    RegionSize = 0;
    Status = ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_size(RegionSize, PAGE_SIZE);

    //////////////////////////////////////////////////////////////////////////
    // COMMIT AND RESERVE SCENARIO AND STATE CHANGE
    //////////////////////////////////////////////////////////////////////////
    //reserve and then commit
    Base = NULL;
    RegionSize = DEFAULT_ALLOC_SIZE;
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
    Test_NtQueryVirtualMemory(Base, RegionSize, MEM_RESERVE, PAGE_NOPROT);
    CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_ACCESS_VIOLATION);
    

    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
    CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_SUCCESS);
    Test_NtQueryVirtualMemory(Base, RegionSize, MEM_COMMIT, PAGE_READWRITE);

    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);

    //////////////////////////////////////////////////////////////////////////
    // TRY READING/WRITING TO INVALID PROTECTION PAGES
    //////////////////////////////////////////////////////////////////////////
    RegionSize = DEFAULT_ALLOC_SIZE; 
    Base = NULL;
    ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_NOACCESS);

    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_ACCESS_VIOLATION);

    Test_NtQueryVirtualMemory(Base, RegionSize, MEM_COMMIT, PAGE_NOACCESS);
    CheckBufferRead(Base, (PVOID)TestString, 200, STATUS_ACCESS_VIOLATION);

    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);

    ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READONLY);
    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_ACCESS_VIOLATION);

    Test_NtQueryVirtualMemory(Base, RegionSize, MEM_COMMIT, PAGE_READONLY);

    ok_bool_true(CheckBuffer(Base, 200, 0), "Couldn't read a read-only buffer");

    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);

    //////////////////////////////////////////////////////////////////////////
    // GUARD PAGES
    //////////////////////////////////////////////////////////////////////////
    RegionSize = 1000; 
    Base = NULL;
    ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), (PAGE_GUARD | PAGE_READWRITE));

    Test_NtQueryVirtualMemory(Base, RegionSize, MEM_COMMIT, (PAGE_GUARD | PAGE_READWRITE));
    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_GUARD_PAGE_VIOLATION);

    Test_NtQueryVirtualMemory(Base, RegionSize, MEM_COMMIT, PAGE_READWRITE);

    KmtStartSeh()
        RtlCopyMemory(Base, (PVOID)TestString, 200);
    KmtEndSeh(STATUS_SUCCESS);
    
    RegionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);

    return Status;
}



static VOID CustomBaseAllocation(VOID) 
{

    NTSTATUS Status;  
    SIZE_T RegionSize = 200;
    PVOID Base =  (PVOID) 0x60025000;
    PVOID ActualStartingAddress = (PVOID)ROUND_DOWN(Base, MM_ALLOCATION_GRANULARITY); //it is rounded down to the nearest allocation granularity (64k) address
    PVOID EndingAddress = (PVOID)(((ULONG_PTR)Base + RegionSize - 1) | (PAGE_SIZE - 1));
    SIZE_T ActualSize = BYTES_TO_PAGES((ULONG_PTR)EndingAddress - (ULONG_PTR)ActualStartingAddress) * PAGE_SIZE; //calculates the actual size based on the required pages

    // allocate the memory
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&Base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_size(RegionSize, ActualSize);  
    ok_eq_ulong(Base, ActualStartingAddress);  
    Test_NtQueryVirtualMemory(ActualStartingAddress, ActualSize, MEM_COMMIT, PAGE_READWRITE);

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

    for (Index = 0; Index < RTL_NUMBER_OF(bases) && NT_SUCCESS(Status); Index++) {

        Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, AllocationType, PAGE_READWRITE);

        bases[Index] = (ULONG_PTR)Base;
        if ((Index % 10) == 0)
        {
            
            if (AllocationType == MEM_COMMIT)
            {
                CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_SUCCESS);             
            }
            else 
            {
                CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_ACCESS_VIOLATION);   
            }
                
        }
        
        Base = NULL;

    }

    trace("Finished reserving. Error code %x. Chunks allocated: %d\n", Status, Index );

    ReturnStatus = Status;

    //free the allocated memory so that we can continue with the tests
    Status = STATUS_SUCCESS;
    Index = 0;
    while (NT_SUCCESS(Status)) {
        RegionSize = 0;
        Status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID)&bases[Index], &RegionSize, MEM_RELEASE);
        bases[Index++] = (ULONG_PTR) NULL;

    }

    return ReturnStatus;
}

static VOID SystemProcessTestWorker(PVOID StartContext) 
{
    
   NTSTATUS Status = STATUS_SUCCESS; 
   PTEST_CONTEXT Context = (PTEST_CONTEXT) StartContext; 
   ULONG Index = 0;	
   PVOID Base = NULL;

   PAGED_CODE();

   trace("Thread %d started\n", Context->ThreadId);

   Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Context->RegionSize, Context->AllocationType, Context->Protect);
   ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &Context->RegionSize, MEM_RELEASE);

    while (NT_SUCCESS(Status) && Index < RTL_NUMBER_OF(Context->Bases))
    {
        Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Context->RegionSize, Context->AllocationType, Context->Protect);

        Context->Bases[Index] = (ULONG_PTR)Base;
        if ((Index % 10) == 0)
        {

            if (Context->Protect == MEM_COMMIT)
            {
                CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_SUCCESS);             
            }
            else 
            {
                CheckBufferReadWrite(Base, (PVOID)TestString, 200, STATUS_ACCESS_VIOLATION);   
            }

        }

        Base = NULL;
        Index++;
    }

    trace("[SYSTEM THREAD %d]. Error code %x. Chunks allocated: %d\n", Context->ThreadId, Status, Index);

    //free the allocated memory so that we can continue with the tests
    Status = STATUS_SUCCESS;
    Index = 0;
    while (NT_SUCCESS(Status)) 
    {
        Context->RegionSize = 0;
        Status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID)&Context->Bases[Index], &Context->RegionSize, MEM_RELEASE);
        Context->Bases[Index++] = (ULONG_PTR) NULL;
    }

    PsTerminateSystemThread(Status);
}

HANDLE ProcessHandle;
ULONG RegionSize;
ULONG AllocationType;
ULONG Protect;

static VOID KmtInitTestContext(PTEST_CONTEXT Ctx, SHORT ThreadId, ULONG RegionSize, ULONG AllocationType, ULONG Protect)
{
    PAGED_CODE();

    {
        Ctx->AllocationType = AllocationType;
        Ctx->Protect = Protect;
        Ctx->RegionSize = RegionSize;
        Ctx->ThreadId = ThreadId;
    }

}

static VOID SystemProcessTest() 
{

    NTSTATUS Status; 
    HANDLE Thread1; 
    HANDLE Thread2;
    PVOID ThreadObjects[2];
    OBJECT_ATTRIBUTES ObjectAttributes;
    PTEST_CONTEXT StartContext1;
    PTEST_CONTEXT StartContext2;

    StartContext1 = ExAllocatePoolWithTag(NonPagedPool, sizeof(TEST_CONTEXT), 'tXTC');
    StartContext2 = ExAllocatePoolWithTag(NonPagedPool, sizeof(TEST_CONTEXT), 'tXTC');
    if(StartContext1 == NULL || StartContext2 == NULL)
    {
        trace("Error allocating space for context structs\n");
        goto cleanup;
    }

    KmtInitTestContext(StartContext1, 1, 1 * 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
    KmtInitTestContext(StartContext2, 2, 3 * 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = PsCreateSystemThread(&Thread1, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, (PKSTART_ROUTINE)SystemProcessTestWorker, (PVOID) StartContext1);
    if (!NT_SUCCESS(Status))
    {
        trace("Error creating thread1\n");
        goto cleanup;
    }

    Status = ObReferenceObjectByHandle(Thread1, THREAD_ALL_ACCESS, PsThreadType, KernelMode, &ThreadObjects[0], NULL);
    if (NT_SUCCESS(Status))
    {
        trace("error referencing thread1 \n");
        goto cleanup;
    }

    Status = PsCreateSystemThread(&Thread2, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, (PKSTART_ROUTINE)SystemProcessTestWorker, (PVOID) StartContext2);
    if (!NT_SUCCESS(Status))
    {
        trace("Error creating thread2\n");
        goto cleanup;
    }

    Status = ObReferenceObjectByHandle(Thread2, THREAD_ALL_ACCESS, PsThreadType, KernelMode, &ThreadObjects[1], NULL);
    if (NT_SUCCESS(Status))
    {
         trace("error referencing thread2 \n");
        goto cleanup;
    }
    
   KeWaitForMultipleObjects(2, ThreadObjects, WaitAll, UserRequest, UserMode, TRUE, NULL, NULL);
   //the return reason can be ignored since what follows is cleaning up which should always be executed; 

cleanup:
    /* FIXME: If the thread 1 has started and thread 2 fails
       then here we are cleaning absolutely everything and essentially breaking the running thread*/
    if(StartContext1 != NULL)
        ExFreePoolWithTag(StartContext1, 'tXTC');

    if(StartContext2 != NULL)
        ExFreePoolWithTag(StartContext2, 'tXTC');

    if(ThreadObjects[0] != NULL)
        ObDereferenceObject(ThreadObjects[0]);

    if(ThreadObjects[1] != NULL)
        ObDereferenceObject(ThreadObjects[1]);
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

    SystemProcessTest();
}