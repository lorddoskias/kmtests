/*
* PROJECT:         ReactOS kernel-mode tests
* LICENSE:         GPLv2+ - See COPYING in the top level directory
* PURPOSE:         Kernel-Mode Test Suite Runtime library bit map test
* PROGRAMMER:      Nikolay Borisov <nib9@aber.ac.uk>
*/


#include <kmt_test.h>
#include <ntifs.h>

#define StartSeh()                  Status = STATUS_SUCCESS; _SEH2_TRY {
#define EndSeh(ExpectedStatus)      } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); } _SEH2_END; ok_eq_hex(Status, ExpectedStatus)

#define _2gb 0x80000000
#define _1gb 0x40000000
#define ROUND_DOWN(n,align) (((ULONG)n) & ~((align) - 1l))

QUOTA_LIMITS limits;

const char TestString[] = "TheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheWhiteRabbitTheLongBrownFoxJumpedTheW";

static ULONG_PTR GetRandomAddress() {
	ULONG_PTR address;
	ULONG seed;
	do 
	{
		LARGE_INTEGER state = KeQueryPerformanceCounter(NULL);
		seed = state.LowPart ^ state.HighPart;
		address = RtlRandomEx(&seed);
	} while (address >= (ULONG_PTR)MmSystemRangeStart);

	return address;
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

static NTSTATUS CheckBufferReadWrite(PVOID Source, const PVOID Destination, SIZE_T Length) {
	//do a little bit of writing/reading to memory
	NTSTATUS Status;
	SIZE_T match = 0;

	_SEH2_TRY {
		RtlCopyMemory(Source, Destination, Length);
		match = RtlCompareMemory(Source, Destination, Length);
		ok_eq_int(match, Length);
	} _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
		Status = _SEH2_GetExceptionCode();
	} _SEH2_END;

	return Status;

}

static VOID GetProcLimits() {
	NTSTATUS Status;
	ULONG ReturnLength;

	Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessQuotaLimits, &limits, sizeof(limits), &ReturnLength);
}

static NTSTATUS SimpleAllocation() {

	NTSTATUS Status;
	PVOID base = NULL;
	SIZE_T RegionSize = 200;

	// commit
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_size(RegionSize, 4096); //this should have resulted in a single-page allocation

	//check for the zero-filled pages 
	ok_bool_true(CheckBuffer(base, RegionSize, 0), "The buffer is not zero-filled");
	CheckBufferReadWrite(base, (PVOID)TestString, 200);

	// try freeing
	RegionSize = 0;
	Status = ZwFreeVirtualMemory(NtCurrentProcess(), &base, &RegionSize, MEM_RELEASE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_size(RegionSize, PAGE_SIZE);

	//test reserve and then commit
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	CheckBufferReadWrite(base, (PVOID)TestString, 200);

	return Status;
}

static NTSTATUS CustomBaseAllocation() {

	NTSTATUS Status;  
	SIZE_T RegionSize = 200;
	ULONG_PTR base =  GetRandomAddress();
	ULONG_PTR ActualStartingAddress = ROUND_DOWN((ULONG_PTR)base, MM_ALLOCATION_GRANULARITY); //it is rounded down to the nearest allocation granularity (64k) address
	ULONG_PTR EndingAddress = ((ULONG_PTR)base + RegionSize - 1) | (PAGE_SIZE - 1);
	ULONG_PTR ActualSize = BYTES_TO_PAGES(EndingAddress - ActualStartingAddress) * PAGE_SIZE; //calculates the actual size based on the required pages
	

	// allocate the memory
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_size(RegionSize, ActualSize);  
	ok_eq_ulong(base, ActualStartingAddress);  

	// try freeing
	RegionSize = 0;
	Status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&base, &RegionSize, MEM_RELEASE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_ulong(RegionSize, ActualSize);

	return Status;
}

static NTSTATUS InvalidAllocations() {
	NTSTATUS Status;
	PVOID base = (PVOID) NULL;
	SIZE_T RegionSize = 200;

	//invalid process handle
	Status = ZwAllocateVirtualMemory(NULL, &base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_INVALID_HANDLE);

	//double reserve
	RegionSize = 200;
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize,  MEM_RESERVE, PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_CONFLICTING_ADDRESSES);


	//invalid upper address
	base = (PVOID)((char *)MmSystemRangeStart + 200); //this is invalid 
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_INVALID_PARAMETER_2);

	return Status;
}

static NTSTATUS StressTesting(ULONG AllocationType) {

	NTSTATUS Status = STATUS_SUCCESS; 
	NTSTATUS returnStatus = STATUS_SUCCESS;
	ULONG_PTR bases[1024]; //assume we are going to allocate only 5 gigs. 
	ULONG index = 0;	
	PVOID base = NULL;
	SIZE_T RegionSize = 5 * 1024 * 1024; // 5 megabytes; 

	for(index = 0; NT_SUCCESS(Status); index++) {

		Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, AllocationType, PAGE_READWRITE);

		if(index >= 1024) {
			trace("[ZwAlloc]Reservation limit exceeded, won't free all reservations. Reservations written: %d\n", index);
		} else {
			bases[index] = (ULONG_PTR)base;
			base = NULL;
		}
	}

	trace("[ZwAlloc] Finished reserving. Error code %x. Chunks allocated: %d\n", Status, index );
	
	returnStatus = Status;

	//free the allocated memory so that we can continue with the tests
	Status = STATUS_SUCCESS;
	index = 0;
	while(NT_SUCCESS(Status)) {
		RegionSize = 0;
		Status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID)&bases[index++], &RegionSize, MEM_RELEASE);

	}


	return returnStatus;
}

START_TEST(ZwAllocateVirtualMemory) {
	NTSTATUS Status;

	GetProcLimits(); //populate global quota
	
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

