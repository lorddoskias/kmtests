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

QUOTA_LIMITS limits;


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
	if(NT_SUCCESS(Status)) {
		trace("PagedPoolLimit        = %x\n", limits.PagedPoolLimit);
		trace("NonPagedPoolLimit     = %x\n", limits.NonPagedPoolLimit);
		trace("MinimumWorkingSetSize = %x\n", limits.MinimumWorkingSetSize);
		trace("MaximumWorkingSetSize = %x\n", limits.MaximumWorkingSetSize);
		trace("PagefileLimit         = %x\n", limits.PagefileLimit);
	} else {
		trace("FAILURE STATUS = 0x%08lx\n", Status);
	}
}

static NTSTATUS SimpleAllocation() {

	NTSTATUS Status;
	PVOID base = NULL;
	SIZE_T RegionSize = 200;

	// allocate the memory
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_size(RegionSize, 4096); //this should have resulted in a single-page allocation

	//check for the zero-filled pages 
	ok_bool_true(CheckBuffer(base, RegionSize, 0), "The buffer is not zero-filed");
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
	PVOID base = (PVOID)0x45EC6324; //dummy address  
	SIZE_T RegionSize = 200;

	// allocate the memory
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_size(RegionSize, 28672);  
	ok_eq_ulong(base, (PVOID)(((ULONG)base / MM_ALLOCATION_GRANULARITY ) * MM_ALLOCATION_GRANULARITY));  //it is rounded down to the nearest allocation granularity (64k) address

	// try freeing
	RegionSize = 0;
	Status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&base, &RegionSize, MEM_RELEASE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_ulong(RegionSize, 28672);

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


	//invalid start address
	RegionSize = 200;
	base = (PVOID)0xD903; //should fail because i'm allocating in the first 64k
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_CONFLICTING_ADDRESSES);
	trace("Allocated address is %p\n", base);
	Status = CheckBufferReadWrite(base, (PVOID)TestString, 200);

	//invalid upper address
	base = (PVOID)((char *)MmSystemRangeStart + 200); //this is invalid 
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_INVALID_PARAMETER_2);

	//allocate more than the architecturally allowed 2 gigabytes for a 32bit
	RegionSize = limits.MaximumWorkingSetSize + 100;
	base = (PVOID) NULL;
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_COMMITMENT_LIMIT);
	return Status;
}


START_TEST(ZwAllocateVirtualMemory) {
	NTSTATUS Status;

	GetProcLimits(); //populate global quota

	StartSeh();
	SimpleAllocation();
	EndSeh(STATUS_SUCCESS);

	StartSeh();
	CustomBaseAllocation();
	EndSeh(STATUS_SUCCESS);

	StartSeh();
	InvalidAllocations();
	EndSeh(STATUS_SUCCESS);



}


// UTILITY FUNCTIONS

