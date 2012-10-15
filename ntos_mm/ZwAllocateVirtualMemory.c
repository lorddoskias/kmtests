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


static VOID CheckBufferReadWrite(PVOID Source, const PVOID Destination, SIZE_T Length) {
	//do a little bit of writing/reading to memory
	RtlCopyMemory(Source, Destination, Length);
	ok_eq_int(RtlCompareMemory(Source, Destination, Length), Length);
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
	ok_eq_size(RegionSize, 4096);

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
	PVOID base = (PVOID)0x45EC6324; //this 
	SIZE_T RegionSize = 200;

	// allocate the memory
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_SUCCESS);
	ok_eq_size(RegionSize, 28672);  
	ok_eq_ulong(base, (PVOID)0x45EC0000);  //it is rounded down to the nearest allocation granularity (64k) address

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

	/*
	//invalid start address
	RegionSize = 200;
	base = (PVOID)0xD903; //should fail because i'm allocating in the first 64k
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	ok_eq_hex(Status, STATUS_CONFLICTING_ADDRESSES);
	trace("Allocated address is %p\n", base);
	CheckBufferReadWrite(base, (PVOID)TestString, 200);
	*/

	base = (PVOID)((char *)MmSystemRangeStart + 200);
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	//ok_eq_hex(Status, 0x00000f0); //ERROR_VC_DISCONNECTED?
	

	return Status;
}


START_TEST(ZwAllocateVirtualMemory) {
	NTSTATUS Status;

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

