/*
* PROJECT:         ReactOS kernel-mode tests
* LICENSE:         GPLv2+ - See COPYING in the top level directory
* PURPOSE:         Kernel-Mode Test Suite ZwMapViewOfSection
* PROGRAMMER:      Nikolay Borisov <nib9@aber.ac.uk>
*/

#include <kmt_test.h>

#define IGNORE -99

static UNICODE_STRING FileReadOnly = RTL_CONSTANT_STRING(L"\\SystemRoot\\system32\\ntdll.dll");
static UNICODE_STRING FileWriteOnly = RTL_CONSTANT_STRING(L"\\SystemRoot\\kmtest-MmSection.txt");
extern const char TestString[];
extern const SIZE_T TestStringSize;
static OBJECT_ATTRIBUTES NtdllObject;
static OBJECT_ATTRIBUTES KmtestFileObject;


#define TestMapView(SectionHandle, ProcessHandle, BaseAddress2, ZeroBits, CommitSize, SectionOffset, ViewSize2, InheritDisposition, AllocationType, Win32Protect, MapStatus, UnmapStatus) do    \
    {                                                                                                                                                                                           \
        Status = ZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress2, ZeroBits, CommitSize, SectionOffset, ViewSize2, InheritDisposition, AllocationType, Win32Protect);              \
        ok_eq_hex(Status, MapStatus);                                               \
        if (NT_SUCCESS(Status))                                                     \
        {                                                                           \
            Status = ZwUnmapViewOfSection(ProcessHandle, BaseAddress);              \
            if(UnmapStatus != IGNORE) ok_eq_hex(Status, UnmapStatus);               \
            *BaseAddress2 = NULL;                                                   \
            *ViewSize2 = 0;                                                         \
        }                                                                           \
    } while (0)                                                                     \


static 
VOID
KmtInitTestFiles(PHANDLE ReadOnlyFile, PHANDLE WriteOnlyFile) 
{
    NTSTATUS Status;
    LARGE_INTEGER FileOffset;
    IO_STATUS_BLOCK IoStatusBlock;
    UCHAR FileData = 0;

    //INIT THE READ-ONLY FILE
    Status = ZwCreateFile(ReadOnlyFile, ( GENERIC_READ | GENERIC_EXECUTE ), &NtdllObject, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(*ReadOnlyFile != NULL, "Couldn't acquire READONLY handle\n");

    //INIT THE WRITE-ONLY FILE
    //TODO: Delete the file when the tests are all executed
    Status = ZwCreateFile(WriteOnlyFile, (GENERIC_WRITE | SYNCHRONIZE), &KmtestFileObject, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_SUPERSEDE, (FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE), NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulongptr(IoStatusBlock.Information, FILE_CREATED);
    ok(*WriteOnlyFile != NULL, "WriteOnlyFile is NULL\n");
    if (WriteOnlyFile)
    {
        FileOffset.QuadPart = 0;
        Status = ZwWriteFile(*WriteOnlyFile, NULL, NULL, NULL, &IoStatusBlock, (PVOID)TestString, TestStringSize, &FileOffset, NULL);
        ok(Status == STATUS_SUCCESS || Status == STATUS_PENDING, "Status = 0x%08lx\n", Status);
        Status = ZwWaitForSingleObject(*WriteOnlyFile, FALSE, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_ulongptr(IoStatusBlock.Information, TestStringSize);
    }
}

VOID
SimpleErrorChecks(HANDLE FileHandleReadOnly, HANDLE FileHandleWriteOnly) 
{

    NTSTATUS Status;
    HANDLE Handle;
    LARGE_INTEGER MaximumSize;
    LARGE_INTEGER SectionOffset;
    SIZE_T AllocSize = TestStringSize;
    SIZE_T ViewSize = 0;
    PVOID BaseAddress = NULL;
    PVOID AllocBase = NULL;
    UNICODE_STRING SectionName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\KmtTestReadSect");
    MaximumSize.QuadPart = TestStringSize;

    //Basic section checks 
    Status = ZwCreateSection(&Handle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, FileHandleWriteOnly);                       
    ok_eq_hex(Status, STATUS_SUCCESS);   

    //section handle
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(0xDEADBEEF, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_HANDLE, IGNORE);
    TestMapView(INVALID_HANDLE_VALUE, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_OBJECT_TYPE_MISMATCH, IGNORE);
    TestMapView(NULL, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_HANDLE, IGNORE);

    //process handle
    TestMapView(Handle, 0xDEADBEEF, &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_HANDLE, IGNORE);
    TestMapView(Handle, NULL, &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_HANDLE, IGNORE);
    
    //base address
    BaseAddress = (PVOID)0x00567A20;
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_MAPPED_ALIGNMENT, IGNORE);

    BaseAddress = (PVOID) 0x60000000; 
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);

    BaseAddress = (PVOID)((char *)MmSystemRangeStart + 200);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_3, IGNORE);

    Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &AllocBase, 0, &AllocSize, MEM_COMMIT, PAGE_READWRITE);
    if (!skip(NT_SUCCESS(Status), "Cannot allocate memory\n"))
    {
        BaseAddress = AllocBase;
        TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_CONFLICTING_ADDRESSES, IGNORE);
        Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &AllocBase, &AllocSize, MEM_RELEASE);
        ok_eq_hex(Status, STATUS_SUCCESS);
        
    }

    //zero bits
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 1, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 5, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, -1, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_4, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 20, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_NO_MEMORY, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 21, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_NO_MEMORY, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 22, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_4, IGNORE);



    ZwClose(Handle);
}

START_TEST(ZwMapViewOfSection) 
{

    HANDLE FileHandleReadOnly = NULL;
    HANDLE FileHandleWriteOnly = NULL;

    InitializeObjectAttributes(&NtdllObject, &FileReadOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    InitializeObjectAttributes(&KmtestFileObject, &FileWriteOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    KmtInitTestFiles(&FileHandleReadOnly, &FileHandleWriteOnly);

    SimpleErrorChecks(FileHandleReadOnly, FileHandleWriteOnly);

    if(FileHandleReadOnly)
        ZwClose(FileHandleReadOnly);

    if(FileHandleWriteOnly)
        ZwClose(FileHandleWriteOnly);

}

