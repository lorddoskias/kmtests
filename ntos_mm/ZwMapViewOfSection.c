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

#define MmTestMapView(Object, ProcessHandle, BaseAddress2, ZeroBits, CommitSize, SectionOffset, ViewSize2, InheritDisposition, AllocationType, Win32Protect, MapStatus, UnmapStatus) do    \
    {                                                                                                                                                                                           \
        Status = MmMapViewOfSection(Object, ProcessHandle, BaseAddress2, ZeroBits, CommitSize, SectionOffset, ViewSize2, InheritDisposition, AllocationType, Win32Protect);              \
        ok_eq_hex(Status, MapStatus);                                               \
        if (NT_SUCCESS(Status))                                                     \
        {                                                                           \
            Status = MmUnmapViewOfSection(ProcessHandle, BaseAddress);              \
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


static
VOID
AdvancedErrorChecks(HANDLE FileHandleReadOnly, HANDLE FileHandleWriteOnly)
{
    NTSTATUS Status;
    PVOID BaseAddress;
    HANDLE PageFileSectionHandle;
    HANDLE FileSectionHandle;
    LARGE_INTEGER SectionOffset;
    LARGE_INTEGER MaximumSize;
    SIZE_T ViewSize = 0;
    PVOID SectionObject; 

    
    MaximumSize.QuadPart = TestStringSize;
    //Used for parameters working on file-based section
    Status = ZwCreateSection(&FileSectionHandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, FileHandleWriteOnly);
    ok_eq_hex(Status, STATUS_SUCCESS);   

    Status = ObReferenceObjectByHandle(FileSectionHandle, 
                                       STANDARD_RIGHTS_ALL,
                                       NULL, 
                                       KernelMode, 
                                       &SectionObject, 
                                       NULL);

    ok_eq_hex(Status, STATUS_SUCCESS);

    //Bypassing Nt/Zw function calls mean I bypass the alignment checks which are not crucial for the branches being tested here

    //test first conditional branch 
    ViewSize = -1;
    MmTestMapView(SectionObject, PsGetCurrentProcess(), &BaseAddress, 0, TestStringSize, &SectionOffset, &ViewSize, ViewUnmap, MEM_RESERVE, PAGE_READWRITE, STATUS_INVALID_VIEW_SIZE, IGNORE);

    //test second conditional branch
    ViewSize = 1;
    SectionOffset.QuadPart = TestStringSize;
    MmTestMapView(SectionObject, PsGetCurrentProcess(), &BaseAddress, 0, TestStringSize, &SectionOffset, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_VIEW_SIZE, IGNORE);
    MmTestMapView(SectionObject, PsGetCurrentProcess(), &BaseAddress, 0, TestStringSize, &SectionOffset, &ViewSize, ViewUnmap, MEM_RESERVE, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);

    ObDereferenceObject(SectionObject);
    ZwClose(FileSectionHandle);
}


static
VOID
SimpleErrorChecks(HANDLE FileHandleReadOnly, HANDLE FileHandleWriteOnly) 
{

    NTSTATUS Status;
    NTSTATUS ExceptionStatus;
    HANDLE Handle;
    HANDLE ReadOnlySection;
    HANDLE PageFileSectionHandle;
    LARGE_INTEGER MaximumSize;
    LARGE_INTEGER SectionOffset;
    SIZE_T AllocSize = TestStringSize;
    SIZE_T ViewSize = 0;
    PVOID BaseAddress = NULL;
    PVOID AllocBase = NULL;
    //UNICODE_STRING SectionName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\KmtTestReadSect");
    MaximumSize.QuadPart = TestStringSize;

    //Used for parameters working on file-based section
    Status = ZwCreateSection(&Handle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, FileHandleWriteOnly); 
    ok_eq_hex(Status, STATUS_SUCCESS);   

    Status = ZwCreateSection(&ReadOnlySection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly);
    ok_eq_hex(Status, STATUS_SUCCESS);


    //Used for parameters taking effect only on page-file backed section
    MaximumSize.QuadPart = 5 * MM_ALLOCATION_GRANULARITY;
    Status = ZwCreateSection(&PageFileSectionHandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL); 
    ok_eq_hex(Status, STATUS_SUCCESS); 

    MaximumSize.QuadPart = TestStringSize;

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

    /*KmtStartSeh()
    Status = ZwMapViewOfSection(Handle, ZwCurrentProcess(), NULL, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE);
    KmtEndSeh(STATUS_ACCESS_VIOLATION);*/

    //zero bits
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 1, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 5, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, -1, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_4, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 20, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_NO_MEMORY, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 21, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_NO_MEMORY, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 22, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_4, IGNORE);

    //commit size
    TestMapView(PageFileSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, 500, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(PageFileSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(PageFileSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, -1, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, IGNORE);
    TestMapView(PageFileSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, 0x10000000, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, IGNORE);
    TestMapView(PageFileSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, 0x01000000, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 500, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_5, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 500, NULL, &ViewSize, ViewUnmap, MEM_RESERVE, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);    
    
    //section offset
    SectionOffset.QuadPart = 0;
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, &SectionOffset, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    ok_eq_ulonglong(SectionOffset.QuadPart, 0);

    SectionOffset.QuadPart = 0x00040211; //MSDN is wrong, in w2k3 the ZwMapViewOfSection doesn't align offsets automatically 
    TestMapView(PageFileSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, 500, &SectionOffset, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_MAPPED_ALIGNMENT, IGNORE);

    SectionOffset.QuadPart = -1;
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, &SectionOffset, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_MAPPED_ALIGNMENT, IGNORE);

    //View Size 
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);

    ViewSize = -1;
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_PARAMETER_3, IGNORE);
    
    ViewSize = TestStringSize+1;
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_INVALID_VIEW_SIZE, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, MEM_RESERVE, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    
    ViewSize = TestStringSize;
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);

    ViewSize = TestStringSize-1;
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);


    //allocation type
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, MEM_RESERVE, PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(PageFileSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, MEM_RESERVE, PAGE_READWRITE, STATUS_INVALID_PARAMETER_9, STATUS_SUCCESS);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE, STATUS_INVALID_PARAMETER_9, IGNORE);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, (MEM_LARGE_PAGES | MEM_RESERVE), PAGE_READWRITE, STATUS_SUCCESS, STATUS_SUCCESS);
    
    //win32protect
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READONLY, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_NOACCESS, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(Handle, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY, STATUS_SECTION_PROTECTION, IGNORE);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE, STATUS_SECTION_PROTECTION, IGNORE);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_WRITECOPY, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READ, STATUS_SECTION_PROTECTION, IGNORE);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE, STATUS_SECTION_PROTECTION, IGNORE);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READONLY, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_NOACCESS, STATUS_SUCCESS, STATUS_SUCCESS);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, (PAGE_READWRITE | PAGE_READONLY), STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    TestMapView(ReadOnlySection, ZwCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, MEM_RESERVE, PAGE_READONLY, STATUS_SECTION_PROTECTION, IGNORE);

    ZwClose(Handle);
    ZwClose(PageFileSectionHandle);
    ZwClose(ReadOnlySection);
}


static 
VOID
BehaviorChecks(HANDLE FileHandleReadOnly, HANDLE FileHandleWriteOnly)
{
    NTSTATUS Status;
    PVOID BaseAddress = NULL;
    HANDLE PageFileSectionHandle;
    HANDLE ReadOnlySectionHandle;
    HANDLE WriteSectionHandle;
    LARGE_INTEGER SectionOffset;
    LARGE_INTEGER MaximumSize;
    SIZE_T Match;
    char *String = "NewContent";
    SIZE_T ViewSize = 0;

    MaximumSize.QuadPart = TestStringSize;
    SectionOffset.QuadPart = 0;

    Status = ZwCreateSection(&WriteSectionHandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, FileHandleWriteOnly);
    ok(NT_SUCCESS(Status), "Error creating write section from file. Error = %p\n", Status); 

    //check for section reading/writing by comparing its content to a well-known pattern.
    Status = ZwMapViewOfSection(WriteSectionHandle, ZwCurrentProcess() ,&BaseAddress, 0, 0, &SectionOffset, &ViewSize, ViewUnmap, 0, PAGE_READWRITE);
    ok(NT_SUCCESS(Status), "Error mapping view with READ/WRITE priv. Error = %p\n", Status);
    if (NT_SUCCESS(Status))
    {
        PVOID FileContent;
        IO_STATUS_BLOCK IoStatusBlock;

        Match = RtlCompareMemory(BaseAddress, TestString, TestStringSize);
        ok_eq_size(Match, TestStringSize);

        RtlCopyMemory(BaseAddress, String, 10);

        Match = RtlCompareMemory(BaseAddress, String, 10);
        ok_eq_size(Match, 10);

        //check to see if the contents have been written to the actual file on disk.
        Match = 0;
        
        FileContent = ExAllocatePoolWithTag(PagedPool, 10, 'Test');
        if (FileContent != NULL)
        {
            LARGE_INTEGER ByteOffset;
            ByteOffset.QuadPart = 0;

            Status = ZwReadFile(FileHandleWriteOnly, NULL, NULL, NULL, &IoStatusBlock, FileContent, 10, &ByteOffset, NULL);
            ok_eq_hex(Status, STATUS_SUCCESS);
            ok_eq_ulongptr(IoStatusBlock.Information, 10);

            Match = RtlCompareMemory(FileContent, String, 10);
            ok_eq_size(Match, 10);

            //return everything to normal.
            RtlCopyMemory(BaseAddress, TestString, TestStringSize);
            ExFreePoolWithTag(FileContent, 'Test');
        }  

        ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);

    }


    //Try to write to read-only section
    BaseAddress = NULL;
    ViewSize = 0;
    SectionOffset.QuadPart = 0;
    Status = ZwMapViewOfSection(WriteSectionHandle, ZwCurrentProcess(), &BaseAddress, 0, 0, &SectionOffset, &ViewSize, ViewUnmap, 0, PAGE_READONLY);
    ok(NT_SUCCESS(Status), "Error mapping view with READ priv. Error = %p\n", Status);
    if (NT_SUCCESS(Status))
    {
       NTSTATUS ExceptionStatus;

       Match = RtlCompareMemory(BaseAddress, TestString, TestStringSize);
       ok_eq_size(Match, TestStringSize);

        KmtStartSeh()
            RtlCopyMemory(BaseAddress, String, 10);
        KmtEndSeh(STATUS_ACCESS_VIOLATION);

        ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);
    }

    ZwClose(WriteSectionHandle);
}


START_TEST(ZwMapViewOfSection) 
{

    HANDLE FileHandleReadOnly = NULL;
    HANDLE FileHandleWriteOnly = NULL;

    InitializeObjectAttributes(&NtdllObject, &FileReadOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    InitializeObjectAttributes(&KmtestFileObject, &FileWriteOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    KmtInitTestFiles(&FileHandleReadOnly, &FileHandleWriteOnly);

    SimpleErrorChecks(FileHandleReadOnly, FileHandleWriteOnly);
    AdvancedErrorChecks(FileHandleReadOnly, FileHandleWriteOnly);
    BehaviorChecks(FileHandleReadOnly, FileHandleWriteOnly);

    if(FileHandleReadOnly)
        ZwClose(FileHandleReadOnly);

    if(FileHandleWriteOnly)
        ZwClose(FileHandleWriteOnly);

}

