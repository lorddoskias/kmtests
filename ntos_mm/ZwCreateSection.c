/*
* PROJECT:         ReactOS kernel-mode tests
* LICENSE:         GPLv2+ - See COPYING in the top level directory
* PURPOSE:         Kernel-Mode Test Suite ZwCreateSection
* PROGRAMMER:      Nikolay Borisov <nib9@aber.ac.uk>
*/

#include <kmt_test.h>

#define IGNORE -999
#define NO_HANDLE_CLOSE -998
#define _4mb 4194304
extern const char TestString[];
extern const SIZE_T TestStringSize;
static UNICODE_STRING FileReadOnlyPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\system32\\ntdll.dll");
static UNICODE_STRING WritableFilePath = RTL_CONSTANT_STRING(L"\\SystemRoot\\kmtest-MmSection.txt");
static OBJECT_ATTRIBUTES NtdllObject;
static OBJECT_ATTRIBUTES KmtestFileObject;


#define CREATE_SECTION(Handle, DesiredAccess, Attributes, Size, SectionPageProtection, AllocationAttributes, FileHandle,  RetStatus, CloseRetStatus)  do    \
    {                                                                                                                                                       \
        Status = ZwCreateSection(&Handle, DesiredAccess, Attributes, &Size, SectionPageProtection, AllocationAttributes, FileHandle);                       \
        ok_eq_hex(Status, RetStatus);                                                                                                                       \
        if (NT_SUCCESS(Status))                                                                                                                             \
        {                                                                                                                                                   \
                                                                                                                                                            \
          if (CloseRetStatus != NO_HANDLE_CLOSE)                                                                                                            \
            {                                                                                                                                               \
                Status = ZwClose(Handle);                                                                                                                   \
                Handle = NULL;                                                                                                                              \
                if (CloseRetStatus != IGNORE) ok_eq_hex(Status, CloseRetStatus);                                                                            \
            }                                                                                                                                               \
        }                                                                                                                                                   \
    } while (0)                                                                                                                                             \


#define CheckObject(Handle, Pointers, Handles) do                   \
{                                                                   \
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectInfo;                     \
    Status = ZwQueryObject(Handle, ObjectBasicInformation,          \
    &ObjectInfo, sizeof ObjectInfo, NULL);                          \
    ok_eq_hex(Status, STATUS_SUCCESS);                              \
    ok_eq_ulong(ObjectInfo.PointerCount, Pointers);                 \
    ok_eq_ulong(ObjectInfo.HandleCount, Handles);                   \
} while (0)


#define CheckSection(SectionHandle, SectionFlag, SectionSize, RetStatus) do \
{                                                                           \
    SECTION_BASIC_INFORMATION Sbi;                                          \
    NTSTATUS Status;                                                        \
    Status = ZwQuerySection(SectionHandle, SectionBasicInformation,         \
    &Sbi, sizeof Sbi, NULL);                                                \
    ok_eq_hex(Status, RetStatus);                                           \
    if(RetStatus == STATUS_SUCCESS && NT_SUCCESS(Status))                   \
    {                                                                       \
        ok_eq_pointer(Sbi.BaseAddress, NULL);                               \
        ok_eq_longlong(Sbi.Size.QuadPart, SectionSize);                     \
        ok_eq_hex(Sbi.Attributes, SectionFlag | SEC_FILE);                  \
    }                                                                       \
} while (0)

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
    Status = ZwCreateFile(WriteOnlyFile, (GENERIC_WRITE | SYNCHRONIZE), &KmtestFileObject, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);
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
SimpleErrorChecks(HANDLE FileHandleReadOnly, HANDLE FileHandleWriteOnly) 
{
    NTSTATUS Status;
    HANDLE Section = NULL;

    
    OBJECT_ATTRIBUTES ObjectAttributesReadOnly;
    OBJECT_ATTRIBUTES ObjectAttributesWriteOnly;
    OBJECT_ATTRIBUTES InvalidObjectAttributes;
    LARGE_INTEGER MaximumSize;

    UNICODE_STRING SectReadOnly = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\KmtTestReadSect");
    UNICODE_STRING SectWriteOnly = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\KmtTestWriteSect");
    UNICODE_STRING InvalidObjectString = RTL_CONSTANT_STRING(L"THIS/IS/INVALID");
    MaximumSize.QuadPart = TestStringSize; 

    InitializeObjectAttributes(&ObjectAttributesReadOnly, &SectReadOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    InitializeObjectAttributes(&ObjectAttributesWriteOnly, &SectWriteOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    InitializeObjectAttributes(&InvalidObjectAttributes, &InvalidObjectString, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);

    //PAGE FILE BACKED SECTION
    //DESIRED ACCESS TESTS
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, 0, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, -1, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);

    //OBJECT ATTRIBUTES 
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesReadOnly, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &InvalidObjectAttributes, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_SUCCESS);

    //MAXIMUM SIZE
    MaximumSize.QuadPart = -1;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SECTION_TOO_BIG, IGNORE);

    MaximumSize.QuadPart = 0;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_INVALID_PARAMETER_4, IGNORE);
   
    //division by zero in ROS
    if (SharedUserData->LargePageMinimum > 0 ) 
    {
        MaximumSize.QuadPart = (_4mb / SharedUserData->LargePageMinimum) * SharedUserData->LargePageMinimum; //4mb 
        CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_LARGE_PAGES | SEC_COMMIT), NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    }
    
   
    MaximumSize.QuadPart = TestStringSize;

    //SECTION PAGE PROTECTION
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_EXECUTE_READ, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_EXECUTE_WRITECOPY, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READONLY, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, (PAGE_EXECUTE_READ | PAGE_READWRITE), SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, (PAGE_READONLY | PAGE_READWRITE), SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, (PAGE_WRITECOPY | PAGE_READONLY), SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, 0, SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, -1, SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, STATUS_SUCCESS);

    //ALLOCATION ATTRIBUTES
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, 0, NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_COMMIT | SEC_RESERVE), NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_RESERVE, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_IMAGE, NULL, STATUS_INVALID_FILE_FOR_SECTION, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_IMAGE | SEC_COMMIT), NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, -1, NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_LARGE_PAGES, NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_LARGE_PAGES | SEC_COMMIT), NULL, STATUS_INVALID_PARAMETER_4, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_NOCACHE, NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_NOCACHE | SEC_RESERVE | SEC_COMMIT), NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_NOCACHE | SEC_COMMIT), NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_NOCACHE | SEC_RESERVE), NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_IMAGE, NULL, STATUS_INVALID_FILE_FOR_SECTION, STATUS_SUCCESS);

    //NORMAL FILE-BACKED SECTION

    //DESIRED ACCESS TESTS 
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesReadOnly, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesWriteOnly, MaximumSize, PAGE_WRITECOPY, SEC_COMMIT, FileHandleWriteOnly, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_MAP_WRITE, &ObjectAttributesReadOnly, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_MAP_READ, &ObjectAttributesWriteOnly, MaximumSize, PAGE_WRITECOPY, SEC_COMMIT, FileHandleWriteOnly, STATUS_SUCCESS, STATUS_SUCCESS);

    //Object Attributes
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &InvalidObjectAttributes, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly, STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_SUCCESS);

    //MAXIMUM SIZE
    MaximumSize.QuadPart = 100;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly, STATUS_SUCCESS, STATUS_SUCCESS);

    MaximumSize.QuadPart = -1;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly, STATUS_SECTION_TOO_BIG, STATUS_SUCCESS);
    
    MaximumSize.QuadPart = 0;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleReadOnly, STATUS_SUCCESS, STATUS_SUCCESS);
    
    //allocation type
    CREATE_SECTION(Section, SECTION_MAP_READ, &ObjectAttributesWriteOnly, MaximumSize, PAGE_WRITECOPY, SEC_IMAGE, FileHandleWriteOnly, STATUS_INVALID_IMAGE_NOT_MZ, STATUS_SUCCESS);

    //PAGE PROTECTION
  /*  CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesReadOnly, MaximumSize, PAGE_READWRITE, SEC_COMMIT, FileHandleReadOnly, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesReadOnly, MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, FileHandleReadOnly, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesWriteOnly, MaximumSize, PAGE_READONLY, SEC_COMMIT, FileHandleWriteOnly, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesWriteOnly, MaximumSize, PAGE_READWRITE, SEC_COMMIT, FileHandleWriteOnly, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesWriteOnly, MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, FileHandleWriteOnly, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesWriteOnly, MaximumSize, PAGE_EXECUTE_READ, SEC_COMMIT, FileHandleWriteOnly, STATUS_INVALID_PAGE_PROTECTION, IGNORE); 
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesWriteOnly, MaximumSize, PAGE_WRITECOPY, SEC_COMMIT, FileHandleWriteOnly, STATUS_INVALID_PAGE_PROTECTION, IGNORE); 
    
   */ 

}

static
VOID
BasicBehaviorChecks(VOID) 
{
    NTSTATUS Status;
    HANDLE Section = NULL;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    PFILE_OBJECT File;
    LARGE_INTEGER Length;
    Length.QuadPart = TestStringSize;


    //mimic lack of section support for a particular file.
    Status = ZwCreateFile(&FileHandle, GENERIC_READ, &KmtestFileObject, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
    
    if (NT_SUCCESS(Status))
    {
        Status = ObReferenceObjectByHandle(FileHandle, STANDARD_RIGHTS_ALL, IoFileObjectType, KernelMode, &File, NULL);
        if (NT_SUCCESS(Status))  
        {
            
            PSECTION_OBJECT_POINTERS Pointers = File->SectionObjectPointer;

            File->SectionObjectPointer = NULL;
            CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, Length, PAGE_READONLY, SEC_COMMIT, FileHandle, STATUS_INVALID_FILE_FOR_SECTION, IGNORE);
            File->SectionObjectPointer = Pointers;
            ObDereferenceObject(File);
        }

        ZwClose(FileHandle);
    }

    //check normal section query 
    Status = ZwCreateFile(&FileHandle, GENERIC_READ, &KmtestFileObject, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, (FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE), NULL, 0); 
    if(NT_SUCCESS(Status))
    {
       CREATE_SECTION(Section, (SECTION_ALL_ACCESS), NULL, Length, PAGE_READONLY, SEC_COMMIT, FileHandle, STATUS_SUCCESS, NO_HANDLE_CLOSE);
       CheckObject(Section, 2, 1);
       CheckSection(Section, SEC_FILE, Length.QuadPart, STATUS_SUCCESS);
       ZwClose(FileHandle);
       ZwClose(Section); //we have to manually close it due to NO_HANDLE_CLOSE in CREATE_SECTION
       Section = NULL;
    }

    //check zero-based section
    Status = ZwCreateFile(&FileHandle, (GENERIC_WRITE | SYNCHRONIZE), &KmtestFileObject, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, (FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE), NULL, 0);
    if (NT_SUCCESS(Status))
    {
        Length.QuadPart = 0;
        CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, Length, PAGE_READONLY, SEC_COMMIT, FileHandle, STATUS_MAPPED_FILE_SIZE_ZERO, IGNORE);
        ZwClose(FileHandle);
    }
}


START_TEST(ZwCreateSection) 
{
    HANDLE FileHandleReadOnly = NULL;
    HANDLE FileHandleWriteOnly = NULL;

    InitializeObjectAttributes(&NtdllObject, &FileReadOnlyPath, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    InitializeObjectAttributes(&KmtestFileObject, &WritableFilePath, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    KmtInitTestFiles(&FileHandleReadOnly, &FileHandleWriteOnly);

    SimpleErrorChecks(FileHandleReadOnly, FileHandleWriteOnly); 

    if(FileHandleReadOnly)
        ZwClose(FileHandleReadOnly);

    if(FileHandleWriteOnly)
        ZwClose(FileHandleWriteOnly);

    BasicBehaviorChecks();

    
}