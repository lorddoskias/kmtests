/*
* PROJECT:         ReactOS kernel-mode tests
* LICENSE:         GPLv2+ - See COPYING in the top level directory
* PURPOSE:         Kernel-Mode Test Suite ZwCreateSection
* PROGRAMMER:      Nikolay Borisov <nib9@aber.ac.uk>
*/

#include <kmt_test.h>

#define IGNORE -999
#define _4mb 4194304
extern const char TestString[];
extern const SIZE_T TestStringSize;
static UNICODE_STRING FileReadOnly = RTL_CONSTANT_STRING(L"\\SystemRoot\\system32\\ntdll.dll");
static UNICODE_STRING FileWriteOnly = RTL_CONSTANT_STRING(L"\\SystemRoot\\kmtest-MmSection.txt");
static OBJECT_ATTRIBUTES NtdllObject;
static OBJECT_ATTRIBUTES KmtestFileObject;

/* http://picturoku.blogspot.co.uk/2011/07/pointers-for-user-shared-data.html */
static PKUSER_SHARED_DATA UserSharedData = (PKUSER_SHARED_DATA)0xffdf0000;

#define CREATE_SECTION(Handle, DesiredAccess, Attributes, Size, SectionPageProtection, AllocationAttributes, FileHandle,  RetStatus, CloseRetStatus)  do    \
    {                                                                                                                                                       \
        Status = ZwCreateSection(&Handle, DesiredAccess, Attributes, &Size, SectionPageProtection, AllocationAttributes, FileHandle);                       \
        ok_eq_hex(Status, RetStatus);                                                                                                                       \
        if(Handle != NULL)                                                                                                                                  \
        {                                                                                                                                                   \
           Status = ZwClose(Handle);                                                                                                                        \
           if (CloseRetStatus != IGNORE) ok_eq_hex(Status, CloseRetStatus);                                                                                 \
            Handle = NULL;                                                                                                                                  \
        }                                                                                                                                                   \
    } while (0)                                                                                                                                             \


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
    CREATE_SECTION(Section, NULL, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, -1, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);

    //OBJECT ATTRIBUTES 
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &ObjectAttributesReadOnly, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, &InvalidObjectAttributes, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_SUCCESS);

    //MAXIMUM SIZE
    MaximumSize.QuadPart = -1;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SECTION_TOO_BIG, IGNORE);

    MaximumSize.QuadPart = 0;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_INVALID_PARAMETER_4, IGNORE);
   
    MaximumSize.QuadPart = (_4mb / UserSharedData->LargePageMinimum) * UserSharedData->LargePageMinimum; //4mb 
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_LARGE_PAGES | SEC_COMMIT), NULL, STATUS_SUCCESS, STATUS_SUCCESS);
   
    MaximumSize.QuadPart = TestStringSize;

    //SECTION PAGE PROTECTION
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_EXECUTE_READ, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_EXECUTE_WRITECOPY, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READONLY, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, (PAGE_EXECUTE_READ | PAGE_READWRITE), SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, (PAGE_READONLY | PAGE_READWRITE), SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, IGNORE);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, (PAGE_WRITECOPY | PAGE_READONLY), SEC_COMMIT, NULL, STATUS_INVALID_PAGE_PROTECTION, IGNORE);

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
    Status = ZwCreateFile(&FileHandle, GENERIC_READ, &KmtestFileObject, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, (FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE), NULL, 0);
    
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

    InitializeObjectAttributes(&NtdllObject, &FileReadOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    InitializeObjectAttributes(&KmtestFileObject, &FileWriteOnly, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    KmtInitTestFiles(&FileHandleReadOnly, &FileHandleWriteOnly);

    SimpleErrorChecks(FileHandleReadOnly, FileHandleWriteOnly); 

    if(FileHandleReadOnly)
        ZwClose(FileHandleReadOnly);

    if(FileHandleWriteOnly)
        ZwClose(FileHandleWriteOnly);

    BasicBehaviorChecks();

    
}