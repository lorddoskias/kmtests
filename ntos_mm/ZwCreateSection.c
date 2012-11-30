/*
* PROJECT:         ReactOS kernel-mode tests
* LICENSE:         GPLv2+ - See COPYING in the top level directory
* PURPOSE:         Kernel-Mode Test Suite ZwCreateSection
* PROGRAMMER:      Nikolay Borisov <nib9@aber.ac.uk>
*/

#include <kmt_test.h>

#define IGNORE -999

#define CREATE_SECTION(Handle, DesiredAccess, Attributes, Size, SectionPageProtection, AllocationAttributes, FileHandle,  RetStatus, CloseRetStatus)  do    \
    {                                                                                                                                                       \
        Status = ZwCreateSection(&Handle, DesiredAccess, Attributes, &Size, SectionPageProtection, AllocationAttributes, FileHandle);                       \
        ok_eq_hex(Status, RetStatus);                                                                                                                       \
        if(Handle != NULL)                                                                                                                                  \
        {                                                                                                                                                   \
            Status = ZwClose(Handle);                                                                                                                       \
            if (CloseRetStatus != IGNORE) ok_eq_hex(Status, CloseRetStatus);                                                                                \
            Handle = NULL;                                                                                                                                  \
        }                                                                                                                                                   \
    } while (0)                                                                                                                                             \

static
VOID 
SimpleErrorChecks(VOID) 
{
    NTSTATUS Status;
    HANDLE Section = NULL;
    HANDLE FileHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER MaximumSize;
    UNICODE_STRING SectionName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\KmtTestSection");

    MaximumSize.QuadPart = 200; 

    //PAGE FILE BACKED SECTION
    //DESIRED ACCESS TESTS
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, NULL, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, -1, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SUCCESS, STATUS_SUCCESS);

    //MAXIMUM SIZE
    MaximumSize.QuadPart = -1;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_SECTION_TOO_BIG, IGNORE);

    MaximumSize.QuadPart = 0;
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL, STATUS_INVALID_PARAMETER_4, IGNORE);

    MaximumSize.QuadPart = 200;

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
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, SEC_NOCACHE, NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_NOCACHE | SEC_RESERVE | SEC_COMMIT), NULL, STATUS_INVALID_PARAMETER_6, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_NOCACHE | SEC_COMMIT), NULL, STATUS_SUCCESS, STATUS_SUCCESS);
    CREATE_SECTION(Section, SECTION_ALL_ACCESS, NULL, MaximumSize, PAGE_READWRITE, (SEC_NOCACHE | SEC_RESERVE), NULL, STATUS_SUCCESS, STATUS_SUCCESS);

}



START_TEST(ZwCreateSection) 
{
    SimpleErrorChecks(); 
}