/*
* PROJECT:         ReactOS kernel-mode tests
* LICENSE:         GPLv2+ - See COPYING in the top level directory
* PURPOSE:         Kernel-Mode Test Suite Driver
* PROGRAMMER:      Thomas Faber <thfabba@gmx.de>
*/

#include <kmt_test.h>

#include "kmtest.h"
#include <kmt_public.h>

#include <assert.h>

extern HANDLE KmtestHandle;

// set to true when the current test run is finished.
BOOLEAN KmtFinishedTest;

/**
* @name KmtUserCallbackThread
*
* Routine which awaits callback requests from kernel-mode
*
*
* @return Win32 error code as returned by DeviceIoControl/HeapAlloc/VirtualQuery
*/
DWORD WINAPI 
KmtUserCallbackThread(LPVOID Unused) 
{ 
    DWORD Error = ERROR_SUCCESS;
    CALLBACK_REQUEST_PACKET OutputBuffer;
    SIZE_T UserReturned;
    PVOID Response;
    DWORD BytesReturned;
    HANDLE LocalKmtHandle = INVALID_HANDLE_VALUE;

    printf("[USERMODE CALLBACK] Thread started\n");

    //avoid a deadlock shitty deadlock. For more info http://www.osronline.com/showthread.cfm?link=230782
    LocalKmtHandle = CreateFile(KMTEST_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    while(!KmtFinishedTest) {
        
        if(DeviceIoControl(LocalKmtHandle, IOCTL_KMTEST_USERMODE_AWAIT_REQ, NULL, 0,  &OutputBuffer, sizeof(OutputBuffer), &BytesReturned, NULL)) 
        {
            switch(OutputBuffer.OperationType) 
            {
            case QueryVirtualMemory:
                { 

                    Response  = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORY_BASIC_INFORMATION));
                    if(NULL == Response) 
                    {
                        error_goto(Error, cleanup);
                        
                    }

                    UserReturned = VirtualQuery(OutputBuffer.Parameters, Response, sizeof(MEMORY_BASIC_INFORMATION));
                    if(0 == UserReturned) 
                    {
                        error_goto(Error, cleanup);
                        
                    }

                    if(!DeviceIoControl(LocalKmtHandle, IOCTL_KMTEST_USERMODE_SEND_RESPONSE, Response, sizeof(MEMORY_BASIC_INFORMATION), NULL, 0, NULL, NULL))
                    {
                        
                        error_goto(Error, cleanup);
                       
                    }

                    HeapFree(GetProcessHeap(),  0, Response);
                    break;
                }    

            default: 
                {
                    printf("UNRECOGNISED USER-MODE CALLBACK REQUEST\n");
                    break;
                }

            }
        } else 
        {
            error_goto(Error, cleanup);
        }
    }


cleanup:
    if(LocalKmtHandle != INVALID_HANDLE_VALUE) 
    {
        CloseHandle(LocalKmtHandle);
    }

    return Error;
}




/**
* @name KmtRunKernelTest
*
* Run the specified kernel-mode test part
*
* @param TestName
*        Name of the test to run
*
* @return Win32 error code as returned by DeviceIoControl
*/
DWORD
    KmtRunKernelTest(
    IN PCSTR TestName)
{
    DWORD Error = ERROR_SUCCESS;
    HANDLE CallbackThread; 
    DWORD BytesRead;

	KmtFinishedTest = FALSE;

    CallbackThread = CreateThread(NULL, 0, KmtUserCallbackThread, NULL, 0, NULL);

    if (!DeviceIoControl(KmtestHandle, IOCTL_KMTEST_RUN_TEST, (PVOID)TestName, (DWORD)strlen(TestName), NULL, 0, &BytesRead, NULL))
        error(Error);

    KmtFinishedTest = TRUE;
    CloseHandle(CallbackThread);
    return Error;
}



static WCHAR TestServiceName[MAX_PATH];
static SC_HANDLE TestServiceHandle;
static HANDLE TestDeviceHandle;

/**
* @name KmtLoadDriver
*
* Load the specified special-purpose driver (create/start the service)
*
* @param ServiceName
*        Name of the driver service (Kmtest- prefix will be added automatically)
* @param RestartIfRunning
*        TRUE to stop and restart the service if it is already running
*/
VOID
    KmtLoadDriver(
    IN PCWSTR ServiceName,
    IN BOOLEAN RestartIfRunning)
{
    DWORD Error = ERROR_SUCCESS;
    WCHAR ServicePath[MAX_PATH];

    StringCbCopy(ServicePath, sizeof ServicePath, ServiceName);
    StringCbCat(ServicePath, sizeof ServicePath, L"_drv.sys");

    StringCbCopy(TestServiceName, sizeof TestServiceName, L"Kmtest-");
    StringCbCat(TestServiceName, sizeof TestServiceName, ServiceName);

    Error = KmtCreateAndStartService(TestServiceName, ServicePath, NULL, &TestServiceHandle, RestartIfRunning);

    if (Error)
    {
        // TODO
        __debugbreak();
    }
}

/**
* @name KmtUnloadDriver
*
* Unload special-purpose driver (stop the service)
*/
VOID
    KmtUnloadDriver(VOID)
{
    DWORD Error = ERROR_SUCCESS;

    Error = KmtStopService(TestServiceName, &TestServiceHandle);

    if (Error)
    {
        // TODO
        __debugbreak();
    }
}

/**
* @name KmtOpenDriver
*
* Open special-purpose driver (acquire a device handle)
*/
VOID
    KmtOpenDriver(VOID)
{
    DWORD Error = ERROR_SUCCESS;
    WCHAR DevicePath[MAX_PATH];

    StringCbCopy(DevicePath, sizeof DevicePath, L"\\\\.\\Global\\GLOBALROOT\\Device\\");
    StringCbCat(DevicePath, sizeof DevicePath, TestServiceName);

    TestDeviceHandle = CreateFile(DevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (TestDeviceHandle == INVALID_HANDLE_VALUE)
        error(Error);

    if (Error)
    {
        // TODO
        __debugbreak();
    }

}

/**
* @name KmtCloseDriver
*
* Close special-purpose driver (close device handle)
*/
VOID
    KmtCloseDriver(VOID)
{
    DWORD Error = ERROR_SUCCESS;

    if (TestDeviceHandle && !CloseHandle(TestDeviceHandle))
        error(Error);

    if (Error)
    {
        // TODO
        __debugbreak();
    }
}

/**
* @name KmtSendToDriver
*
* Unload special-purpose driver (stop the service)
*
* @param ControlCode
*
* @return Win32 error code as returned by DeviceIoControl
*/
DWORD
    KmtSendToDriver(
    IN DWORD ControlCode)
{
    DWORD BytesRead;

    assert(ControlCode < 0x400);

    if (!DeviceIoControl(TestDeviceHandle, KMT_MAKE_CODE(ControlCode), NULL, 0, NULL, 0, &BytesRead, NULL))
        return GetLastError();

    return ERROR_SUCCESS;
}

/**
* @name KmtSendStringToDriver
*
* Unload special-purpose driver (stop the service)
*
* @param ControlCode
* @param String
*
* @return Win32 error code as returned by DeviceIoControl
*/
DWORD
    KmtSendStringToDriver(
    IN DWORD ControlCode,
    IN PCSTR String)
{
    DWORD BytesRead;

    assert(ControlCode < 0x400);

    if (!DeviceIoControl(TestDeviceHandle, KMT_MAKE_CODE(ControlCode), (PVOID)String, (DWORD)strlen(String), NULL, 0, &BytesRead, NULL))
        return GetLastError();

    return ERROR_SUCCESS;
}

/**
* @name KmtSendBufferToDriver
*
* @param ControlCode
* @param Buffer
* @param InLength
* @param OutLength
*
* @return Win32 error code as returned by DeviceIoControl
*/
DWORD
    KmtSendBufferToDriver(
    IN DWORD ControlCode,
    IN OUT PVOID Buffer OPTIONAL,
    IN DWORD InLength,
    IN OUT PDWORD OutLength)
{
    assert(OutLength);
    assert(Buffer || (!InLength && !*OutLength));
    assert(ControlCode < 0x400);

    if (!DeviceIoControl(TestDeviceHandle, KMT_MAKE_CODE(ControlCode), Buffer, InLength, Buffer, *OutLength, OutLength, NULL))
        return GetLastError();

    return ERROR_SUCCESS;
}