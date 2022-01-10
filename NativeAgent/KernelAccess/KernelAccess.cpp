#include "KernelAccess.h"
#include "../Common.h"

KernelAccess::KernelAccess()
{
    driverHandle = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == driverHandle)
    {
        Common::ThrowException("Cannot open driver. Is the driver correctly loaded?");
    }
}

KernelAccess::~KernelAccess()
{
    ::CloseHandle(driverHandle);
}

void* KernelAccess::AllocateRemoteMemory(DWORD pid, void* addr, DWORD length, DWORD protect)
{
    KCProtocols::REQUEST_ALLOC_PROCESS_MEM request = {};
    KCProtocols::RESPONSE_ALLOC_PROCESS_MEM response = {};
    request.addr = (UINT64)addr;
    request.length = (UINT32)length;
    request.isFree = false;
    request.pid = pid;
    request.protect = protect;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_ALLOC_PROCESS_MEM, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Allocate memory failed.");
    }
    return (void*)response.base;
}

void KernelAccess::ReadProcessMemory(DWORD pid, void* addr, DWORD length, std::vector<BYTE>& out)
{
    KCProtocols::REQUEST_READ_PROCESS_MEM request = {};
    auto responseSize = sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + length;
    std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(responseSize);
    KCProtocols::RESPONSE_READ_PROCESS_MEM* response = (KCProtocols::RESPONSE_READ_PROCESS_MEM*)buffer.get();

    request.pid = pid;
    request.addr = (UINT64)addr;
    request.size = length;
    request.method = KCProtocols::MEM_ACCESS_METHOD::MmCopyVirtualMemory;  // any of these methods should work
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_READ_PROCESS_MEM, &request, sizeof(request), response, responseSize, &bytesReturned, 0))
    {
        Common::ThrowException("Read process memory failed.");
    }

    out.assign(response->data, response->data + response->size);
}

DWORD KernelAccess::WriteProcessMemory(DWORD pid, void* addr, const std::vector<BYTE>& data)
{
    auto requestSize = sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + data.size();
    std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(requestSize);
    auto request = (KCProtocols::REQUEST_WRITE_PROCESS_MEM*)buffer.get();
    KCProtocols::RESPONSE_WRITE_PROCESS_MEM response = {};
    request->addr = (UINT64)addr;
    request->method = KCProtocols::MEM_ACCESS_METHOD::MmCopyVirtualMemory;
    request->pid = pid;
    request->size = data.size();
    memcpy(request->data, &data[0], data.size());
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_WRITE_PROCESS_MEM, request, requestSize, &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Write process memory failed.");
    }
    return response.bytesWritten;
}

UINT64 KernelAccess::OpenProcess(DWORD pid, DWORD access)
{
    KCProtocols::REQUEST_OPEN_PROCESS request = {};
    KCProtocols::RESPONSE_OPEN_PROCESS response = {};
    request.pid = pid;
    request.access = access;
    response.kernelModeHandle = 0;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_OPEN_PROCESS, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Call to NtOpenProcess() failed.");
    }
    return response.kernelModeHandle;
}

void KernelAccess::CloseHandle(UINT64 h)
{
    KCProtocols::REQUEST_CLOSE_HANDLE request = {};
    KCProtocols::RESPONSE_CLOSE_HANDLE response = {};
    request.kernelModeHandle = h;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_CLOSE_HANDLE, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Call to NtClose() failed.");
    }
    return ;
}

void KernelAccess::SetInformationProcess(UINT64 kernelModeHandle, DWORD processInfoClass, const std::vector<BYTE>& data)
{
    auto requestSize = sizeof(KCProtocols::REQUEST_SET_INFORMATION_PROCESS) + data.size();
    std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(requestSize);
    auto request = (KCProtocols::REQUEST_SET_INFORMATION_PROCESS*)buffer.get();
    KCProtocols::RESPONSE_SET_INFORMATION_PROCESS response = {};
    request->kernelModeHandle = kernelModeHandle;
    request->processInformationClass = processInfoClass;
    request->processInformationLength = data.size();
    memcpy(request->processInformation, &data[0], data.size());
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_SET_INFORMATION_PROCESS, request, requestSize, &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Call to NtSetInformationProcess() failed.");
    }
    return ;
}

DWORD KernelAccess::CreateRemoteThread(DWORD pid, void* addr, void* param, DWORD flag)
{
    KCProtocols::REQUEST_CREATE_USER_THREAD request = {};
    KCProtocols::RESPONSE_CREATE_USER_THREAD response = {};
    request.createSuspended = false;
    request.parameter = (UINT64)param;
    request.pid = pid;
    request.startAddr = (UINT64)addr;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_CREATE_USER_THREAD, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Create remote thread failed.");
    }
    return response.threadID;
}

void KernelAccess::QueueUserAPC(DWORD tid, void* addr, void* param, bool forceExecute)
{
    KCProtocols::REQUEST_QUEUE_USER_APC request = {};
    KCProtocols::RESPONSE_QUEUE_USER_APC response = {};
    request.tid = tid;
    request.apcRoutine = (UINT64)addr;
    request.apcParam = (UINT64)param;
    request.forceExecute = forceExecute;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_QUEUE_USER_APC, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Queue user APC failed.");
    }
    return;
}
