#include "KC_usermode.h"
#include <windows.h>
#include "interface.h"
#include <cstdlib>
#include <time.h>
#include <memory>

HANDLE G_Driver = INVALID_HANDLE_VALUE;
uint32_t DriverReferenceCount = 0;

bool KernelCorridor::CreateDriverServiceAndLoadDriver(const std::wstring& driver_file_path, const std::wstring& service_name, bool append_random_suffix, std::wstring& actual_service_name)
{
    DWORD dwAttrib = GetFileAttributesW(driver_file_path.c_str());
    if (dwAttrib == INVALID_FILE_ATTRIBUTES || (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
    {
        return false;
    }
    auto service_mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (service_mgr == NULL)
    {
        return false;
    }
    if (append_random_suffix)
    {
        srand(time(0));
        auto random_number = rand() & 0xffff;
        actual_service_name = service_name + L"_" + std::to_wstring(random_number);
    }
    else
    {
        actual_service_name = service_name;
    }
    auto service = CreateServiceW(service_mgr,
        actual_service_name.c_str(),
        actual_service_name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driver_file_path.c_str(),
        0,
        0,
        0,
        0,
        0);
    if (!service)
    {
        // maybe a previous service exists
        if (ERROR_SERVICE_EXISTS == GetLastError())
        {
            // try to delete it
            auto previous_service = OpenServiceW(service_mgr, actual_service_name.c_str(), SERVICE_ALL_ACCESS);
            if (!previous_service)
            {
                CloseServiceHandle(service_mgr);
                return false;
            }
            SERVICE_STATUS_PROCESS status = {};
            DWORD bytesNeeded = 0;
            if (!QueryServiceStatusEx(previous_service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &bytesNeeded))
            {
                CloseServiceHandle(previous_service);
                CloseServiceHandle(service_mgr);
                return false;
            }
            if (status.dwCurrentState != SERVICE_STOPPED)
            {
                // still running ? 
                CloseServiceHandle(previous_service);
                CloseServiceHandle(service_mgr);
                return false;
            }
            // so there is a previous registered service, and it is not running now
            // delete it!
            if (!DeleteService(previous_service))
            {
                CloseServiceHandle(previous_service);
                CloseServiceHandle(service_mgr);
                return false;
            }
            CloseServiceHandle(previous_service);
            // now register our new service again
            service = CreateServiceW(service_mgr,
                actual_service_name.c_str(),
                actual_service_name.c_str(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                driver_file_path.c_str(),
                0,
                0,
                0,
                0,
                0);
            if (!service)
            {
                // failed again??
                CloseServiceHandle(service_mgr);
                return false;
            }
        }
        else
        {
            // cannot create a new service, failed
            CloseServiceHandle(service_mgr);
            return false;
        }
    }
    // service registered, start it now
    if (!StartServiceW(service, 0, 0))
    {
        // failed to load driver, delete the newly registered service
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    // driver loaded successfully
    CloseServiceHandle(service);
    CloseServiceHandle(service_mgr);
    return true;
}

bool KernelCorridor::StopDriverServiceAndDeleteIt(const std::wstring& kernel_service_name)
{
    auto service_mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!service_mgr)
    {
        return false;
    }
    auto service = OpenServiceW(service_mgr, kernel_service_name.c_str(), SERVICE_ALL_ACCESS);
    if (!service)
    {
        CloseServiceHandle(service_mgr);
        return false;
    }
    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &bytesNeeded))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    if (status.dwCurrentState == SERVICE_STOPPED)
    {
        if (!DeleteService(service))
        {
            CloseServiceHandle(service);
            CloseServiceHandle(service_mgr);
            return false;
        }
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return true;
    }
    SERVICE_STATUS svcStatus = {};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &svcStatus))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    if (svcStatus.dwCurrentState != SERVICE_STOPPED)
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    if (!DeleteService(service))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(service_mgr);
    return true;
}

bool KernelCorridor::Open()
{
    G_Driver = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == G_Driver)
    {
        return false;
    }
    DriverReferenceCount += 1;
    return true;
}

void KernelCorridor::Close()
{
    if (DriverReferenceCount)
    {
        DriverReferenceCount -= 1;
        if (!DriverReferenceCount)
        {
            CloseHandle(G_Driver);
            G_Driver = INVALID_HANDLE_VALUE;
        }
    }
}

bool KernelCorridor::WriteProcessMemory(uint32_t pid, uint64_t address_to_write, const std::vector<uint8_t>& data, uint32_t& bytes_written, uint32_t method_id)
{
    KCProtocols::REQUEST_WRITE_PROCESS_MEM* request = (KCProtocols::REQUEST_WRITE_PROCESS_MEM*)malloc(sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + data.size());
    request->addr = address_to_write;
    request->method = (KCProtocols::MEM_ACCESS_METHOD)method_id;
    request->pid = pid;
    request->size = data.size();
    memcpy(request->data, data.data(), data.size());
    KCProtocols::RESPONSE_WRITE_PROCESS_MEM response = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_WRITE_PROCESS_MEM, request, sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + data.size(), &response, sizeof(response), &bytesReturned, 0))
    {
        return false;
    }
    bytes_written = response.bytesWritten;
    return true;
}

bool KernelCorridor::ReadProcessMemory(uint32_t pid, uint64_t address_to_read, uint32_t length_to_read, std::vector<uint8_t>& out, uint32_t method_id)
{
    KCProtocols::REQUEST_READ_PROCESS_MEM request = {};
    request.pid = pid;
    request.addr = address_to_read;
    request.size = length_to_read;
    request.method = (KCProtocols::MEM_ACCESS_METHOD)method_id;
    KCProtocols::RESPONSE_READ_PROCESS_MEM* response = (KCProtocols::RESPONSE_READ_PROCESS_MEM*)malloc(sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + length_to_read);
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_READ_PROCESS_MEM, &request, sizeof(request), response, sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + length_to_read, &bytesReturned, 0))
    {
        return false;
    }
    out = { response->data, response->data + response->size };
    return true;
}

bool KernelCorridor::SetThreadContext(uint32_t tid, CONTEXT* ctx)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_SET_THREAD_CONTEXT*)&protocol_buffer;
    request->tid = tid;
    request->ctx = ctx;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_SET_THREAD_CONTEXT, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return false;
    }
    return true;
}

bool KernelCorridor::GetThreadContext(uint32_t tid, CONTEXT* ctx)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_GET_THREAD_CONTEXT*)&protocol_buffer;
    request->tid = tid;
    request->ctx = ctx;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_GET_THREAD_CONTEXT, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return false;
    }
    return true;
}

bool KernelCorridor::AllocProcessMemory(uint32_t pid, uint64_t* base, uint32_t* size, uint32_t protect)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_ALLOC_PROCESS_MEM*)&protocol_buffer;
    request->pid = pid;
    request->addr = *base;
    request->length = *size;
    request->protect = protect;
    request->isFree = 0;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_ALLOC_PROCESS_MEM, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return false;
    }
    auto response = (KCProtocols::RESPONSE_ALLOC_PROCESS_MEM*)request;
    *base = response->base;
    *size = response->size;
    return true;
}

bool KernelCorridor::FreeAllocedProcessMemory(uint32_t pid, uint64_t base)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_ALLOC_PROCESS_MEM*)&protocol_buffer;
    request->pid = pid;
    request->addr = base;
    request->isFree = 1;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_ALLOC_PROCESS_MEM, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return false;
    }
    return true;
}

HANDLE KernelCorridor::OpenProcess(uint32_t pid, uint32_t access, bool request_kernel_mode_handle)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_OPEN_PROCESS*)&protocol_buffer;
    request->access = access;
    request->pid = pid;
    request->request_user_mode_handle = !request_kernel_mode_handle;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_OPEN_PROCESS, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return NULL;
    }
    auto response = (KCProtocols::RESPONSE_OPEN_PROCESS*)request;
    return (HANDLE)response->handle;
}

bool KernelCorridor::KCCloseHandle(HANDLE handle)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_CLOSE_HANDLE*)&protocol_buffer;
    request->handle = (UINT64)handle;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_CLOSE_HANDLE, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return false;
    }
    return true;
}

bool KernelCorridor::SetInformationProcess(uint64_t handle, uint32_t process_info_class, const std::vector<uint8_t>& data)
{
    auto requestSize = sizeof(KCProtocols::REQUEST_SET_INFORMATION_PROCESS) + data.size();
    auto buffer = std::make_unique<uint8_t>(requestSize);
    auto request = (KCProtocols::REQUEST_SET_INFORMATION_PROCESS*)buffer.get();
    request->handle = handle;
    request->processInformationClass = process_info_class;
    request->processInformationLength = data.size();
    memcpy(request->processInformation, data.data(), data.size());
    KCProtocols::RESPONSE_SET_INFORMATION_PROCESS response = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_SET_INFORMATION_PROCESS, request, requestSize, &response, sizeof(response), &bytesReturned, 0))
    {
        return false;
    }
    return true;
}

uint32_t KernelCorridor::CreateRemoteUserThread(uint32_t pid, uint64_t addr, uint64_t param, bool create_suspended)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_CREATE_USER_THREAD*)&protocol_buffer;
    request->createSuspended = create_suspended;
    request->parameter = param;
    request->pid = pid;
    request->startAddr = addr;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_CREATE_USER_THREAD, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return 0;
    }
    auto response = (KCProtocols::RESPONSE_CREATE_USER_THREAD*)&protocol_buffer;
    return response->threadID;
}

bool KernelCorridor::QueueUserAPC(uint32_t tid, uint64_t start_addr, uint64_t param, bool force_execute)
{
    KCProtocols::GENERAL_FIXED_SIZE_PROTOCOL_INPUT_OUTPUT protocol_buffer = {};
    auto request = (KCProtocols::REQUEST_QUEUE_USER_APC*)&protocol_buffer;
    request->tid = tid;
    request->apcRoutine = start_addr;
    request->apcParam = param;
    request->forceExecute = force_execute;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_QUEUE_USER_APC, &protocol_buffer, sizeof(protocol_buffer), &protocol_buffer, sizeof(protocol_buffer), &bytesReturned, 0))
    {
        return false;
    }
    return true;
}
