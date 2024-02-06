#include "KernelAccess.h"
#include "../Common.h"
#include "KC_usermode.h"

bool KernelAccess::IsKernelModuleReady()
{
    if (!KernelCorridor::Open())
    {
        return false;
    }
    KernelCorridor::Close();
    return true;
}

KernelAccess::KernelAccess()
{
    if (!KernelCorridor::Open())
    {
        Common::ThrowException("Cannot open driver. Is the driver correctly loaded?");
    }
}

KernelAccess::~KernelAccess()
{
    ;
}

void* KernelAccess::AllocateRemoteMemory(DWORD pid, void* addr, DWORD length, DWORD protect)
{
    uint64_t alloc_base = (uint64_t)addr;
    uint32_t alloc_size = (uint32_t)length;
    if (!KernelCorridor::AllocProcessMemory(pid, &alloc_base, &alloc_size, protect))
    {
        return 0;
    }
    return (void*)alloc_base;
}

void KernelAccess::ReadProcessMemory(DWORD pid, void* addr, DWORD length, std::vector<BYTE>& out)
{
    KernelCorridor::ReadProcessMemory(pid, (uint64_t)addr, length, out);
}

DWORD KernelAccess::WriteProcessMemory(DWORD pid, void* addr, const std::vector<BYTE>& data)
{
    uint32_t bytes_written = 0;
    KernelCorridor::WriteProcessMemory(pid, (uint64_t)addr, data, bytes_written);
    return bytes_written;
}

UINT64 KernelAccess::OpenProcess(DWORD pid, DWORD access)
{
    auto ret = KernelCorridor::OpenProcess(pid, access, true);
    if (!ret)
    {
        Common::ThrowException("kernel mode openprocess failed.");
    }
    return (UINT64)ret;
}

void KernelAccess::CloseHandle(UINT64 h)
{
    if (!KernelCorridor::KCCloseHandle((HANDLE)h))
    {
        Common::ThrowException("KCCloseHandle() failed.");
    }
    return;
}

void KernelAccess::SetInformationProcess(UINT64 kernelModeHandle, DWORD processInfoClass, const std::vector<BYTE>& data)
{
    if (!KernelCorridor::SetInformationProcess(kernelModeHandle, processInfoClass, data))
    {
        Common::ThrowException("Kernel mode SetInformationProcess failed.");
    }
    return;
}

// todo: param "flag" is not operational
DWORD KernelAccess::CreateRemoteThread(DWORD pid, void* addr, void* param, DWORD flag)
{
    auto ret = KernelCorridor::CreateRemoteUserThread(pid, (uint64_t)addr, (uint64_t)param, 0);
    if (!ret)
    {
        Common::ThrowException("Kernel mode CreateRemoteThread() failed.");
    }
    return ret;
}

void KernelAccess::QueueUserAPC(DWORD tid, void* addr, void* param, bool forceExecute)
{
    if (!KernelCorridor::QueueUserAPC(tid, (uint64_t)addr, (uint64_t)param, forceExecute))
    {
        Common::ThrowException("Kernel mode QueueUserAPC() failed.");
    }
    return;
}
