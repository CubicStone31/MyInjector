#include "interface.h"
#include <vector>

class KernelAccess
{
public:
    KernelAccess();

    KernelAccess(const KernelAccess& another) = delete;

    ~KernelAccess();

    void* AllocateRemoteMemory(DWORD pid, void* addr, DWORD length, DWORD protect);

    void ReadProcessMemory(DWORD pid, void* addr, DWORD length, std::vector<BYTE>& out);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="pid"></param>
    /// <param name="addr"></param>
    /// <param name="data"></param>
    /// <returns>Number of bytes written</returns>
    DWORD WriteProcessMemory(DWORD pid, void* addr, const std::vector<BYTE>& data);

    /// <summary>
    /// OpenProcess like the win32 api
    /// </summary>
    /// <param name="pid"></param>
    /// <param name="access"></param>
    /// <returns>return a kernel handle</returns>
    UINT64 OpenProcess(DWORD pid, DWORD access);

    /// <summary>
    /// Close the handle
    /// </summary>
    /// <param name="h"></param>
    void CloseHandle(UINT64 h);

    /// <summary>
    /// Just like the win32 api
    /// </summary>
    /// <param name="process">use a kernel handle by calling KernelAccesss::OpenProcess</param>
    /// <param name="processInfoClass"></param>
    /// <param name="data"></param>
    /// <param name="len"></param>
    void SetInformationProcess(UINT64 process, DWORD processInfoClass, const std::vector<BYTE>& data);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="pid"></param>
    /// <param name="addr"></param>
    /// <param name="param"></param>
    /// <param name="flag"></param>
    /// <returns>the thread id of the newly created thread</returns>
    DWORD CreateRemoteThread(DWORD pid, void* addr, void* param, DWORD flag);

    void QueueUserAPC(DWORD tid, void* addr, void* param, bool forceExecute);

private:
    HANDLE driverHandle = NULL;
};