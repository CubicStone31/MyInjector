#include "SetWindowHookInjection.h"
#include <windows.h>
#include "Common.h"
#include <memory>
#include <tlhelp32.h>

#pragma pack(push, 1)
struct SetWindowHookInjectionParam 
{
    DWORD targetPid;
    wchar_t dllPath[1024];
};
#pragma pack(pop)

/// <summary>
/// Returns a thread id which belongs to target process
/// </summary>
/// <param name="pid"></param>
/// <returns></returns>
DWORD GetProcessThread(DWORD pid)
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        Common::ThrowException("CreateToolHelp32Snapshot() failed with last error: %d.", GetLastError());
    }
    auto handleDeleter = [](HANDLE h) -> void { CloseHandle(h); };
    std::unique_ptr<void, decltype(handleDeleter)> holder1(snapshot, handleDeleter);

    THREADENTRY32 threadData = {};
    threadData.dwSize = sizeof(threadData);
    if (!Thread32First(snapshot, &threadData))
    {
        Common::ThrowException("Thread32First() failed with last error: %d.", GetLastError());
    }
    if (threadData.th32OwnerProcessID == pid)
    {
        return threadData.th32ThreadID;
    }
    while (true)
    {
        threadData.dwSize = sizeof(threadData);
        if (!Thread32Next(snapshot, &threadData))
        {
            break;
        }
        if (threadData.th32OwnerProcessID == pid)
        {
            return threadData.th32ThreadID;
        }
    }
    Common::ThrowException("No thread is found in process %d.", pid);

    // It won't be executed, just to make compiler happy
    return 0;
}

struct EnumWindowParam
{
    DWORD targetPid;
    HWND outWindow;
};

void TriggerWindowsHook(DWORD pid, DWORD tid)
{
    // 1. Get target process's window, any of them.
    EnumWindowParam param = {};
    param.targetPid = pid;
    EnumWindows([](HWND handle, LPARAM param) -> BOOL {
        DWORD processId = 0;
        EnumWindowParam* p = (EnumWindowParam*)param;
        GetWindowThreadProcessId(handle, &processId);
        if (processId == p->targetPid)
        {
            p->outWindow = handle;
            return false;
        }
        return true;
    }, (LPARAM)&param);

    if (param.outWindow == 0)
    {
        Common::ThrowException("Cannot get target process's window.");
    }

    SendMessageW(param.outWindow, WM_ACTIVATE, WA_CLICKACTIVE, 0);
    SendMessageW(param.outWindow, WM_MOUSEMOVE, MK_LBUTTON, rand());
    SendMessageW(param.outWindow, WM_ACTIVATEAPP, TRUE, tid);

    Sleep(2000);
}



void SetWindowsHookInjectionMgr::DoInjection(int pid, const std::filesystem::path& dllPath, const std::vector<std::string>& methods)
{
    auto fileMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SetWindowHookInjectionParam), L"WINDOWHOOK-PARAM-CUBIC");
    if (!fileMap)
    {
        Common::ThrowException("CreateFileMappingW() failed with last error %d.", GetLastError());
    }
    auto deleter = [](HANDLE h) -> void { CloseHandle(h); };
    std::unique_ptr<void, decltype(deleter)> holder1(fileMap, deleter);
    SetWindowHookInjectionParam* view = (SetWindowHookInjectionParam*)MapViewOfFile(fileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!view)
    {
        Common::ThrowException("MapViewOfFile() failed with last error %d.", GetLastError());
    }
    auto deleter2 = [](void* p) -> void { if (p) UnmapViewOfFile(p); };
    std::unique_ptr<void, decltype(deleter2)> holder2(view, deleter2);

    view->targetPid = pid;
    if (wcscpy_s(view->dllPath, dllPath.wstring().c_str()))
    {
        Common::ThrowException("wcscpy_s() error(File path too long?).");
    }

#ifdef _WIN64
    std::filesystem::path container = Common::GetMainModuleFolder() / "WindowHookContainer_x64.dll";
#else
    std::filesystem::path container = Common::GetMainModuleFolder() / "WindowHookContainer_x86.dll";
#endif
    auto containerModule = LoadLibraryW(container.wstring().c_str());
    if (!containerModule)
    {
        Common::ThrowException("Load window hook container failed with last error %d.", GetLastError());
    }
    auto handler = GetProcAddress(containerModule, "WindowHookProc");
    if (!handler)
    {
        Common::ThrowException("WindowHookProc is not found in container dll.");
    }

    auto targetThread = GetProcessThread(pid);
    auto hook = SetWindowsHookExW(WH_CBT, (HOOKPROC)handler, containerModule, targetThread);
    if (!hook)
    {
        Common::ThrowException("SetWindowsHookExW() failed with last error %d.", GetLastError());
    }
    auto deleter3 = [](void* h) -> void {  UnhookWindowsHookEx((HHOOK)h); };
    std::unique_ptr<void, decltype(deleter3)> holder3(hook, deleter3);

    TriggerWindowsHook(pid, targetThread);
}

bool SetWindowsHookInjectionMgr::CheckParameters(const std::vector<std::string>& methods)
{
    return false;
}
