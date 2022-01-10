// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"
#include <string>
#include <thread>
#include <winternl.h>

#pragma pack(push, 1)
struct SetWindowHookInjectionParam
{
    DWORD targetPid;
    wchar_t dllPath[1024];
};
#pragma pack(pop)

std::wstring GetTargetDllPath()
{
    auto fileMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, false, L"WINDOWHOOK-PARAM-CUBIC");
    if (!fileMap)
    {
        return L"";
    }
    auto view = (SetWindowHookInjectionParam*)MapViewOfFile(fileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!view)
    {
        CloseHandle(fileMap);
        return L"";
    }
    if (view->targetPid != GetCurrentProcessId())
    {
        UnmapViewOfFile(view);
        CloseHandle(fileMap);
        return L"";
    }
    std::wstring ret = view->dllPath;
    UnmapViewOfFile(view);  
    CloseHandle(fileMap);
    return ret;
}

void Payload()
{
    auto dllPath = GetTargetDllPath();
    if (dllPath == L"")
    {
        return;
    }
    UNICODE_STRING path = {};
    auto Func_RtlInitUnicodeString = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(GetProcAddress(GetModuleHandleW(L"NTDLL"), "RtlInitUnicodeString"));
    Func_RtlInitUnicodeString(&path, dllPath.c_str());
    auto Func_LdrLoadDll = reinterpret_cast<void*(__stdcall*)(void*, void*, void*, void*)>(GetProcAddress(GetModuleHandleW(L"NTDLL"), "LdrLoadDll"));
    void* out;
    Func_LdrLoadDll(0, 0, &path, &out);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        std::thread t([]() -> void {
            Payload();
            });
        t.detach();
        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

