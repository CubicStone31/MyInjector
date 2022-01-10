// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        wchar_t process[MAX_PATH];
        wchar_t dll[MAX_PATH];
        GetModuleFileNameW(0, process, MAX_PATH);
        GetModuleFileNameW(hModule, dll, MAX_PATH);
        MessageBoxW(0, dll, process, MB_OK | MB_TOPMOST);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return FALSE;
}

