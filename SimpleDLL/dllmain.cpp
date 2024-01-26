// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <windows.h>
#include <exception>

void CppExceptionTest()
{
    try
    {
        throw std::exception("really?");
    }
    catch (std::exception e)
    {
        MessageBoxA(0, "c++ exception ok.", "Exception Test", MB_OK | MB_TOPMOST);
    }
}

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
        if (!GetModuleFileNameW(hModule, dll, MAX_PATH))
        {
            wsprintfW(dll, L"Dll path not available, base 0x%p", (void*)hModule);
        }
        MessageBoxW(0, dll, process, MB_OK | MB_TOPMOST);
        __try
        {
            char* data = 0;
            data[0] = 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            MessageBoxA(0, "SEH is good.", "Exception Test", MB_OK | MB_TOPMOST);
        }
        // CppExceptionTest();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return true;
}

