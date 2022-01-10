#pragma once
#include <windows.h>
#include <algorithm>
#include <string>
#include <iostream>
#include <memory>
#include <VersionHelpers.h>
#include <filesystem>

namespace Common
{
    inline void Print(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        int len = _vscprintf(fmt, args) + 1;
        char* formatted = (char*)malloc(len * sizeof(char));
        vsprintf_s(formatted, len, fmt, args);
        va_end(args);      
        std::cout << formatted << std::endl;
        free(formatted);
    }

    /// <summary>
    /// Caution: memory leak in this function
    /// </summary>
    /// <param name="fmt"></param>
    /// <param name=""></param>
    inline void ThrowException(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        int len = _vscprintf(fmt, args) + 1;
        static char* buffer = (char*)malloc(1024 * 1024);
        vsprintf_s(buffer, len, fmt, args);
        va_end(args);
        throw std::exception(buffer);
    }

    inline std::wstring StringToWString(const std::string& str, UINT codePage = CP_ACP) 
    {
        int num = MultiByteToWideChar(codePage, 0, str.c_str(), -1, NULL, 0);
        wchar_t* wide = new wchar_t[num];
        MultiByteToWideChar(codePage, 0, str.c_str(), -1, wide, num);
        std::wstring w_str(wide);
        delete[] wide;
        return w_str;
    }

    inline std::string WStringToString(const std::wstring& wstr, UINT codePage = CP_ACP)
    {
        int num = WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, NULL, 0, 0, 0);
        char* converted = (char*)malloc(num + 1);
        WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, converted, num + 1, 0, 0);
        std::string ret = converted;
        free(converted);
        return ret;
    }

    /// <summary>
    /// Get Windows version
    /// </summary>
    /// <param name="winVer">out: 10 for windows 10, 8 for win8 and 7 for win7. Any other version will be 0</param>
    inline void GetWindowsVersion(DWORD& winVer)
    {
        //winVer = 0;
        //if (IsWindows10OrGreater())
        //{
        //    winVer = 10;
        //    return;
        //}
        //if (IsWindows8OrGreater())
        //{
        //    winVer = 8;
        //    return;
        //}
        //if (IsWindows7OrGreater())
        //{
        //    winVer = 7; 
        //    return;
        //}
        //return;
        // IsWindowsXXXOrGreater() is not reliable, fuck it.

        using RtlGetVersionFunc =  NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
        RtlGetVersionFunc func = (RtlGetVersionFunc)GetProcAddress(GetModuleHandleW(L"NTDLL"), "RtlGetVersion");
        RTL_OSVERSIONINFOW version = {};
        version.dwOSVersionInfoSize = sizeof(version);
        if (func(&version))
        {
            Common::ThrowException("RtlGetVersion() failed.");
        }
        if (version.dwMajorVersion >= 10)
        {
            winVer = 10;
            return;
        }
        if (version.dwMajorVersion == 6)
        {
            if (version.dwMinorVersion >= 2)
            {
                winVer = 8;
                return;
            }
            if (version.dwMinorVersion == 1)
            {
                winVer = 7;
                return;
            }
        }
    }

    inline bool SetPrivilege(
        LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
        BOOL bEnablePrivilege   // to enable or disable privilege
    )
    {
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid))        // receives LUID of privilege
        {
            return FALSE;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        if (bEnablePrivilege)
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        else
            tp.Privileges[0].Attributes = 0;

        // Enable the privilege or disable all privileges.
        HANDLE token = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
        {
            return false;
        }
        auto deleter = [](void* p) -> void { CloseHandle(p); };
        std::unique_ptr<void, decltype(deleter)> holder(token, deleter);

        if (!AdjustTokenPrivileges(
            token,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES)NULL,
            (PDWORD)NULL))
        {
            return FALSE;
        }

        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

        {
            return FALSE;
        }

        return TRUE;
    }

    inline std::filesystem::path GetMainModuleFolder()
    {
        std::unique_ptr<wchar_t[]> buffer = std::make_unique<wchar_t[]>(2048);
        if (!GetModuleFileNameW(0, buffer.get(), 2048))
        {
            ThrowException("GetModuleFileNameW() failed with last error %d.", GetLastError());
        }
        std::filesystem::path mainModule = buffer.get();
        return mainModule.parent_path();
    }

}