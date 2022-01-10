#include "framework.h"

// __stdcall is forced to be mangled, no matter if the extern "C" statement is used
// https://stackoverflow.com/questions/4550294/stdcall-name-mangling-using-extern-c-and-dllexport-vs-module-definitions-msvc
// so we have to use a .def file
// https://stackoverflow.com/questions/366228/def-files-c-c-dlls
LRESULT CALLBACK WindowHookProc(int Code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, Code, wParam, lParam);
}
