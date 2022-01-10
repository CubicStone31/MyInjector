// NativeAgent.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "RegularInjection.h"
#include "SetWindowHookInjection.h"
#include <iostream>
#include "Common.h"

int main(int argc, char* argv[], char* envp[])
{
#ifdef _DEBUG
    std::cout << "[D] ";
    for (int i = 1; i < argc; i++)
    {
        std::cout << argv[i] << " ";
    }
    std::cout << std::endl;
#endif // DEBUG

    try
    {
        int pid = std::stoi(argv[1]);
        std::filesystem::path dllPath = argv[2];
        std::string major_method = argv[3];
        std::vector<std::string> methods;
        for (int i = 4; i < argc; i++)
        {
            methods.push_back(argv[i]);
        }

        if (major_method == "Regular")
        {
            RegularInjectionMgr::DoInjection(pid, dllPath, methods);
            return 0;
        }
        else if (major_method == "SetWindowsHook")
        {
            SetWindowsHookInjectionMgr::DoInjection(pid, dllPath, methods);
            return 0;
        }
        else if (major_method == "IME")
        {
            Common::Print("Not implemented.");
            return -1;
        }
    }
    catch (std::exception e)
    {
        Common::Print("[!] %s", e.what());
    }
    return -1;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
