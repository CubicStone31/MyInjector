#pragma once
#include <string>
#include <list>
#include <filesystem>

class RegularInjectionMgr
{
public:
    static void DoInjection(int pid, const std::filesystem::path& dllPath, const std::vector<std::string>& methods);

    static bool CheckParameters(const std::vector<std::string>& methods);
};