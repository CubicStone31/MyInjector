#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <windows.h>

namespace KernelCorridor
{
	bool CreateDriverServiceAndLoadDriver(const std::wstring& driver_file_path, const std::wstring& service_name, bool append_random_suffix, std::wstring& actual_service_name);

	bool StopDriverServiceAndDeleteIt(const std::wstring& kernel_service_name);

	bool Open();

	void Close();

	bool WriteProcessMemory(uint32_t pid, uint64_t address_to_write, const std::vector<uint8_t>& data, uint32_t& bytes_written, uint32_t method_id = 1);

	bool ReadProcessMemory(uint32_t pid, uint64_t address_to_read, uint32_t length_to_read, std::vector<uint8_t>& out, uint32_t method_id = 0);

	bool SetThreadContext(uint32_t tid, CONTEXT* ctx);

	bool GetThreadContext(uint32_t tid, CONTEXT* ctx);

	bool AllocProcessMemory(uint32_t pid, uint64_t* base, uint32_t* size, uint32_t protect);

	bool FreeAllocedProcessMemory(uint32_t pid, uint64_t base);

	HANDLE OpenProcess(uint32_t pid, uint32_t access, bool request_kernel_mode_handle);

	bool KCCloseHandle(HANDLE handle);

	bool SetInformationProcess(uint64_t handle, uint32_t process_info_class, const std::vector<uint8_t>& data);

	uint32_t CreateRemoteUserThread(uint32_t pid, uint64_t addr, uint64_t param, bool create_suspended);

	bool QueueUserAPC(uint32_t tid, uint64_t start_addr, uint64_t param, bool force_execute);
}




