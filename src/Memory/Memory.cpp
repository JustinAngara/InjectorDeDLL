#include "Memory.h"
#include "../Global/Conditionals.h"
#include "../Life/InjectorContext.h"
#include "../Global/Globals.h"
#include <windows.h>
#include <sstream>
#include <vector>
#include <fstream>
#include <string>
#include <winnt.h>

#include <Richedit.h>

std::vector<BYTE> Memory::LoadDLL(InjectorContext& ctx, const std::wstring& dllPath)
{
	try
	{
		if (!ctx.ValidateDLLPath(dllPath))
		{
			throw std::runtime_error("Invalid DLL path");
		}
		std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
		if (!file.is_open())
		{
			Conditionals::LogErrorAndStatus(ctx, L"[-] Could not open DLL file", RGB(255, 0, 0), true);
			throw std::runtime_error("Could not open DLL file");
		}
		auto fileSize = file.tellg();
		if (fileSize < 0x1000)
		{
			file.close();
			Conditionals::LogErrorAndStatus(ctx, L"[-] Invalid DLL file size", RGB(255, 0, 0), true);
			throw std::runtime_error("Invalid DLL file size");
		}
		std::vector<BYTE> dllData(static_cast<size_t>(fileSize));
		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
		file.close();
		return dllData;
	}
	catch (const std::exception& e)
	{
		std::wstring error = L"[-] Exception in LoadDLL: " + std::wstring(e.what(), e.what() + strlen(e.what()));
		Conditionals::LogErrorAndStatus(ctx, error, RGB(255, 0, 0), true);
		throw;
	}
}

BYTE* Memory::AllocateProcessMemory(InjectorContext& ctx, HANDLE hProcess, SIZE_T size, DWORD& oldProtect, std::wstring& errorMsg)
{
	BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase)
	{
		errorMsg = L"[-] Error allocating process memory, code: 0x" + std::to_wstring(GetLastError());
		return nullptr;
	}
	if (!VirtualProtectEx(hProcess, pTargetBase, size, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		errorMsg = L"[-] Error setting memory protection, code: 0x" + std::to_wstring(GetLastError());
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		return nullptr;
	}
	errorMsg = L"[+] Memory allocated and protection set";
	return pTargetBase;
}

bool Memory::WritePEHeaders(InjectorContext& ctx, HANDLE hProcess, BYTE* pTargetBase, const BYTE* pSourceData, std::wstring& errorMsg)
{
	IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(pSourceData));
	IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(pSourceData + pDosHeader->e_lfanew));
	SIZE_T            bytesWritten = 0;

	// capture the NTSTATUS return code
	NTSTATUS status = NtWriteVirtualMemory_Syscall(
		hProcess, 
		pTargetBase, 
		(PVOID)pSourceData, 
		pNtHeaders->OptionalHeader.SizeOfHeaders, 
		&bytesWritten
	);

	if (status != 0) 
	{
		std::wstringstream ss;
		ss << std::hex << status;
		errorMsg = L"[-] Error writing PE headers, NTSTATUS: 0x" + ss.str();
		return false;
	}

	errorMsg = L"[+] PE headers written successfully";
	return true;
}


bool Memory::WriteSections(InjectorContext& ctx, HANDLE hProcess, BYTE* pTargetBase, const BYTE* pSourceData, IMAGE_NT_HEADERS* pNtHeaders, std::wstring& errorMsg)
{
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	SIZE_T bytesWritten = 0;

	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		// skip empty sections
		if (pSectionHeader[i].SizeOfRawData)
		{
			NTSTATUS status = NtWriteVirtualMemory_Syscall(
				hProcess, 
				pTargetBase + pSectionHeader[i].VirtualAddress,
				(PVOID)(pSourceData + pSectionHeader[i].PointerToRawData),
				pSectionHeader[i].SizeOfRawData, 
				&bytesWritten
			);

			if (status != 0)
			{
				std::wstringstream ss;
				ss << std::hex << status;
				errorMsg = L"[-] Error writing section " + std::to_wstring(i) + L", NTSTATUS: 0x" + ss.str();
				return false;
			}
		}
	}
	errorMsg = L"[+] All sections written successfully";
	return true;
}

BYTE* Memory::AllocateMappingData(InjectorContext& ctx, HANDLE hProcess, const MANUAL_MAPPING_DATA& mappingData, std::wstring& errorMsg)
{
	BYTE* pMappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!pMappingDataAlloc)
	{
		errorMsg = L"[-] Error allocating mapping data, code: 0x" + std::to_wstring(GetLastError());
		return nullptr;
	}

	SIZE_T bytesWritten = 0;

	NTSTATUS status = NtWriteVirtualMemory_Syscall(
		hProcess, 
		pMappingDataAlloc, 
		(PVOID)(&mappingData), 
		sizeof(MANUAL_MAPPING_DATA), 
		&bytesWritten
	);

	if (status != 0) 
	{
		std::wstringstream ss;
		ss << std::hex << status;
		errorMsg = L"[-] Error writing mapping data, NTSTATUS: 0x" + ss.str();

		VirtualFreeEx(hProcess, pMappingDataAlloc, 0, MEM_RELEASE);
		return nullptr;
	}

	errorMsg = L"[+] Mapping data allocated and written";
	return pMappingDataAlloc;
}



bool Memory::WriteSectionsToMemory(InjectorContext& ctx, HANDLE hProcess, BYTE* pTargetBase, const BYTE* pSourceData, IMAGE_NT_HEADERS* pNtHeaders)
{
	std::wstring errorMsg;
	if (!Memory::WriteSections(ctx, hProcess, pTargetBase, pSourceData, pNtHeaders, errorMsg))
	{
		Conditionals::LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
		return false;
	}
	return true;
}


bool Memory::AllocateAndWriteHeaders(InjectorContext& ctx, HANDLE hProcess, const BYTE* pSourceData, SIZE_T fileSize, BYTE*& pTargetBase, IMAGE_NT_HEADERS*& pNtHeaders, DWORD& oldProtect)
{
	std::wstring errorMsg;
	if (!Conditionals::ValidatePEHeaders(ctx, pSourceData, fileSize, errorMsg))
	{
		Conditionals::LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
		SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
		return false;
	}
	Conditionals::LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
	pNtHeaders	= reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<BYTE*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<BYTE*>(pSourceData))->e_lfanew));
	pTargetBase = Memory::AllocateProcessMemory(ctx, hProcess, pNtHeaders->OptionalHeader.SizeOfImage, oldProtect, errorMsg);
	if (!pTargetBase)
	{
		Conditionals::LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
		SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
		return false;
	}
	Conditionals::LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
	if (!Memory::WritePEHeaders(ctx, hProcess, pTargetBase, pSourceData, errorMsg))
	{
		Conditionals::LogErrorAndStatus(ctx, errorMsg, RGB(255, 0, 0), true);
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		SendMessage(ctx.hwndProgressBar, PBM_SETSTATE, PBST_ERROR, 0);
		return false;
	}
	Conditionals::LogErrorAndStatus(ctx, errorMsg, RGB(0, 255, 0), false);
	return true;
}
