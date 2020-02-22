#include "utils.h"

int GetPidFromName(wchar_t str[]) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp(entry.szExeFile, str) == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}

	return -1;
}


PVOID AllocateVirtualMemory(SIZE_T size, int pid)
{
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtAllocateVirtualMemory");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtWriteVirtualMemory");
	PVOID address = NULL;

	HANDLE p = NtOpenProcess2(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, (DWORD)pid);
	NTSTATUS status = NtAllocateVirtualMemory(p, &address, 0, (PSIZE_T)&size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NT_SUCCESS(status))
		return address;
	else
		return NULL;
}


HANDLE NtOpenProcess2(DWORD dwDesiredAccess, DWORD dwProcessId)
{
	HMODULE hNtdll = LoadLibraryW(L"ntdll");
	if (!hNtdll)
		return 1;

	TNtOpenProcess NtOpenProcess1 = (TNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
	if (!NtOpenProcess1)
		return 1;

	CLIENT_ID cid = { (HANDLE)dwProcessId, NULL };

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);

	HANDLE hProcess = NULL;
	NTSTATUS ntStatus = NtOpenProcess1(&hProcess, dwDesiredAccess, &oa, &cid);
	if (!NT_SUCCESS(ntStatus))
		printf("%x\n", ntStatus);
	SetLastError(ntStatus);
	return hProcess;
}

