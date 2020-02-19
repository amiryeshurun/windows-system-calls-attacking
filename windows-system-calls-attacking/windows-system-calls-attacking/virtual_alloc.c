#include "fptr.h"
#include <processthreadsapi.h>
#include <windows.h>
#include <MMSystem.h>


HANDLE NtOpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId)
{
	_NtOpenProcess NtOpenProcess1 = (_NtOpenProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtOpenProcess");
	CLIENT_ID cid = { (HANDLE)dwProcessId, NULL };

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);

	HANDLE hProcess = NULL;
	NTSTATUS ntStatus = NtOpenProcess1(&hProcess, dwDesiredAccess, &oa, &cid);

	SetLastError(ntStatus);
	return hProcess;
}

PVOID GetMemory(ULONG Size) 
{
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtAllocateVirtualMemory");
	PVOID Address = NULL;

	HANDLE p = NtOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ, (DWORD)((unsigned int)11328));
	NTSTATUS Status = NtAllocateVirtualMemory(p, &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) 
	{
		printf("Failed to allocate memory");
	}
	return Address;
}

PVOID GetMemory1(ULONG Size)
{
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtAllocateVirtualMemory");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtWriteVirtualMemory");
	PVOID Address = NULL;
	int* buff = (int*)malloc(100);
	for (int i = 0; i < 100/4; i++)
		buff[i] = 1;

	HANDLE p = NtOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ, (DWORD)((unsigned int)6636));
	NTSTATUS Status = NtAllocateVirtualMemory(p, &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(Status)) {
		NTSTATUS s = NtWriteVirtualMemory(p, Address, (PVOID)buff, (ULONG)100, NULL);
		printf("%d\n", GetLastError());
		if (NT_SUCCESS(s))
			puts("I wrote it");
	}

	
	printf("Failed to allocate memory");
	
}

int main() 
{
	GetMemory1(100*sizeof(int));
	Sleep(20000);
	return 0;
}