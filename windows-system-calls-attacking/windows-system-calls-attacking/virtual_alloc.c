#include "fptr.h"
#include <processthreadsapi.h>
#include <windows.h>
#include <MMSystem.h>
#include <tlhelp32.h>


//HANDLE NtOpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId)
//{
//	_NtOpenProcess NtOpenProcess1 = (_NtOpenProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtOpenProcess");
//	CLIENT_ID cid = { (HANDLE)dwProcessId, NULL };
//
//	OBJECT_ATTRIBUTES oa;
//	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
//
//	HANDLE hProcess = NULL;
//	NTSTATUS ntStatus = NtOpenProcess1(&hProcess, dwDesiredAccess, &oa, &cid);
//
//	SetLastError(ntStatus);
//	return hProcess;
//}

//PVOID GetMemory(ULONG Size) 
//{
//	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtAllocateVirtualMemory");
//	PVOID Address = NULL;
//
//	HANDLE p = NtOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ, (DWORD)((unsigned int)11328));
//	NTSTATUS Status = NtAllocateVirtualMemory(p, &Address, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
//	if (!NT_SUCCESS(Status)) 
//	{
//		printf("Failed to allocate memory");
//	}
//	return Address;
//}

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef NTSTATUS(NTAPI* TNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);

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

	SetLastError(ntStatus);
	return hProcess;
}


PVOID GetMemory1(SIZE_T size)
{
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtAllocateVirtualMemory");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtWriteVirtualMemory");
	PVOID address = NULL;
	int* buff = (int*)malloc(100 * sizeof(int));
	for (int i = 0; i < 100; i++)
		buff[i] = 1;

	HANDLE p = NtOpenProcess2(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, (DWORD)8844);
	NTSTATUS status = NtAllocateVirtualMemory(p, &address, 0, (PSIZE_T)&size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%x\n", status);
 	printf("The memory has been allocated at: %p\n", address);
	if (NT_SUCCESS(status)) {
		ULONG len;
		NTSTATUS s = NtWriteVirtualMemory(p, address, (PVOID)buff, (ULONG)(100 *sizeof(int)), &len);
		printf("I allocated %d bytes\nat: %s\n", len, address);
		if (NT_SUCCESS(s))
			puts("I wrote it");
	}
}

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

	return -5;
}

VOID WriteOnAddress(int pid) {
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtWriteVirtualMemory");
	PVOID address = NULL;
	char* val = (char*)malloc(4*sizeof(char));
	strcpy_s(val, 4,"BIG");
	printf("Please enter the address of the variable: ");
	scanf_s("%x", &address);
	HANDLE p = NtOpenProcess2(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, (DWORD)pid);
	NTSTATUS s = NtWriteVirtualMemory(p, address, (PVOID)val, (ULONG)(4*sizeof(char)), NULL);
}

int main() 
{
	wchar_t wsInput[80];
	fgetws(wsInput, 80, stdin);
	wsInput[wcslen(wsInput) - 1] = L'\0';
	int pid = GetPidFromName(wsInput);
	WriteOnAddress(pid);
	return 0;
}