#include "utils.h"
#include "fptr.h"

VOID WriteOnAddress(int pid) {
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtWriteVirtualMemory");
	PVOID address = NULL;
	char* val = (char*)malloc(4*sizeof(char));
	strcpy_s(val, 4,"BIG");
	printf("Please enter the address of the variable: ");
	scanf_s("%x", &address);
	HANDLE p = NtOpenProcess2(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, (DWORD)pid);
	for (unsigned long long i = 0; i < 0xFFFFFFFF; i++) {
		NTSTATUS val1 = NtWriteVirtualMemory(p, i, (PVOID)val, (ULONG)(4 * sizeof(char)), NULL);
		if (NT_SUCCESS(val1))
			puts("big");
		else
			printf("%x\n", val1);
	}
}

//int main() 
//{
//	wchar_t wsInput[80];
//	fgetws(wsInput, 80, stdin);
//	wsInput[wcslen(wsInput) - 1] = L'\0';
//	int pid = GetPidFromName(wsInput);
//	WriteOnAddress(pid);
//	return 0;
//}