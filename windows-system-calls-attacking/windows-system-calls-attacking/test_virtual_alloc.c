#include "utils.h"
#include "fptr.h"

int TestVirtualAlloc()
{
	wchar_t wsInput[80];
	fgetws(wsInput, 80, stdin);
	wsInput[wcslen(wsInput) - 1] = L'\0';
	int pid = GetPidFromName(wsInput);
	WriteOnAddress(pid);
	return 0;
}