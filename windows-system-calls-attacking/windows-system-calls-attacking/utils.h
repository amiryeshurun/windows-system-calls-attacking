#ifndef __UTILS_GLOBAL_H
#define __UTILS_GLOBAL_H

#include "fptr.h"
#include <tlhelp32.h>

#define NT_SUCCESS(x) ((x)>=0)
#define FILE_CREATE 0x00000002
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define OBJ_CASE_INSENSITIVE 0x00000040L

int GetPidFromName(wchar_t str[]);
PVOID AllocateVirtualMemory(SIZE_T size, int pid);
HANDLE NtOpenProcess2(DWORD dwDesiredAccess, DWORD dwProcessId);


#endif