#include "utils.h"

int main()
{
	int pid;
	printf("Enter a pid: ");
	scanf_s("%d", &pid);
	_putws(GetProcessNameByPid(pid));
	return 0;
}