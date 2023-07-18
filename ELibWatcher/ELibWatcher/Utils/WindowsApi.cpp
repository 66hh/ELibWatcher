#include "WindowsApi.h"
#include <windows.h>
#include <Psapi.h>

unsigned int GetModuleSize(unsigned int hModule)
{
	MODULEINFO moduleInfo;
	if (GetModuleInformation(GetCurrentProcess(), (HMODULE)hModule, &moduleInfo, sizeof(MODULEINFO)))
	{
		return moduleInfo.SizeOfImage;
	}
	return 0x0;
}