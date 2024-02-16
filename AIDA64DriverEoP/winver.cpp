#include "winver.h"
#include <Windows.h>

#pragma comment(lib, "ntdll")

extern "C" NTSTATUS __stdcall RtlGetVersion(OSVERSIONINFOEXW * lpVersionInformation);

bool GetVersion(VersionInfo& info)
{
	OSVERSIONINFOEXW osv;
	osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	if (RtlGetVersion(&osv) == 0)
	{
		info.Major = osv.dwMajorVersion;
		info.Minor = osv.dwMinorVersion;
		info.BuildNum = osv.dwBuildNumber;

		return true;
	}
	return false;
}

bool IsBuildNumGreaterOrEqual(unsigned int buildNumber)
{
	VersionInfo info;
	if (GetVersion(info))
	{
		return (info.BuildNum >= buildNumber);
	}
	return false;
}
