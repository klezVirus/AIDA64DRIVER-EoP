#pragma once
#include <Windows.h>
#include <stdio.h>

#define IOCTL_MAP_MEMORY 0x80112104

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

#pragma pack(push,1)
typedef struct INPUT_BUFFER {
	ULONG64 PhyAddress;
	DWORD Size;
	DWORD Unused;
    ULONG64 Reserved1;
    ULONG64 Reserved2;
} INPUT_BUFFER, * PINPUT_BUFFER;

typedef struct OUTPUT_BUFFER {
	UINT64 PhyAddress;
	DWORD Size;
	DWORD Information;
    DWORD Status;
	UINT64 MappedAddress;
	DWORD Control;
} OUTPUT_BUFFER, * POUTPUT_BUFFER;
#pragma pack(pop)

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQueryIntervalProfile)(
    DWORD ProfileSource,
    PULONG Interval
    );

ULONG64 findSystemEPROCESS();
ULONG64 driverMmMap(HANDLE, ULONG64, DWORD);