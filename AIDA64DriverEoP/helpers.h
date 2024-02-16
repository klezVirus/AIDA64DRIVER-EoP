#pragma once
#include <Windows.h>
#include <vector>
#include <string>

#ifndef HELPER_CLASS
#define HELPER_CLASS

// This struct will hold the address of a "Proc" tag and that Proc chunk's 
// header size
struct PROC_DATA {
    INT64 allocation_address; // The allocated memory kernel address
    INT64 proc_offset;        // The offset from the allocated memory address where the "Proc" chunk is located
};

struct VERSION_OFFSETS {
    DWORD UniqueProcessId;
    DWORD Token;
    DWORD ImageFileName; 
};

typedef ULONG64 (__stdcall* DriverMmMapper)(HANDLE, ULONG64, DWORD);

BOOL parse_proc(UINT64 allocation_address, DWORD proc_offset, PUINT64 pToken, PBOOL isSystem);
BOOL map_memory(HANDLE device_handle, DriverMmMapper driverMappingFunction);

#endif // !HELPER_CLASS
