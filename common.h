#pragma once
#include <Windows.h>
#include "structs.h"

#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
       STANDARD_RIGHTS_REQUIRED | \
       WORKER_FACTORY_RELEASE_WORKER | \
       WORKER_FACTORY_WAIT | \
       WORKER_FACTORY_SET_INFORMATION | \
       WORKER_FACTORY_QUERY_INFORMATION | \
       WORKER_FACTORY_READY_WORKER | \
       WORKER_FACTORY_SHUTDOWN \
)

// norka.c
BOOL Norka(HANDLE hProcess, SIZE_T shellcodeSize, PVOID shellcode, PVOID * shellcodeAdress);

// thread.c
HANDLE HijackProcessHandle(LPCWSTR wsObjectType, HANDLE hProcess, DWORD dwDesiredAccess);
BOOL InjectStartRoutine(HANDLE hProcess, HANDLE hDuplicatedHandle, PVOID shellcodeAddress);

typedef struct _NT_API {
    _NtQueryInformationProcess	        pNtQueryInformationProcess;
    _NtWriteVirtualMemory		        pNtWriteVirtualMemory;
    _NtReadVirtualMemory		        pNtReadVirtualMemory;
    _NtQueryObject                      pNtQueryObject;
    _NtQueryInformationWorkerFactory    pNtQueryInformationWorkerFactory;
    _NtSetInformationWorkerFactory      pNtSetInformationWorkerFactory;
    _NtProtectVirtualMemory             pNtProtectVirtualMemory;
}NT_API, * PNT_API;
