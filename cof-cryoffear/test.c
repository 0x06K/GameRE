// find_module.c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid> <module_name|all>\n", argv[0]);
        printf("Example: %s 1234 kernel32.dll\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    const char *target = "crashhandler.dll";

    // --- Find the process (your original snapshot) ---
    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot(process) failed. Error: %lu\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        fprintf(stderr, "Process32First failed. Error: %lu\n", GetLastError());
        return 1;
    }

    int found_proc = 0;
    do {
        if (pe32.th32ProcessID == pid) {
            printf("Snapshot of PID %lu:\n", pid);
            printf("--------------------------------------------------\n");
            printf("Process name : %s\n", pe32.szExeFile);
            printf("PID          : %lu\n", pe32.th32ProcessID);
            printf("Parent PID   : %lu\n", pe32.th32ParentProcessID);
            printf("Threads      : %lu\n", pe32.cntThreads);
            printf("--------------------------------------------------\n");
            found_proc = 1;
            break;
        }
    } while (Process32Next(hProcSnap, &pe32));

    CloseHandle(hProcSnap);

    if (!found_proc) {
        fprintf(stderr, "Process with PID %u not found.\n", pid);
        return 2;
    }

    // --- Module snapshot: include TH32CS_SNAPMODULE32 to see 32-bit modules from a 64-bit tool ---
    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hModSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot(modules) failed. Error: %lu\n", GetLastError());
        return 1;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    int found_module = 0;
    if (Module32First(hModSnap, &me)) {
        do {
            // me.szModule is filename (e.g., "kernel32.dll"), me.szExePath full path
            // Case-insensitive compare: use _stricmp on Windows
            if (_stricmp(me.szModule, target) == 0 || _stricmp(me.szExePath, target) == 0 || strcmp(target, "all") == 0) {
                printf("Module: %s\n", me.szModule);
                printf("  Path : %s\n", me.szExePath);
                printf("  Base : %p\n", me.modBaseAddr);
                printf("  Size : %lu bytes\n\n", (unsigned long)me.modBaseSize);
                found_module = 1;
                if (strcmp(target, "all") != 0) break; // if searching for a specific module, stop when found
            }
        } while (Module32Next(hModSnap, &me));
    } else {
        fprintf(stderr, "Module32First failed. Error: %lu\n", GetLastError());
    }
    if (!found_module) {
        printf("Module '%s' not found in PID %u.\n", target, pid);
        return 3;
    }
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        fprintf(stderr, "OpenProcess failed. Error: %lu\n", GetLastError());
        return 1;
    }
    uintptr_t base = me.modBaseAddr;
    uintptr_t offset = 0x0001B4C8;  // Fixed: offset is a number, not a pointer
    uintptr_t offsets[] ={0x04, 0x58, 0x20C, 0x7C, 0x04, 0x032C};  // Fixed: offset is a number, not a pointer
    printf("0x%p\n", (base = base + offset));
    uintptr_t  byteValue;
    SIZE_T bytesRead;
    for(int i = 0; i < 6;i++){
        if (ReadProcessMemory(hProcess, (BYTE)base, &byteValue, sizeof(uintptr_t ), &bytesRead)) {
            printf("BYTE value: 0x%02X\n", byteValue);
        } else {
            fprintf(stderr, "ReadProcessMemory failed. Error: %lu\n", GetLastError());
            return -1;
        }
        base = byteValue;
        base += offsets[i];
    }
    CloseHandle(hModSnap);
    return 0;
}
