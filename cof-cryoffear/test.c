// chain_resolver_edit_float.c
// Educational debug tool: tries two pointer-chain semantics, then reads/writes float (+0x164).
// Compile with the same bitness as your target process.
// MSVC x64: cl /EHsc chain_resolver_edit_float.c
// MinGW-w64 x64: x86_64-w64-mingw32-gcc chain_resolver_edit_float.c -o chain_resolver_edit_float.exe

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

uintptr_t find_module_base_by_pid(DWORD pid, const wchar_t *module_name) {
    MODULEENTRY32W me = {0};
    me.dwSize = sizeof(me);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            wprintf(L"Module: %s @ 0x%p\n", me.szModule, me.modBaseAddr);
            if (_wcsicmp(me.szModule, module_name) == 0) base = (uintptr_t)me.modBaseAddr;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

void print_region_info(HANDLE hProc, LPCVOID addr) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T r = VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi));
    if (r == 0) {
        printf("  VirtualQueryEx failed: %lu\n", GetLastError());
        return;
    }
    printf("  Region: Base=0x%p Size=0x%zx State=%s Protect=0x%X Type=%s\n",
           mbi.BaseAddress, mbi.RegionSize,
           (mbi.State == MEM_COMMIT) ? "COMMIT" : (mbi.State == MEM_RESERVE) ? "RESERVE" : (mbi.State == MEM_FREE) ? "FREE" : "UNKNOWN",
           (unsigned)mbi.Protect,
           (mbi.Type == MEM_PRIVATE) ? "PRIVATE" : (mbi.Type == MEM_MAPPED) ? "MAPPED" : (mbi.Type == MEM_IMAGE) ? "IMAGE" : "UNKNOWN");
}

bool read_ptr(HANDLE hProc, uintptr_t addr, uintptr_t *out, size_t ptr_size) {
    SIZE_T br = 0;
    if (ptr_size == 8) {
        uint64_t tmp = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)addr, &tmp, sizeof(tmp), &br) || br != sizeof(tmp)) return false;
        *out = (uintptr_t)tmp;
        return true;
    } else {
        uint32_t tmp = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)addr, &tmp, sizeof(tmp), &br) || br != sizeof(tmp)) return false;
        *out = (uintptr_t)tmp;
        return true;
    }
}

// Try resolving with method A:
//   addr = base + chain[0]
//   for i=1..n-1: read ptr at addr -> addr = ptr + chain[i]
// Try resolving with method B:
//   addr = base
//   for i=0..n-1: read ptr at (addr + chain[i]) -> addr = ptr
// These cover two common pointer-chain conventions.
bool try_resolve_methodA(HANDLE hProc, uintptr_t base, const uintptr_t chain[], size_t n, size_t ptr_size, uintptr_t *out_final) {
    printf("\n--- Trying Method A (start = base + chain[0]; for each step: read(addr) -> addr = ptr + chain[i]) ---\n");
    uintptr_t addr = base + chain[0];
    printf("Step 0: addr = base + 0x%" PRIxPTR " = 0x%p\n", chain[0], (void*)addr);
    print_region_info(hProc, (LPCVOID)addr);
    for (size_t i = 1; i < n; ++i) {
        uintptr_t ptrval = 0;
        printf("  Reading pointer at 0x%p ... ", (void*)addr);
        if (!read_ptr(hProc, addr, &ptrval, ptr_size)) {
            printf("FAILED (GetLastError=%lu)\n", GetLastError());
            print_region_info(hProc, (LPCVOID)addr);
            return false;
        }
        printf("OK -> ptr=0x%p\n", (void*)ptrval);
        addr = ptrval + chain[i];
        printf("  + 0x%" PRIxPTR " => next addr = 0x%p\n", chain[i], (void*)addr);
        print_region_info(hProc, (LPCVOID)addr);
    }
    *out_final = addr;
    return true;
}

bool try_resolve_methodB(HANDLE hProc, uintptr_t base, const uintptr_t chain[], size_t n, size_t ptr_size, uintptr_t *out_final) {
    printf("\n--- Trying Method B (start = base; for i: read(addr + chain[i]) -> addr = ptr) ---\n");
    uintptr_t addr = base;
    printf("Start base = 0x%p\n", (void*)addr);
    for (size_t i = 0; i < n; ++i) {
        uintptr_t read_addr = addr + chain[i];
        printf("  Reading pointer at (addr + 0x%" PRIxPTR ") = 0x%p ... ", chain[i], (void*)read_addr);
        print_region_info(hProc, (LPCVOID)read_addr);
        uintptr_t ptrval = 0;
        if (!read_ptr(hProc, read_addr, &ptrval, ptr_size)) {
            printf("FAILED (GetLastError=%lu)\n", GetLastError());
            print_region_info(hProc, (LPCVOID)read_addr);
            return false;
        }
        printf("OK -> ptr=0x%p\n", (void*)ptrval);
        addr = ptrval;
    }
    *out_final = addr;
    return true;
}

int main(void) {
    const wchar_t targetMod[] = L"crashhandler.dll";
    const uintptr_t chain[] = { 0x0001B4C8ULL, 0x4ULL, 0x58ULL, 0x20CULL, 0x7CULL, 0x4ULL, 0x32CULL };
    const size_t chain_len = sizeof(chain)/sizeof(chain[0]);
    const uintptr_t final_plus = 0x164; // +164

    DWORD pid = 0;
    wprintf(L"Enter target PID: ");
    if (wscanf(L"%u", &pid) != 1) { fprintf(stderr, "Invalid PID\n"); return 1; }
    int ch; while ((ch = getchar()) != '\n' && ch != EOF) {} // flush

    wprintf(L"Searching for module %s in PID %u...\n", targetMod, pid);
    uintptr_t base = find_module_base_by_pid(pid, targetMod);
    if (!base) { wprintf(L"Module %s not found in PID %u\n", targetMod, pid); return 1; }
    wprintf(L"Found base = 0x%p\n", (void*)base);

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { printf("OpenProcess failed: %lu. Try Admin & matching bitness.\n", GetLastError()); return 1; }

    // detect pointer size best-effort
    BOOL targetIs64 = TRUE;
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS2)(HANDLE, USHORT*, USHORT*);
    LPFN_ISWOW64PROCESS2 pIsWow64Ex = (LPFN_ISWOW64PROCESS2)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process2");
    if (pIsWow64Ex) {
        USHORT procMachine=0, nativeMachine=0;
        if (pIsWow64Ex(hProc, &procMachine, &nativeMachine)) targetIs64 = (procMachine == IMAGE_FILE_MACHINE_UNKNOWN);
    } else {
        BOOL wow = FALSE; IsWow64Process(hProc, &wow);
#if INTPTR_MAX == INT64_MAX
        targetIs64 = !wow;
#else
        targetIs64 = FALSE;
#endif
    }
    size_t ptr_size = targetIs64 ? 8 : 4;
    printf("Assuming pointer size = %zu (%s)\n", ptr_size, targetIs64 ? "64-bit" : "32-bit");

    // Try Method A first
    uintptr_t finalAddr = 0;
    if (try_resolve_methodA(hProc, base, chain, chain_len, ptr_size, &finalAddr)) {
        printf("\nMethod A resolved final address: 0x%p\n", (void*)finalAddr);
    } else {
        printf("\nMethod A failed. Trying Method B...\n");
        if (try_resolve_methodB(hProc, base, chain, chain_len, ptr_size, &finalAddr)) {
            printf("\nMethod B resolved final address: 0x%p\n", (void*)finalAddr);
        } else {
            printf("\nBoth methods failed to fully resolve the chain. See above logs.\n");
            CloseHandle(hProc);
            return 1;
        }
    }

    // Add +0x164 and operate on float
    finalAddr += final_plus;
    printf("\nFinal target for float operation: 0x%p (after +0x%zx)\n", (void*)finalAddr, final_plus);
    print_region_info(hProc, (LPCVOID)finalAddr);

    float cur = 0.0f;
    SIZE_T br = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)finalAddr, &cur, sizeof(cur), &br) || br != sizeof(cur)) {
        printf("ReadProcessMemory(float) failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("Current float at 0x%p = %f\n", (void*)finalAddr, cur);

    float newv = 0.0f;
    printf("Enter health: ");
    scanf("%f", &newv);
    SIZE_T bw = 0;
    if (!WriteProcessMemory(hProc, (LPVOID)finalAddr, &newv, sizeof(newv), &bw) || bw != sizeof(newv)) {
        printf("WriteProcessMemory(float) failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("Wrote %f to 0x%p\n", newv, (void*)finalAddr);

    // verify
    float verify = 0.0f;
    if (!ReadProcessMemory(hProc, (LPCVOID)finalAddr, &verify, sizeof(verify), &br) || br != sizeof(verify)) {
        printf("Verification read failed: %lu\n", GetLastError());
    } else {
        printf("Verified float now = %f\n", verify);
    }

    CloseHandle(hProc);
    return 0;
}
