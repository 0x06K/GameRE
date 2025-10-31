// find_module_gui.c
// Compile with: gcc cheat.c -o cheat.exe -luser32 -lgdi32 -mwindows
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// ============================================================================
// CONFIGURATION
// ============================================================================
#define TARGET_MODULE "crashhandler.dll"
#define BASE_OFFSET   0x0001B4C8
#define HEALTH_OFFSET 0x164

// ============================================================================
// GUI CONTROLS IDs
// ============================================================================
#define ID_PID_INPUT      101
#define ID_SCAN_BTN       102
#define ID_HEALTH_INPUT   103
#define ID_WRITE_BTN      104
#define ID_RESET_BTN      105
#define ID_LOG_OUTPUT     106

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================
HWND hPidInput, hScanBtn, hHealthInput, hWriteBtn, hResetBtn, hLogOutput;
HWND hProcessLabel, hModuleLabel, hAddressLabel, hCurrentHealthLabel;
HANDLE g_hProcess = NULL;
DWORD g_finalAddress = 0;
HANDLE g_hModSnap = NULL;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
void AppendLog(const char* message) {
    int len = GetWindowTextLength(hLogOutput);
    SendMessage(hLogOutput, EM_SETSEL, len, len);
    SendMessage(hLogOutput, EM_REPLACESEL, FALSE, (LPARAM)message);
    SendMessage(hLogOutput, EM_REPLACESEL, FALSE, (LPARAM)"\r\n");
}

int find_process(DWORD pid, char* processName) {
    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) {
        AppendLog("[-] CreateToolhelp32Snapshot failed");
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        AppendLog("[-] Process32First failed");
        return 0;
    }

    int found = 0;
    do {
        if (pe32.th32ProcessID == pid) {
            sprintf(processName, "%s (PID: %lu, Threads: %lu)", 
                    pe32.szExeFile, pe32.th32ProcessID, pe32.cntThreads);
            found = 1;
            break;
        }
    } while (Process32Next(hProcSnap, &pe32));

    CloseHandle(hProcSnap);
    return found;
}

BYTE* find_module_base(DWORD pid, const char* target, HANDLE* hModSnap_out, char* moduleInfo) {
    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hModSnap == INVALID_HANDLE_VALUE) {
        AppendLog("[-] CreateToolhelp32Snapshot (modules) failed");
        return NULL;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModSnap, &me)) {
        AppendLog("[-] Module32First failed");
        CloseHandle(hModSnap);
        return NULL;
    }

    BYTE* baseAddr = NULL;
    do {
        if (_stricmp(me.szModule, target) == 0) {
            sprintf(moduleInfo, "%s | Base: 0x%p | Size: %lu bytes", 
                    me.szModule, me.modBaseAddr, (unsigned long)me.modBaseSize);
            baseAddr = me.modBaseAddr;
            break;
        }
    } while (Module32Next(hModSnap, &me));

    if (!baseAddr) {
        CloseHandle(hModSnap);
        return NULL;
    }

    *hModSnap_out = hModSnap;
    return baseAddr;
}

DWORD resolve_pointer_chain(HANDLE hProcess, DWORD startAddress, DWORD* offsets, int numOffsets) {
    DWORD address = startAddress;
    SIZE_T bytesRead;
    DWORD pointerValue;
    char logBuffer[256];

    if (!ReadProcessMemory(hProcess, (LPCVOID)address, &pointerValue, sizeof(DWORD), &bytesRead)) {
        AppendLog("[-] Failed to read initial pointer");
        return 0;
    }
    
    sprintf(logBuffer, "[BASE] 0x%08X -> 0x%08X", address, pointerValue);
    AppendLog(logBuffer);
    address = pointerValue;

    for (int i = 0; i < numOffsets; i++) {
        address = pointerValue + offsets[i];
        
        if (!ReadProcessMemory(hProcess, (LPCVOID)address, &pointerValue, sizeof(DWORD), &bytesRead)) {
            sprintf(logBuffer, "[-] Failed at offset[%d]", i);
            AppendLog(logBuffer);
            return 0;
        }
        
        sprintf(logBuffer, "[%d] 0x%08X + 0x%03X -> 0x%08X", i, address - offsets[i], offsets[i], pointerValue);
        AppendLog(logBuffer);
        address = pointerValue;
    }
    
    return address;
}

float read_health(HANDLE hProcess, DWORD baseAddress) {
    DWORD healthAddress = baseAddress + HEALTH_OFFSET;
    float health = 0.0f;
    SIZE_T bytesRead;
    
    if (ReadProcessMemory(hProcess, (LPCVOID)healthAddress, &health, sizeof(float), &bytesRead)) {
        return health;
    }
    return -1.0f;
}

int write_health(HANDLE hProcess, DWORD baseAddress, float newHealth) {
    DWORD healthAddress = baseAddress + HEALTH_OFFSET;
    SIZE_T bytesWritten;
    
    if (WriteProcessMemory(hProcess, (LPVOID)healthAddress, &newHealth, sizeof(float), &bytesWritten)) {
        return 1;
    }
    return 0;
}

// ============================================================================
// GUI CALLBACKS
// ============================================================================
void OnScanProcess() {
    char pidText[32];
    GetWindowText(hPidInput, pidText, sizeof(pidText));
    DWORD pid = (DWORD)atoi(pidText);
    
    if (pid == 0) {
        AppendLog("[-] Invalid PID");
        MessageBox(NULL, "Please enter a valid PID", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    AppendLog("==============================");
    AppendLog("[*] Starting scan...");
    
    char processInfo[256];
    if (!find_process(pid, processInfo)) {
        AppendLog("[-] Process not found");
        MessageBox(NULL, "Process not found", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    AppendLog("[+] Process found!");
    SetWindowText(hProcessLabel, processInfo);
    
    char moduleInfo[512];
    BYTE* moduleBase = find_module_base(pid, TARGET_MODULE, &g_hModSnap, moduleInfo);
    if (!moduleBase) {
        AppendLog("[-] Module not found");
        MessageBox(NULL, "Module not found", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    AppendLog("[+] Module found!");
    SetWindowText(hModuleLabel, moduleInfo);
    
    g_hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!g_hProcess) {
        AppendLog("[-] Failed to open process. Run as Administrator!");
        MessageBox(NULL, "Failed to open process. Run as Administrator!", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    AppendLog("[+] Process handle acquired");
    AppendLog("[*] Resolving pointer chain...");
    
    DWORD offsets[] = {0x04, 0x58, 0x08, 0x04};
    int numOffsets = sizeof(offsets) / sizeof(offsets[0]);
    DWORD startAddress = (DWORD)moduleBase + BASE_OFFSET;
    
    DWORD finalAddress = resolve_pointer_chain(g_hProcess, startAddress, offsets, numOffsets);
    if (!finalAddress) {
        AppendLog("[-] Failed to resolve pointer chain");
        MessageBox(NULL, "Failed to resolve pointer chain. Either restart the game Or load another stage.", "Error", MB_OK | MB_ICONERROR);
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
        return;
    }
    
    finalAddress = finalAddress + 0x78;
    g_finalAddress = finalAddress;
    
    char addrBuffer[128];
    sprintf(addrBuffer, "Final: 0x%08X | Health: 0x%08X", finalAddress, finalAddress + HEALTH_OFFSET);
    SetWindowText(hAddressLabel, addrBuffer);
    
    AppendLog("[+] Chain resolved!");
    
    float currentHealth = read_health(g_hProcess, g_finalAddress);
    if (currentHealth >= 0) {
        char healthBuffer[64];
        sprintf(healthBuffer, "Current Health: %.2f", currentHealth);
        SetWindowText(hCurrentHealthLabel, healthBuffer);
        AppendLog("[+] Health read successfully");
    }
    
    AppendLog("==============================");
    AppendLog("[+] Ready for manipulation!");
    
    EnableWindow(hHealthInput, TRUE);
    EnableWindow(hWriteBtn, TRUE);
    EnableWindow(hResetBtn, TRUE);
    EnableWindow(hScanBtn, FALSE);
}

void OnWriteHealth() {
    char healthText[32];
    GetWindowText(hHealthInput, healthText, sizeof(healthText));
    float newHealth = (float)atof(healthText);
    
    if (newHealth <= 0 || newHealth > 29999998) {
        MessageBox(NULL, "Invalid health value (0 < health <= 29999998)", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    AppendLog("[*] Writing new health...");
    
    if (write_health(g_hProcess, g_finalAddress, newHealth)) {
        char logBuffer[128];
        sprintf(logBuffer, "[+] Successfully wrote %.2f", newHealth);
        AppendLog(logBuffer);
        
        float verifyHealth = read_health(g_hProcess, g_finalAddress);
        if (verifyHealth >= 0) {
            char healthBuffer[64];
            sprintf(healthBuffer, "Current Health: %.2f", verifyHealth);
            SetWindowText(hCurrentHealthLabel, healthBuffer);
            sprintf(logBuffer, "[+] Verified: %.2f", verifyHealth);
            AppendLog(logBuffer);
        }
        
        MessageBox(NULL, "Health updated successfully!", "Success", MB_OK | MB_ICONINFORMATION);
    } else {
        AppendLog("[-] WriteProcessMemory failed");
        MessageBox(NULL, "Failed to write health value", "Error", MB_OK | MB_ICONERROR);
    }
}

void OnReset() {
    if (g_hProcess) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
    }
    if (g_hModSnap) {
        CloseHandle(g_hModSnap);
        g_hModSnap = NULL;
    }
    g_finalAddress = 0;
    
    SetWindowText(hPidInput, "");
    SetWindowText(hHealthInput, "");
    SetWindowText(hLogOutput, "");
    SetWindowText(hProcessLabel, "No process selected");
    SetWindowText(hModuleLabel, "No module loaded");
    SetWindowText(hAddressLabel, "No address resolved");
    SetWindowText(hCurrentHealthLabel, "Health: N/A");
    
    EnableWindow(hHealthInput, FALSE);
    EnableWindow(hWriteBtn, FALSE);
    EnableWindow(hResetBtn, FALSE);
    EnableWindow(hScanBtn, TRUE);
    
    AppendLog("==============================");
    AppendLog("[*] Reset complete. Ready for new scan.");
    AppendLog("==============================");
}

// ============================================================================
// WINDOW PROCEDURE
// ============================================================================
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Title
            CreateWindow("STATIC", "CRY OF FEAR HEALTH MANIPULATION TOOL v1.0", 
                WS_VISIBLE | WS_CHILD | SS_CENTER,
                10, 10, 760, 30, hwnd, NULL, NULL, NULL);
            
            // Process Scanner Group
            CreateWindow("BUTTON", "Process Scanner", 
                WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
                10, 50, 370, 120, hwnd, NULL, NULL, NULL);
            
            CreateWindow("STATIC", "Process ID (PID):", 
                WS_VISIBLE | WS_CHILD,
                20, 75, 150, 20, hwnd, NULL, NULL, NULL);
            
            hPidInput = CreateWindow("EDIT", "", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                20, 95, 150, 25, hwnd, (HMENU)ID_PID_INPUT, NULL, NULL);
            
            hScanBtn = CreateWindow("BUTTON", "Scan Process", 
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                180, 95, 180, 25, hwnd, (HMENU)ID_SCAN_BTN, NULL, NULL);
            
            hResetBtn = CreateWindow("BUTTON", "Reset", 
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                20, 130, 150, 25, hwnd, (HMENU)ID_RESET_BTN, NULL, NULL);
            EnableWindow(hResetBtn, FALSE);
            
            // Health Manipulation Group
            CreateWindow("BUTTON", "Health Manipulation", 
                WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
                390, 50, 380, 120, hwnd, NULL, NULL, NULL);
            
            CreateWindow("STATIC", "New Health Value:", 
                WS_VISIBLE | WS_CHILD,
                400, 75, 150, 20, hwnd, NULL, NULL, NULL);
            
            hHealthInput = CreateWindow("EDIT", "", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                400, 95, 150, 25, hwnd, (HMENU)ID_HEALTH_INPUT, NULL, NULL);
            EnableWindow(hHealthInput, FALSE);
            
            hWriteBtn = CreateWindow("BUTTON", "Write Health", 
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                560, 95, 180, 25, hwnd, (HMENU)ID_WRITE_BTN, NULL, NULL);
            EnableWindow(hWriteBtn, FALSE);
            
            CreateWindow("STATIC", "Max: 29999998", 
                WS_VISIBLE | WS_CHILD,
                400, 125, 150, 20, hwnd, NULL, NULL, NULL);
            
            // Info Panel
            CreateWindow("BUTTON", "System Information", 
                WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
                10, 180, 760, 120, hwnd, NULL, NULL, NULL);
            
            CreateWindow("STATIC", "Process:", 
                WS_VISIBLE | WS_CHILD,
                20, 205, 70, 20, hwnd, NULL, NULL, NULL);
            hProcessLabel = CreateWindow("STATIC", "No process selected", 
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                100, 205, 650, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindow("STATIC", "Module:", 
                WS_VISIBLE | WS_CHILD,
                20, 230, 70, 20, hwnd, NULL, NULL, NULL);
            hModuleLabel = CreateWindow("STATIC", "No module loaded", 
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                100, 230, 650, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindow("STATIC", "Address:", 
                WS_VISIBLE | WS_CHILD,
                20, 255, 70, 20, hwnd, NULL, NULL, NULL);
            hAddressLabel = CreateWindow("STATIC", "No address resolved", 
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                100, 255, 650, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindow("STATIC", "Status:", 
                WS_VISIBLE | WS_CHILD,
                20, 280, 70, 20, hwnd, NULL, NULL, NULL);
            hCurrentHealthLabel = CreateWindow("STATIC", "Health: N/A", 
                WS_VISIBLE | WS_CHILD | SS_LEFT,
                100, 280, 650, 20, hwnd, NULL, NULL, NULL);
            
            // Log Output
            CreateWindow("STATIC", "Console Output:", 
                WS_VISIBLE | WS_CHILD,
                10, 310, 150, 20, hwnd, NULL, NULL, NULL);
            
            hLogOutput = CreateWindow("EDIT", "", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | 
                ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                10, 330, 760, 220, hwnd, (HMENU)ID_LOG_OUTPUT, NULL, NULL);
            
            // Set font
            HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Consolas");
            SendMessage(hLogOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            AppendLog("==============================");
            AppendLog("Memory Manipulation Tool v1.0");
            AppendLog("==============================");
            AppendLog("[*] Ready. Enter PID and click Scan Process.");
            AppendLog("[!] Run as Administrator for full access.");
            AppendLog("==============================");
            
            break;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_SCAN_BTN:
                    OnScanProcess();
                    break;
                case ID_WRITE_BTN:
                    OnWriteHealth();
                    break;
                case ID_RESET_BTN:
                    OnReset();
                    break;
            }
            break;
        }
        
        case WM_DESTROY:
            if (g_hProcess) CloseHandle(g_hProcess);
            if (g_hModSnap) CloseHandle(g_hModSnap);
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// MAIN
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "MemoryToolWindow";
    
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClass(&wc);
    
    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        "Memory Manipulation Tool v1.0",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 620,
        NULL, NULL, hInstance, NULL
    );
    
    if (hwnd == NULL) {
        return 0;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}