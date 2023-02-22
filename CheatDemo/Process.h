#pragma once

#include <windows.h>
#include <tlhelp32.h>

class Process
{
private:
    Process(const Process&);
    Process& operator=(const Process&);

public:
    DWORD pid = 0;
    HANDLE handle = nullptr;
    MODULEENTRY32 mainModule;

    Process(const char* procName);
    ~Process();

    bool Open(DWORD access = PROCESS_ALL_ACCESS);
    void Close();

    BOOL ReadMemory(LPCVOID addr, BYTE* buffer, SIZE_T size, bool changeProtect = false);
    BOOL WriteMemory(LPVOID dest, BYTE* buffer, SIZE_T size, bool changeProtect = false);
    BOOL VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProtect, PDWORD pOldProtect = nullptr);
    MODULEENTRY32 GetModule(const char* modName);
};