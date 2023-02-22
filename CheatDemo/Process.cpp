#include "Process.h"
#include <iostream>

namespace 
{
    void ThrowException(std::string msg)
    {
        std::cerr << msg;
        throw std::runtime_error(msg);
    }

    void ThrowException(char* msg)
    {
        ThrowException(std::string(msg));
    }
}

Process::Process(const char* procName)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    // creates process snapshot
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        ThrowException("CreateToolhelp32Snapshot error");
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32))
    {
        ThrowException("Process32First error");
    }

    do // loops through processes
    {
        if (_strcmpi(procName, pe32.szExeFile) == 0)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    if (!pid)
    {
        ThrowException(std::string("Could not find process: ") + procName);
    }

    this->pid = pid;

    this->mainModule = this->GetModule(procName);
}

Process::~Process()
{

}

bool Process::Open(DWORD access)
{
    this->handle = OpenProcess(access, false, this->pid);
    if (this->handle)
    {
        return true;
    }
    return false;
}

void Process::Close()
{
    if (this->handle)
    {
        CloseHandle(handle);
        this->handle = nullptr;
    }
}

BOOL Process::ReadMemory(LPCVOID addr, BYTE* buffer, SIZE_T size, bool changeProtect)
{
    DWORD oldProtect = 0;
    if (changeProtect) // change protection to read
    {
        if (!this->VirtualProtect(const_cast<LPVOID>(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return FALSE;
    }

    BOOL success = ReadProcessMemory(this->handle, addr, buffer, size, nullptr);
    if (!success)
    {
        std::cerr << "ReadProcessMemory error " << GetLastError() << "\n";
    }

    if (changeProtect) // restore protection
    {
        if (!this->VirtualProtect(const_cast<LPVOID>(addr), size, oldProtect, &oldProtect))
            return FALSE;
    }
    return success;
}

BOOL Process::WriteMemory(LPVOID dest, BYTE* buffer, SIZE_T size, bool changeProtect)
{
    DWORD oldProtect = 0;
    if (changeProtect) // change protection to write
    {
        if (!this->VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return FALSE;
    }

    BOOL success = WriteProcessMemory(this->handle, dest, buffer, size, nullptr);
    if (!success)
    {
        std::cerr << "WriteProcessMemory error " << GetLastError() << "\n";
    }

    if (changeProtect) // restore protection
    {
        if (!this->VirtualProtect(dest, size, oldProtect, &oldProtect))
            return FALSE;
    }
    return success;
}


BOOL Process::VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProtect, PDWORD pOldProtect)
{
    DWORD oldProtect = 0;
    BOOL success = VirtualProtectEx(this->handle, addr, size, newProtect, &oldProtect);
    if (pOldProtect)
    {
        *pOldProtect = oldProtect;
    }
    if (!success)
    {
        std::cerr << "VirtualProtectEx error " << GetLastError() << "\n";
    }
    return success;
}

MODULEENTRY32 Process::GetModule(const char* modName)
{
    HANDLE hModuleSnap;
    MODULEENTRY32 mod32;
    bool found = false;

    // creates process snapshot
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, this->pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot error\n";
        return MODULEENTRY32{ 0 };
    }

    mod32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hModuleSnap, &mod32))
    {
        CloseHandle(hModuleSnap);
        std::cerr << "Module32First error " << GetLastError();
        return MODULEENTRY32{ 0 };
    }

    do // loops through modules
    {
        if (_strcmpi(modName, mod32.szModule) == 0)
        {
            found = true;
            break;
        }
    } while (Module32Next(hModuleSnap, &mod32));

    CloseHandle(hModuleSnap);
    if (!found)
    {
        std::cerr << "Could not find module " << modName << "\n";
        mod32 = MODULEENTRY32{ 0 };
    }
    return mod32;
}