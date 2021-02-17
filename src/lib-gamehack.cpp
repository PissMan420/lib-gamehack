#include "lib-gamehack.h"
#include <tlhelp32.h>
#include <iostream>

namespace libGameHack
{

  DWORD fetch_pid_from_bin_name(std::wstring exeName)
  {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry) == TRUE)
    {
      while (Process32Next(snapshot, &entry) == TRUE)
      {
        std::wstring binPath = entry.szExeFile;
        if (binPath.find(exeName) != std::wstring::npos)
        {
          CloseHandle(snapshot);
          return entry.th32ProcessID;
        }
      }
    }

    CloseHandle(snapshot);
    return NULL;
  }

  DWORD fetch_pid_from_window_name(std::wstring window_name)
  {
    HWND gameWindow = FindWindowW(NULL, window_name.c_str());
    DWORD pid;
    GetWindowThreadProcessId(gameWindow, &pid);
    return pid;
  }

  HANDLE fetch_proces_handle(DWORD pid, DesiredAcess desiredAcess, BOOL inheritHandle)
  {
    HANDLE procesHandle = OpenProcess(static_cast<DWORD>(desiredAcess), inheritHandle, pid);

    if (procesHandle == INVALID_HANDLE_VALUE)
      return NULL;
    else
      return procesHandle;
  }

  template <typename T>
  T readMemory(HANDLE process, LPVOID address)
  {
    T val;
    ReadProcessMemory(process, address, &val, sizeof(T), NULL);
    return val;
  }

  template <typename T>
  void writeMemory(HANDLE proc, LPVOID adr, T val)
  {
    WriteProcessMemory(proc, adr, &val, sizeof(T), NULL);
  }

  template <typename T>
  MemoryProtectionType protectMemory(HANDLE proc, LPVOID adr, MemoryProtectionType prot)
  {
    DWORD oldProt;
    VirtualProtectEx(proc, adr, sizeof(T), prot, &oldProt);
    return static_cast<MemoryProtectionType>(oldProt);
  }

  DWORD rebase(HANDLE process, DWORD address)
  {
    DWORD newBase;
    // get the address of kernel32.dll
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    // get the address of GetModuleHandle()
    LPVOID funcAdr = GetProcAddress(k32, "GetModuleHandleA");
    if (!funcAdr)
      funcAdr = GetProcAddress(k32, "GetModuleHandleW");
    // create the thread
    HANDLE thread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)funcAdr, NULL, NULL, NULL);

    // let the thread finish
    WaitForSingleObject(thread, INFINITE);
    // get the exit code
    GetExitCodeThread(thread, &newBase);
    // clean up the thread handle
    CloseHandle(thread);

    DWORD diff = address - 0x400'000;
    return diff + newBase;
  }

  void showHowToDisableAslr()
  {
    std::cout << "To keep development simple, you can disable ASLR and use addresses with "
              << "the transparent XP-base. To do so, enter a single command in the Visual "
              << "Studio Command Prompt:"
              << "\n"
              << "\t> editbin /DYNAMICBASE:NO \"C:\\path\\to\\game.exe\""
              << "\n"
              << "To renable it, enter:"
              << "\n"
              << "\teditbin /DYNAMICBASE \"C:\\path\\to\\game.exe\"";
  }

  DWORD GetProcessThreadID(HANDLE Process)
  {
    THREADENTRY32 entry;
    entry.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Thread32First(snapshot, &entry) == TRUE)
    {
      DWORD PID = GetProcessId(Process);
      while (Thread32Next(snapshot, &entry) == TRUE)
      {
        if (entry.th32OwnerProcessID == PID)
        {
          CloseHandle(snapshot);
          return entry.th32ThreadID;
        }
      }
    }
    CloseHandle(snapshot);
    return NULL;
  }
}