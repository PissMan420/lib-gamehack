#include "lib-gamehack.h"
#include <tlhelp32.h>

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
}