#ifndef LIB_GAMEHACK_H
#define LIB_GAMEHACK_H

#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <string>
// Putting that incase DEFINE_ENUM_FLAG_OPERATORS is deprecated
#ifndef DEFINE_ENUM_FLAG_OPERATORS
#define DEFINE_ENUM_FLAG_OPERATORS(ENUMTYPE)                                                              \
  extern "C++"                                                                                            \
  {                                                                                                       \
    inline ENUMTYPE operator|(ENUMTYPE a, ENUMTYPE b) { return ENUMTYPE(((int)a) | ((int)b)); }           \
    inline ENUMTYPE &operator|=(ENUMTYPE &a, ENUMTYPE b) { return (ENUMTYPE &)(((int &)a) |= ((int)b)); } \
    inline ENUMTYPE operator&(ENUMTYPE a, ENUMTYPE b) { return ENUMTYPE(((int)a) & ((int)b)); }           \
    inline ENUMTYPE &operator&=(ENUMTYPE &a, ENUMTYPE b) { return (ENUMTYPE &)(((int &)a) &= ((int)b)); } \
    inline ENUMTYPE operator~(ENUMTYPE a) { return ENUMTYPE(~((int)a)); }                                 \
    inline ENUMTYPE operator^(ENUMTYPE a, ENUMTYPE b) { return ENUMTYPE(((int)a) ^ ((int)b)); }           \
    inline ENUMTYPE &operator^=(ENUMTYPE &a, ENUMTYPE b) { return (ENUMTYPE &)(((int &)a) ^= ((int)b)); } \
  }
#endif

namespace libGameHack
{

  /**
   * Search for the process id from a certain exe name. This function will return NULL if it can't find the pid
   * @example get_pid_from_bin_name(L"game.exe") 
   * @param exeName the name of the exe.
  */
  DWORD fetch_pid_from_bin_name(std::wstring exeName);

  /**
  * Fetch the pid of a process from it's window. The function will return NULL if it can't find the pid
  * @param window_name The name of the window. 
  * @example fetch_pid_from_window_name(L"METAL GEAR SOLID 5: THE PHANTOM PAIN")
  */
  DWORD fetch_pid_from_window_name(std::wstring window_name);

  enum class DesiredAcess : DWORD
  {
    /**
     * The returned handle can be used with 
     * VirtualAllocEx(), VirtualFreeEx(), and VirtualProtectEx() to allocate, 
     * free, and protect chunks of memory, respectively.
    */
    VmOperation = PROCESS_VM_OPERATION,
    /**
     * The returned handle can be used with 
     * ReadProcessMemory().
    */
    VmRead = PROCESS_VM_READ,
    /**
     * The returned handle can be used with 
     * WriteProcessMemory(), but it must also have PROCESS_VM_OPERATION rights. 
     * You can set both flags by passing PROCESS_VM_OPERATION | PROCESS_VM_WRITE 
     * as the DesiredAccess parameter.
    */
    VmWrite = PROCESS_VM_WRITE,
    /**
     * The returned handle can be used with 
     * CreateRemoteThread().
    */
    CreateThread = PROCESS_CREATE_THREAD,
    /**
     * The returned handle can be used to do anything. 
     * Avoid using this flag, as it can only be used by processes with debug 
     * privileges enabled and has compatibility issues with older versions of 
     * Windows.
    */
    AllAcess = PROCESS_ALL_ACCESS,
  };

  DEFINE_ENUM_FLAG_OPERATORS(DesiredAcess);

  /**
   * Fetch the handle of a proces. This function will return NULL if it fail to fetch the process memory
  */
  HANDLE fetch_proces_handle(DWORD pid, DesiredAcess desiredAcess = DesiredAcess::VmRead | DesiredAcess::VmWrite | DesiredAcess::VmOperation, BOOL inheritHandle = FALSE);

  template <typename T>
  T readMemory(HANDLE process, LPVOID address);

  template <typename T>
  void writeMemory(HANDLE proc, LPVOID adr, T val);

  enum class MemoryProtectionType : DWORD
  {
    NoAcess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    WriteCopy = 0x08,
    Execute = 0x10,
    ExecuteRead = 0x20,
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400
  };

  template <typename T>
  MemoryProtectionType protectMemory(HANDLE proc, LPVOID adr, MemoryProtectionType prot);

  /**
   * Dynamically rebase addresses at runtime -- Bypass aslr in production
   * @param process The handle of the process of the game
   * @param address Base address of the game 
  */
  DWORD rebase(HANDLE process, DWORD address);

  void showHowToDisableAslr();

  
  DWORD GetProcessThreadID(HANDLE Process);
} // namespace libGameHack

#endif LIB_GAMEHACK_H