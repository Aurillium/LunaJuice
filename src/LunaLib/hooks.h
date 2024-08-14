#pragma once
#include <Windows.h>
#include <stdio.h>

#include "forbidden_headers.h"


// Macro to make hooking easier
// Make sure you follow the naming format though!
// Hooked_{name}, Real_{name}
#define QUICK_HOOK_V3(dll, name) (InstallHookV3(dll, #name, (void*)Hooked_##name, (void**)&Real_##name))
#define QUICK_HOOK_V2(dll, name) (InstallHookV2(dll, #name, (void*)Hooked_##name, (void**)&Real_##name))
// This is more stable than V3, so keep it the default
#define QUICK_HOOK(dll, name) (InstallHookV2(dll, #name, (void*)Hooked_##name, (void**)&Real_##name))
#define EXTERN_HOOK(name) extern name##_t Real_##name;

// Quickly define hooks
// Example:
// typedef BOOL(WINAPI* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
// BOOL WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
//
// Becomes:
// HOOKDEF(MessageBoxA, BOOL, WINAPI, (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType));
#define HOOKHEAD(name, calltype, ret, sig) \
typedef ret(calltype* name##_t)sig; \
ret calltype Hooked_##name##sig;

#define HOOKDEF(name, calltype, ret, sig) \
name##_t Real_##name; \
ret calltype Hooked_##name##sig

// These variables cannot be static, no matter what Visual Studio says:
// https://stackoverflow.com/questions/1358400/what-is-external-linkage-and-internal-linkage
// https://stackoverflow.com/questions/6469849/one-or-more-multiply-defined-symbols-found

// For testing purposes only
HOOKHEAD(MessageBoxA, WINAPI, BOOL, (HWND, LPCSTR, LPCSTR, UINT));

// I/O
HOOKHEAD(WriteFile, WINAPI, BOOL, (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))
HOOKHEAD(ReadFile, WINAPI, BOOL, (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))
HOOKHEAD(NtReadFile, NTAPI, NTSTATUS, (HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key))
HOOKHEAD(NtWriteFile, NTAPI, NTSTATUS, (IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL, IN PULONG Key OPTIONAL))
//HOOKHEAD(fgets, __cdecl, char*, (char* str, int numChars, FILE* stream))
//HOOKHEAD(fgetws, __cdecl, wchar_t*, (wchar_t* str, int numChars, FILE* stream))
//HOOKHEAD(_read, __cdecl, int, (int const fd, void* const buffer, unsigned const buffer_size))

// Privilege adjust
HOOKHEAD(AdjustTokenPrivileges, NTAPI, BOOL, (HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD))
HOOKHEAD(RtlAdjustPrivilege, NTAPI, NTSTATUS, (IN ULONG, IN BOOL, IN BOOL, OUT PULONG))
HOOKHEAD(NtAdjustPrivilegesToken, NTAPI, NTSTATUS, (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG))
HOOKHEAD(ZwAdjustPrivilegesToken, NTAPI, NTSTATUS, (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG)) // Unsure of params

// Open process
HOOKHEAD(OpenProcess, WINAPI, HANDLE, (IN DWORD, IN BOOL, IN DWORD))


// Remote threads
HOOKHEAD(CreateRemoteThread, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId))
HOOKHEAD(CreateRemoteThreadEx, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId))
HOOKHEAD(WriteProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberofBytesWritten))
HOOKHEAD(ReadProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead))


// Process creation neutralisation
HOOKHEAD(CreateProcessW, WINAPI, BOOL, (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation))
HOOKHEAD(CreateProcessA, WINAPI, BOOL, (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation))
