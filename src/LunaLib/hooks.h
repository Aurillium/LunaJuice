#pragma once
#include <Windows.h>
#include <stdio.h>

#include "forbidden_headers.h"


// Macro to make hooking easier
// Make sure you follow the naming format though!
// Hooked_{name}, Real_{name}
#define QUICK_HOOK(dll, name) (InstallHookV2(dll, #name, (void*)Hooked_##name, (void*)Real_##name))

// Quickly define hooks
// Example:
// typedef BOOL(WINAPI* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
// static MessageBoxA_t Real_MessageBoxA = MessageBoxA;
// static BOOL WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
//
// Becomes:
// HOOKDEF(MessageBoxA, BOOL, WINAPI, (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType));
#define HOOKDEF(name, calltype, ret, sig) \
typedef ret(calltype* name##_t)sig; \
static name##_t Real_##name = name; \
ret calltype Hooked_##name##sig;

// For testing purposes only
HOOKDEF(MessageBoxA, WINAPI, BOOL, (HWND, LPCSTR, LPCSTR, UINT));

// I/O
HOOKDEF(WriteFile, WINAPI, BOOL, (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))
HOOKDEF(ReadFile, WINAPI, BOOL, (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))
HOOKDEF(NtReadFile, NTAPI, NTSTATUS, (HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key))
HOOKDEF(fgets, __cdecl, char*, (char* str, int numChars, FILE* stream))
HOOKDEF(fgetws, __cdecl, wchar_t*, (wchar_t* str, int numChars, FILE* stream))
HOOKDEF(_read, __cdecl, int, (int const fd, void* const buffer, unsigned const buffer_size))

// Privilege adjust
HOOKDEF(AdjustTokenPrivileges, NTAPI, BOOL, (HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD))
HOOKDEF(RtlAdjustPrivilege, NTAPI, NTSTATUS, (IN ULONG, IN BOOL, IN BOOL, OUT PULONG))
HOOKDEF(NtAdjustPrivilegesToken, NTAPI, NTSTATUS, (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG))
HOOKDEF(ZwAdjustPrivilegesToken, NTAPI, NTSTATUS, (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG)) // Unsure of params

// Open process
HOOKDEF(OpenProcess, WINAPI, HANDLE, (IN DWORD, IN BOOL, IN DWORD))


// Remote threads
HOOKDEF(CreateRemoteThread, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId))
HOOKDEF(CreateRemoteThreadEx, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId))
HOOKDEF(WriteProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberofBytesWritten))
HOOKDEF(ReadProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead))


// Process creation neutralisation
HOOKDEF(CreateProcessW, WINAPI, BOOL, (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation))
HOOKDEF(CreateProcessA, WINAPI, BOOL, (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation))