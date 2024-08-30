#pragma once
#include <Windows.h>
#include <stdio.h>

#include "forbidden_headers.h"
#include "hooking.h"
#include <Unknwnbase.h>

// For testing purposes only
HOOKHEAD(MessageBoxA, WINAPI, BOOL, (HWND, LPCSTR, LPCSTR, UINT));

// I/O
HOOKHEAD(NtReadFile, NTAPI, NTSTATUS, (HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key))
HOOKHEAD(NtWriteFile, NTAPI, NTSTATUS, (IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL, IN PULONG Key OPTIONAL))
//HOOKHEAD(fgets, __cdecl, char*, (char* str, int numChars, FILE* stream))
//HOOKHEAD(fgetws, __cdecl, wchar_t*, (wchar_t* str, int numChars, FILE* stream))
//HOOKHEAD(_read, __cdecl, int, (int const fd, void* const buffer, unsigned const buffer_size))
HOOKHEAD(ReadConsoleA, WINAPI, BOOL, (IN HANDLE hConsoleInput, OUT LPVOID lpBuffer, IN DWORD nNumberOfCharsToRead, OUT LPDWORD lpNumberOfCharsRead, IN OPTIONAL PCONSOLE_READCONSOLE_CONTROL pInputControl))
HOOKHEAD(ReadConsoleW, WINAPI, BOOL, (IN HANDLE hConsoleInput, OUT LPVOID lpBuffer, IN DWORD nNumberOfCharsToRead, OUT LPDWORD lpNumberOfCharsRead, IN OPTIONAL PCONSOLE_READCONSOLE_CONTROL pInputControl))

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

HOOKHEAD(NtCreateUserProcess, NTAPI, NTSTATUS, (OUT PHANDLE ProcessHandle, OUT PHANDLE ThreadHandle, IN ACCESS_MASK ProcessDesiredAccess,IN ACCESS_MASK ThreadDesiredAccess, IN OPTIONAL POBJECT_ATTRIBUTES ProcessObjectAttributes, IN OPTIONAL POBJECT_ATTRIBUTES ThreadObjectAttributes, IN ULONG ProcessFlags, IN ULONG ThreadFlags, IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters, IN OUT PPS_CREATE_INFO CreateInfo, IN PPS_ATTRIBUTE_LIST AttributeList))

HOOKHEAD(CoCreateInstance, WINAPI, HRESULT, (IN REFCLSID rclsid, IN LPUNKNOWN pUnkOuter, IN DWORD dwClsContext, IN REFIID riid, OUT LPVOID* ppv))