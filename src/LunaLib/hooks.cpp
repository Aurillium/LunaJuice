#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <wincred.h>

#include "hooks.h"

#if _DEBUG
BOOL WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "Intercepted MessageBoxA called!" << std::endl;
    std::cout << "Text: " << lpText << std::endl;
    std::cout << "Caption: " << lpCaption << std::endl;
    BOOL result = Real_MessageBoxA(hWnd, "Hooked Function", lpCaption, uType);
    return result;
}
#endif

// I/O
BOOL WINAPI Hooked_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    // Redirect file writes or modify behavior here
    std::cout << "File Write Hooked!" << std::endl;
    return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
BOOL WINAPI Hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::cout << "Reading bytes: ";
    BOOL result = Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (/*hFile == GetStdHandle(STD_INPUT_HANDLE)*/true) {
#if _DEBUG
        std::cout << "Read " << lpNumberOfBytesRead << " from stdin" << std::endl;
#endif
    }
    return result;
}
char* Hooked_fgets(char* str, int numChars, FILE* stream) {
    std::cout << "Intercept fgets" << std::endl;
    return Real_fgets(str, numChars, stream);
}
wchar_t* __cdecl Hooked_fgetws(wchar_t* str, int numChars, FILE* stream) {
    std::cout << 1;
    wchar_t *buffer = (wchar_t*)calloc(numChars + 1, sizeof(wchar_t));
    std::cout << 2;
    int fd = _fileno(stream);
    std::cout << 3;
    size_t result = fread(buffer, sizeof(wchar_t), numChars, stream);
    std::cout << 4;

    memcpy_s(str, numChars, buffer, numChars);
    std::cout << 5;
    return str;

    /*std::cout << "Intercept fgetws" << std::endl;
    std::cout << str << std::endl;
    wprintf(L"%ls\n", str);
    std::cout << _msize(str) << std::endl;
    Real_fgetws(str, numChars, stream);
    wchar_t* string = (wchar_t*)malloc(8);
    string[0] = 's'; string[1] = 'u'; string[2] = 's';
    return string;*/
    //return Real_fgetws(str, numChars, stream);
}
/*int Hooked__read(
    int const fd,
    void* const buffer,
    unsigned const buffer_size
) {
    std::cout << "Hooked _read" << std::endl;
    return Real__read(fd, buffer, buffer_size);
}*/

// Privilege adjust
BOOL __stdcall Hooked_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    // Redirect file writes or modify behavior here
    std::cout << "Token adjust hooked!" << std::endl;
    return Real_AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}
NTSTATUS WINAPI Hooked_RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState) {
    std::cout << "Faked sucessful escalation!" << std::endl;
    return 0xC0000061; // Permission denied
    // Success
    return 0;
}
NTSTATUS NTAPI Hooked_ZwAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES TokenPrivileges, ULONG PreviousPrivilegesLength, PTOKEN_PRIVILEGES PreviousPrivileges, PULONG RequiredLength) {
    std::cout << "ZW adjust" << std::endl;
    return Real_ZwAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, TokenPrivileges, PreviousPrivilegesLength, PreviousPrivileges, RequiredLength);
}
NTSTATUS NTAPI Hooked_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES TokenPrivileges, ULONG PreviousPrivilegesLength, PTOKEN_PRIVILEGES PreviousPrivileges, PULONG RequiredLength) {
    std::cout << "NT adjust" << std::endl;
    return Real_NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, TokenPrivileges, PreviousPrivilegesLength, PreviousPrivileges, RequiredLength);
}
NTSTATUS NTAPI Hooked_NtReadFile(
    IN HANDLE               FileHandle,
    IN HANDLE               Event OPTIONAL,
    IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
    IN PVOID                ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    OUT PVOID               Buffer,
    IN ULONG                Length,
    IN PLARGE_INTEGER       ByteOffset OPTIONAL,
    IN PULONG               Key OPTIONAL) {
    std::cout << "Reading ntbytes: ";
    std::cout << "Real NtReadFile:      " << (void*)Real_NtReadFile << "   ";
    return Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

// Open process
HANDLE WINAPI Hooked_OpenProcess(IN DWORD dwDesiredAccess, IN BOOL bInheritHandle, IN DWORD dwProcessId) {
    // Return handle to own process
    std::cout << "Faked open process" << std::endl;
    return Real_OpenProcess(dwDesiredAccess, bInheritHandle, GetCurrentProcessId());
}

// Remote threads
HANDLE WINAPI Hooked_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    // Create thread in our process
    std::cout << "Faked remote thread" << std::endl;
    return Real_CreateRemoteThread(GetCurrentProcess(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}
HANDLE WINAPI Hooked_CreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {
    // Create thread in our process
    std::cout << "Faked remote thread" << std::endl;
    return Real_CreateRemoteThreadEx(GetCurrentProcess(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

// Remote writes
BOOL WINAPI Hooked_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberofBytesWritten) {
    // Write to our process
    std::cout << "Faked process write" << std::endl;
    return Real_WriteProcessMemory(GetCurrentProcess(), lpBaseAddress, lpBuffer, nSize, lpNumberofBytesWritten);
}
// Remote reads
BOOL WINAPI Hooked_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    // Read from our process
    std::cout << "Faked process read" << std::endl;
    return Real_ReadProcessMemory(GetCurrentProcess(), lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

// Process creation
BOOL WINAPI Hooked_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    // This is currently a way of escaping the poison
    std::cout << "New process started (wide strings)" << std::endl;
    return Real_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}
BOOL WINAPI Hooked_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    // This is currently a way of escaping the poison
    std::cout << "New process started (normal strings)" << std::endl;
    return Real_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}