#include "pch.h"
#include <iostream>
#include <wincred.h>

#include "debug.h"
#include "events.h"
#include "hooks.h"

#if _DEBUG
// No point using WRITELINE_DEBUG here, it's only compiled on debug mode
HOOKDEF(MessageBoxA, WINAPI, BOOL, (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType))
{
    std::cout << "Intercepted MessageBoxA called!" << std::endl;
    std::cout << "Text: " << lpText << std::endl;
    std::cout << "Caption: " << lpCaption << std::endl;
    BOOL result = Real_MessageBoxA(hWnd, "Hooked Function", lpCaption, uType);
    return result;
}
#endif

// I/O
HOOKDEF(WriteFile, WINAPI, BOOL, (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)) {
    // Redirect file writes or modify behavior here
    WRITELINE_DEBUG("File Write Hooked!");
    return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
HOOKDEF(ReadFile, WINAPI, BOOL, (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)) {
    WRITE_DEBUG("Reading bytes: ");
    BOOL result = Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (/*hFile == GetStdHandle(STD_INPUT_HANDLE)*/true) {
#if _DEBUG
        WRITELINE_DEBUG("Read " << lpNumberOfBytesRead << " from stdin");
#endif
    }
    return result;
}
/*char* Hooked_fgets(char* str, int numChars, FILE* stream) {
    WRITELINE_DEBUG("Intercept fgets");
    return Real_fgets(str, numChars, stream);
}
wchar_t* __cdecl Hooked_fgetws(wchar_t* str, int numChars, FILE* stream) {
    WRITELINE_DEBUG(1;
    wchar_t *buffer = (wchar_t*)calloc(numChars + 1, sizeof(wchar_t));
    WRITELINE_DEBUG(2;
    int fd = _fileno(stream);
    WRITELINE_DEBUG(3;
    size_t result = fread(buffer, sizeof(wchar_t), numChars, stream);
    WRITELINE_DEBUG(4;

    memcpy_s(str, numChars, buffer, numChars);
    WRITELINE_DEBUG(5;
    return str;

    /*WRITELINE_DEBUG("Intercept fgetws");
    WRITELINE_DEBUG(str);
    wprintf(L"%ls\n", str);
    WRITELINE_DEBUG(_msize(str));
    Real_fgetws(str, numChars, stream);
    wchar_t* string = (wchar_t*)malloc(8);
    string[0] = 's'; string[1] = 'u'; string[2] = 's';
    return string;* /
    //return Real_fgetws(str, numChars, stream);
}*/
/*int Hooked__read(
    int const fd,
    void* const buffer,
    unsigned const buffer_size
) {
    WRITELINE_DEBUG("Hooked _read");
    return Real__read(fd, buffer, buffer_size);
}*/

// Privilege adjust
HOOKDEF(AdjustTokenPrivileges, __stdcall, BOOL, (HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)) {
    // Redirect file writes or modify behavior here
    WRITELINE_DEBUG("Token adjust hooked!");
    return Real_AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}
HOOKDEF(RtlAdjustPrivilege, WINAPI, NTSTATUS, (IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState)) {
    WRITELINE_DEBUG("Faked sucessful escalation!");
    return 0xC0000061; // Permission denied
    // Success
    return 0;
}
HOOKDEF(ZwAdjustPrivilegesToken, NTAPI, NTSTATUS, (HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES TokenPrivileges, ULONG PreviousPrivilegesLength, PTOKEN_PRIVILEGES PreviousPrivileges, PULONG RequiredLength)) {
    WRITELINE_DEBUG("ZW adjust");
    return Real_ZwAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, TokenPrivileges, PreviousPrivilegesLength, PreviousPrivileges, RequiredLength);
}
HOOKDEF(NtAdjustPrivilegesToken, NTAPI, NTSTATUS, (HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES TokenPrivileges, ULONG PreviousPrivilegesLength, PTOKEN_PRIVILEGES PreviousPrivileges, PULONG RequiredLength)) {
    WRITELINE_DEBUG("NT adjust");
    return Real_NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, TokenPrivileges, PreviousPrivilegesLength, PreviousPrivileges, RequiredLength);
}
HOOKDEF(NtReadFile, NTAPI, NTSTATUS, (
    IN HANDLE               FileHandle,
    IN HANDLE               Event OPTIONAL,
    IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
    IN PVOID                ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    OUT PVOID               Buffer,
    IN ULONG                Length,
    IN PLARGE_INTEGER       ByteOffset OPTIONAL,
    IN PULONG               Key OPTIONAL)) {
    if (FileHandle == GetStdHandle(STD_INPUT_HANDLE)) {
        WRITE_DEBUG("(hooked) ");
        NTSTATUS result = Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
        printf("DATA: %s", (char*)Buffer);
        LogStdin((LPCSTR)Buffer);
        return result;
    }
    else {
        return Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }
}

HOOKDEF(NtWriteFile, NTAPI, NTSTATUS, (
    IN  HANDLE           FileHandle,
    IN  HANDLE           Event OPTIONAL,
    IN  PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
    IN  PVOID            ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  PVOID            Buffer,
    IN  ULONG            Length,
    IN  PLARGE_INTEGER   ByteOffset OPTIONAL,
    IN  PULONG           Key OPTIONAL)) {
    if (FileHandle == GetStdHandle(STD_OUTPUT_HANDLE)) {
        WRITE_DEBUG("(hooked) ");
        NTSTATUS result = Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
        printf("STDOUT DATA: %s", (char*)Buffer);
        LogStdout((LPCSTR)Buffer);
        return result;
    } else if (FileHandle == GetStdHandle(STD_ERROR_HANDLE)) {
        NTSTATUS result = Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
        printf("STDERR DATA: %s", (char*)Buffer);
        LogStderr((LPCSTR)Buffer);
        return result;
    } else {
        return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }
}

// Open process
HOOKDEF(OpenProcess, WINAPI, HANDLE, (IN DWORD dwDesiredAccess, IN BOOL bInheritHandle, IN DWORD dwProcessId)) {
    // Return handle to own process
    WRITELINE_DEBUG("Faked open process");
    return Real_OpenProcess(dwDesiredAccess, bInheritHandle, GetCurrentProcessId());
}

// Remote threads
HOOKDEF(CreateRemoteThread, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)) {
    // Create thread in our process
    WRITELINE_DEBUG("Faked remote thread");
    return Real_CreateRemoteThread(GetCurrentProcess(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}
HOOKDEF(CreateRemoteThreadEx, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)) {
    // Create thread in our process
    WRITELINE_DEBUG("Faked remote thread");
    return Real_CreateRemoteThreadEx(GetCurrentProcess(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

// Remote writes
HOOKDEF(WriteProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberofBytesWritten)) {
    // Write to our process
    WRITELINE_DEBUG("Faked process write");
    return Real_WriteProcessMemory(GetCurrentProcess(), lpBaseAddress, lpBuffer, nSize, lpNumberofBytesWritten);
}
// Remote reads
HOOKDEF(ReadProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)) {
    // Read from our process
    WRITELINE_DEBUG("Faked process read");
    return Real_ReadProcessMemory(GetCurrentProcess(), lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

// Process creation
HOOKDEF(CreateProcessW, WINAPI, BOOL, (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)) {
    // This is currently a way of escaping the poison
    WRITELINE_DEBUG("New process started (wide strings)");
    return Real_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}
HOOKDEF(CreateProcessA, WINAPI, BOOL, (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)) {
    // This is currently a way of escaping the poison
    WRITELINE_DEBUG("New process started (normal strings)");
    return Real_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}