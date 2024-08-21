#include "pch.h"
#include <iostream>
#include <wincred.h>
#include <winternl.h>

#include "debug.h"
#include "events.h"
#include "functionlogs.h"
#include "hooks.h"
#include "util.h"

// Try to get the last input before the hooks were added
// (Many programs reuse the same buffer in their loop, which helps us)
BOOL firstNtRead = TRUE;
BOOL firstConsoleRead = TRUE;

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

// Privilege adjust
HOOKDEF(RtlAdjustPrivilege, WINAPI, NTSTATUS, (IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState)) {
    LOG_FUNCTION_CALL(RtlAdjustPrivilege, Privilege, Enable, CurrentThread, pPreviousState);

    LogPrivilegeAdjust(Enable, Privilege);
    WRITELINE_DEBUG("Detected priv adjust");
    NTSTATUS status = Real_RtlAdjustPrivilege(Privilege, Enable, CurrentThread, pPreviousState);
    return status; // Permission denied
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
    
    LOG_FUNCTION_CALL(NtReadFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

    if (FileHandle == GetStdHandle(STD_INPUT_HANDLE)) {
        // If it's our first time, try read the buffer before overwriting
        if (firstNtRead) {
            LogStdin((LPCSTR)Buffer);
            firstNtRead = FALSE;
        }
        WRITE_DEBUG("(hooked) ");
        NTSTATUS result = Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
        WRITELINE_DEBUG("DATA: " << (char*)Buffer);
        LogStdin((LPCSTR)Buffer);
        return result;
    } else {
        return Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }
}

HOOKDEF(ReadConsoleA, WINAPI, BOOL, (
    IN HANDLE hConsoleInput,
    OUT LPVOID lpBuffer,
    IN DWORD nNumberOfCharsToRead,
    OUT LPDWORD lpNumberOfCharsRead,
    IN OPTIONAL PCONSOLE_READCONSOLE_CONTROL pInputControl)) {


    if (hConsoleInput == GetStdHandle(STD_INPUT_HANDLE)) {
        // If it's our first time, try read the buffer before overwriting
        if (firstConsoleRead) {
            LogStdin((LPCSTR)lpBuffer);
            firstConsoleRead = FALSE;
        }
        WRITE_DEBUG("(hooked con) ");
        BOOL result = Real_ReadConsoleA(hConsoleInput, lpBuffer, nNumberOfCharsToRead, lpNumberOfCharsRead, pInputControl);
        WRITELINE_DEBUG("DATA: " << (char*)lpBuffer);
        LogStdin((LPCSTR)lpBuffer);
        return result;
    }
    else {
        return Real_ReadConsoleA(hConsoleInput, lpBuffer, nNumberOfCharsToRead, lpNumberOfCharsRead, pInputControl);
    }
}
HOOKDEF(ReadConsoleW, WINAPI, BOOL, (
    IN HANDLE hConsoleInput,
    OUT LPVOID lpBuffer,
    IN DWORD nNumberOfCharsToRead,
    OUT LPDWORD lpNumberOfCharsRead,
    IN OPTIONAL PCONSOLE_READCONSOLE_CONTROL pInputControl)) {

    if (hConsoleInput == GetStdHandle(STD_INPUT_HANDLE)) {
        // If it's our first time, try read the buffer before overwriting
        if (firstConsoleRead) {
            //LogStdin();
            // Convert to normal string
            firstConsoleRead = FALSE;
        }
        WRITE_DEBUG("(hooked con w) ");
        BOOL result = Real_ReadConsoleW(hConsoleInput, lpBuffer, nNumberOfCharsToRead, lpNumberOfCharsRead, pInputControl);
        WRITELINE_DEBUG("DATA: " << (wchar_t*)lpBuffer);
        LogStdin((LPCSTR)lpBuffer);
        return result;
    }
    else {
        return Real_ReadConsoleW(hConsoleInput, lpBuffer, nNumberOfCharsToRead, lpNumberOfCharsRead, pInputControl);
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
        WRITELINE_DEBUG("STDOUT DATA: " << (char*)Buffer);
        LogStdout((LPCSTR)Buffer);
        return result;
    } else if (FileHandle == GetStdHandle(STD_ERROR_HANDLE)) {
        NTSTATUS result = Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
        WRITELINE_DEBUG("STDERR DATA: " << (char*)Buffer);
        LogStderr((LPCSTR)Buffer);
        return result;
    } else {
        return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }
}

// Open process
HOOKDEF(OpenProcess, WINAPI, HANDLE, (IN DWORD dwDesiredAccess, IN BOOL bInheritHandle, IN DWORD dwProcessId)) {
    LOG_FUNCTION_CALL(OpenProcess, dwDesiredAccess, bInheritHandle, dwProcessId);

    // Too much output (~30386 lines)
    //WRITELINE_DEBUG("Detected open process");
    return Real_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

// Remote threads
HOOKDEF(CreateRemoteThread, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)) {
    LOG_FUNCTION_CALL(CreateRemoteThread, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    
    WRITELINE_DEBUG("Detected remote thread");
    return Real_CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}
HOOKDEF(CreateRemoteThreadEx, WINAPI, HANDLE, (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)) {
    LOG_FUNCTION_CALL(CreateRemoteThreadEx, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
    
    WRITELINE_DEBUG("Detected remote thread");
    return Real_CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

// Remote writes
HOOKDEF(WriteProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberofBytesWritten)) {
    LOG_FUNCTION_CALL(WriteProcessMemory, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberofBytesWritten);

    WRITELINE_DEBUG("Detected process write");
    return Real_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberofBytesWritten);
}
// Remote reads
HOOKDEF(ReadProcessMemory, WINAPI, BOOL, (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)) {
    LOG_FUNCTION_CALL(ReadProcessMemory, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    //WRITELINE_DEBUG("Detected process read");
    return Real_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

// High level process creation
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

// Low level process creation
// https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
// https://github.com/BlackOfWorld/NtCreateUserProcess/blob/main/main.cpp
// This function can spoof parent information, as well as what image was actually run (parameters and image are completely separate)
// https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing
// https://www.huntandhackett.com/blog/the-definitive-guide-to-process-cloning-on-windows
HOOKDEF(NtCreateUserProcess, NTAPI, NTSTATUS, (
    OUT PHANDLE ProcessHandle,
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK ProcessDesiredAccess,
    IN ACCESS_MASK ThreadDesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ProcessObjectAttributes,
    IN OPTIONAL POBJECT_ATTRIBUTES ThreadObjectAttributes,
    IN ULONG ProcessFlags,
    IN ULONG ThreadFlags,
    IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    IN OUT PPS_CREATE_INFO CreateInfo,
    IN PPS_ATTRIBUTE_LIST AttributeList
)) {
    // Fake parent process handle
    //HANDLE hParent = AttributeList->Attributes[5].ValuePtr;
    //DWORD spoofedParentID = GetProcessId(hParent);
    //if (hParent == NULL) {
    //    WRITELINE_DEBUG("Parent is NULL");
    //    spoofedParentID = GetCurrentProcessId();
    //}
    WRITELINE_DEBUG(AttributeList->TotalLength << ", " << sizeof(PS_ATTRIBUTE_LIST) << ", " << sizeof(PS_ATTRIBUTE));

    //WRITELINE_DEBUG("Parent PID: " << spoofedParentID);

    // Try get a normal string
    UNICODE_STRING imageUnicode = ProcessParameters->ImagePathName;
    UNICODE_STRING parametersUnicode = ProcessParameters->CommandLine;
    char* image = ConvertUnicodeStringToAnsi(imageUnicode);
    char* parameters = ConvertUnicodeStringToAnsi(parametersUnicode);

    WRITELINE_DEBUG("Parameters: " << parameters);
    WRITELINE_DEBUG("Image: " << image);

    NTSTATUS status = Real_NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    DWORD processID = GetProcessId(*ProcessHandle);

    WRITELINE_DEBUG("PID: " << processID);

    DWORD spoofedParentID = GetParentProcessId(processID);
    WRITELINE_DEBUG("Parent PID: " << spoofedParentID);
    WRITELINE_DEBUG("My PID: " << GetCurrentProcessId());
    if (spoofedParentID != GetCurrentProcessId()) {
        LogParentSpoof(spoofedParentID, image, parameters, processID);
    } else {
        LogProcessCreate(image, parameters, processID);
    }

    // WARNING! image and parameters are freed in the log functions
    // DO NOT free them here.

    return status;
}