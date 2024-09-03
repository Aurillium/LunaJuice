#include "pch.h"
#include <Windows.h>
#include <errhandlingapi.h>
#include <iostream>
#include <tlhelp32.h>

#include "Loader.h"
#include "Config.h"
#include "output.h"

using namespace LunaAPI;

BOOL LUNA_API LunaAPI::InjectDLL(HANDLE IN hProcess, LPCSTR IN dllPath, LunaShared OUT *sharedMemory) {
    // Prepare shared object

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;

    // Define a security descriptor with access for all users
    PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (psd == NULL) {
        DISP_WINERROR("Could not allocate memory for security descriptor");
        return FALSE;
    }
    InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
    if (psd == NULL) {
        DISP_WINERROR("Could not initialise security descriptor for mapped file");
        return FALSE;
    }
    SetSecurityDescriptorDacl(psd, TRUE, (PACL)NULL, FALSE);

    sa.lpSecurityDescriptor = psd;

    HANDLE hFileMapping;
    hFileMapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE,       // Use paging file
        &sa,                        // Security attributes
        PAGE_READWRITE,             // Read/write access
        0,                          // Maximum object size (high-order DWORD)
        1024,                       // Maximum object size (low-order DWORD)
        SHARED_GLOBAL_NAME);        // Name of the file mapping object
    if (hFileMapping == NULL) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            // Try as a regular user
            UPDATE_WARN("Could not create file mapping as admin, can only operate on programs run by your user");
            hFileMapping = CreateFileMappingA(
                INVALID_HANDLE_VALUE,       // Use paging file
                NULL,                       // Security attributes (default)
                PAGE_READWRITE,             // Read/write access
                0,                          // Maximum object size (high-order DWORD)
                1024,                       // Maximum object size (low-order DWORD)
                SHARED_SESSION_NAME);       // This time use a local session object
            if (hFileMapping == NULL) {
                goto filemap_fail;
            }
        }
        else {
            // We end up here if the error was unrelated to permissions
        filemap_fail:
            DISP_WINERROR("Could not create file mapping");
            return FALSE;
        }
    }

    // Get our shared memory pointer
    LPVOID lpMemFile;
    lpMemFile = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == NULL) {
        DISP_WINERROR("Could not map shared memory");
        return FALSE;
    }

    // Inject saved DLL

    DWORD byteLength = (DWORD)((MAX_PATH) * sizeof(CHAR));
    HANDLE allocMemAddress = VirtualAllocEx(hProcess, NULL, byteLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocMemAddress == NULL)
    {
        DISP_WINERROR("Failed to allocate memory for injection in target");
        return FALSE;
    }
    SIZE_T written = 0;
    WriteProcessMemory(hProcess, allocMemAddress, dllPath, byteLength, &written);

    // This block creates a remote thread to load the DLL
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        DISP_WINERROR("Could not find kernel32 DLL");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    // Could improve this by using LoadLibraryEx and passing a handle? -- No, it's reserved for future use
    FARPROC hLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (hKernel32 == NULL) {
        DISP_WINERROR("Could not find LoadLibraryA function");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, allocMemAddress, 0, NULL);

    if (hThread == NULL) {
        DISP_WINERROR("Failed to create remote thread");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Wait for thread to exit
    WaitForSingleObject(hThread, INFINITE);
    // Clean up
    VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // Now save the data we receive so we can init

    memcpy(sharedMemory, lpMemFile, sizeof(LunaShared));

    LocalFree(psd);
    UnmapViewOfFile(lpMemFile);
    CloseHandle(hFileMapping);

    return TRUE;
}

BOOL LUNA_API LunaAPI::InitialiseLunaJuice(HANDLE IN hProcess, LPTHREAD_START_ROUTINE IN initLocation, LunaStart IN config) {

    // Allocate room for the config
    HANDLE allocMemAddress = VirtualAllocEx(hProcess, NULL, sizeof(LunaStart), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocMemAddress == NULL) {
        DISP_WINERROR("Failed to allocate memory for configuration in target");
        return FALSE;
    }

    // Copy configuration into target
    size_t written = 0;
    WriteProcessMemory(hProcess, allocMemAddress, &config, sizeof(LunaStart), &written);

    // Process configuration and load hooks
    HANDLE hConfigThread = CreateRemoteThread(hProcess, NULL, 0, initLocation, allocMemAddress, 0, NULL);
    if (hConfigThread == NULL) {
        DISP_WINERROR("Failed to create config thread");
        return FALSE;
    }
    // Wait for thread to exit
    WaitForSingleObject(hConfigThread, INFINITE);

    UPDATE_LOG("Hi, my name is '" << config.id << "'!");

    return TRUE;
}