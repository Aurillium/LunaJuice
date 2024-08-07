using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.IO;
using System.Reflection;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Reflection.Metadata;

// In retrospect, this is really just a C++ program written in C#
// It should probably be written again in C++ at some point

class Program
{
    static readonly string[] privilegesToRemove = {
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeDelegateSessionUserImpersonatePrivilege",
        "SeCreateTokenPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeChangeNotifyPrivilege",
        "SeCreateGlobalPrivilege",
        "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege",
        "SeEnableDelegationPrivilege",
        "SeLoadDriverPrivilege",
        "SeLockMemoryPrivilege",
        "SeMachineAccountPrivilege",
        "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeRelabelPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeShutdownPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege",
        "SeTrustedCredManAccessPrivilege"
        // Unsolicited input?
    };

    const int PROCESS_ALL_ACCESS = 0x1F0FFF;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_DISABLED = 0x00000000;
    //const int DUPLICATE_SAME_ACCESS = 0x00000002;
    //const string SE_DEBUG_NAME = "SeDebugPrivilege";
    const uint MEM_COMMIT = 0x00001000;
    const uint PAGE_EXECUTE_READWRITE = 0x40; // https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    const uint PAGE_READWRITE = 0x04;
    const uint MEM_RELEASE = 0x00008000;
    // Infinity is a lie anyway
    // (No I could not find the real constant)
    const uint INFINITE = 0xffffffff;

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        MaxTokenInfoClass
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
    // The W versions take wide strings rather than normal ones, that seems to be the only difference
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr GetModuleHandleA(string lpModuleName);


    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);


    static void ImpersonateLowPrivilegeUser(IntPtr hToken)
    {
        // Open the guest account token
        WindowsIdentity guestIdentity = new WindowsIdentity("Guest");

        // Impersonate the guest user
        //WindowsImpersonationContext impersonationContext = guestIdentity.Impersonate();

        // Optional: Apply the guest token to the target process
        if (!SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, guestIdentity.Token))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        // End impersonation
        //impersonationContext.Undo();
    }

    static void DropAllPrivileges(int targetProcessId)
    {
        for (short i = 0; i < privilegesToRemove.Length; i++)
        {
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
            if (hProcess == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;

            // Add privileges to be removed (example: SE_DEBUG_NAME)
            LUID luid;
            if (!LookupPrivilegeValue(null, privilegesToRemove[i], out luid))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            tp.Privileges.Luid = luid;
            tp.Privileges.Attributes = SE_PRIVILEGE_DISABLED;

            // Adjust token privileges
            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            Console.WriteLine("Dropped " + privilegesToRemove[i] + ".");

            CloseHandle(hToken);
            CloseHandle(hProcess);
        }
    }

    static void EnableDebugPrivilege()
    {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        LUID luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Privileges.Luid = luid;
        tp.Privileges.Attributes = 0x00000002;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        CloseHandle(hToken);
    }

    static void InjectDLL(int targetProcessId)
    {
        // Prepare to take the DLL out
        string dllPath = Path.GetTempFileName() + ".dll";
        var assembly = Assembly.GetExecutingAssembly();
        // Slow but more futureproof
        string resourceName = assembly.GetManifestResourceNames()
            .Single(str => str.EndsWith("LunaLib.dll"));

        // Retrieve the DLL from memory and copy it to a file
        using (Stream? resource = assembly.GetManifestResourceStream(resourceName))
        {
            if (resource == null)
            {
                Console.WriteLine("Could not find DLL.");
                return;
            }
            using (FileStream file = new FileStream(dllPath, FileMode.Create, FileAccess.Write))
            {
                resource.CopyTo(file);
            }
        }

        // Open the remote process to write
        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process.");
            return;
        }

        // This block writes the DLL path into the remote process
        // We're not going to use unicode paths internally
        byte[] dllPathBytes = System.Text.Encoding.ASCII.GetBytes(dllPath);
        // ChatGPT said to use the length of the string...
        // While also telling me to use unicode...
        IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPathBytes.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (allocMemAddress == IntPtr.Zero)
        {
            Console.WriteLine("Failed to allocate memory in target process.");
            CloseHandle(hProcess);
            return;
        }
        WriteProcessMemory(hProcess, allocMemAddress, dllPathBytes, (uint)dllPathBytes.Length, out _);

        // This block creates a remote thread to load the DLL
        IntPtr hKernel32 = GetModuleHandleA("kernel32.dll");
        // Could improve this bt using LoadLibraryEx and passing a handle?
        IntPtr hLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, hLoadLibrary, allocMemAddress, 0, IntPtr.Zero);

        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create remote thread.");
            CloseHandle(hProcess);
            return;
        }

        WaitForSingleObject(hThread, INFINITE);
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);

        CloseHandle(hThread);
        CloseHandle(hProcess);
        Console.WriteLine("DLL injected successfully.");
    }

    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: DropPrivileges <ProcessId>");
            return;
        }

        Console.WriteLine("Obtaining debug privilege...");
        EnableDebugPrivilege();

        int targetProcessId = int.Parse(args[0]);
        Console.WriteLine("Dropping all privileges...");
        DropAllPrivileges(targetProcessId);
        Console.WriteLine("Injecting monitor DLL...");
        InjectDLL(targetProcessId);
        Console.WriteLine($"Dropped privileges for process ID {targetProcessId}");
    }
}