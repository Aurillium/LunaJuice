# README

## Vulnerabilities

- Will not work on programs that use assembly to call Windows API

## Resources

- https://joyasystems.com/list-of-ntstatus-codes
    - NTSTATUS codes, useful for spoofing error codes
- https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines
    - Nt and Zw API calls

## FOR LATER

- Make it automatically build LunaLib when LunaJuice is compiled
- Delete the library from temp...

## Notes

- Hooking to process works for all threads
- Does not persist across child processes (LogRhythm will handle this? I could fix anyway)
    - Will attempt to fix via hooking

### Message Text File
- Must be manually compiled by right-clicking to regenerate headers

### Install Hook Version 3
- Currently some errors:
    - Based on addresses, OpenProcess is a relative address error (instruction occurs at trampoline, address referenced is nearby)
    - Unsure of CreateProcessW error, probably similar -- FIXED: was still inserting jump a static 14 bytes after prologue, negating use of prologue length
    - SmartTrampoline will fix at least OpenProcess
- For now V3 works on functions of interest that V2 does not, so sticking with V2 as the default but adding V3