# README

## Vulnerabilities

- Will not work on programs that use assembly to call Windows API

## Resources

- https://joyasystems.com/list-of-ntstatus-codes
  - NTSTATUS codes, useful for spoofing error codes

## FOR LATER

- Make it automatically build LunaLib when LunaJuice is compiled
- Delete the library from temp...

## Notes

- Hooking to process works for all threads
- Does not persist across child processes (LogRhythm will handle this? I could fix anyway)
  - Will attempt to fix via hooking