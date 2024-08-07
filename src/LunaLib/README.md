# README

## Setup

Make sure to compile [Detours](https://github.com/microsoft/Detours) before using this library:

1. Open `x64 Native Tools Command Prompt for VS 2022` (x64 is important)
2. Change directory to the source folder
3. `nmake`

Just follow this really: https://github.com/SpartanX1/microsoft-detours-example
Same goes for adding the compiled files as dependencies
Releases probably won't compile because they're old

- Make sure to add 'detours.lib' to Linker/Input/Additional Dependencies
- If setting this up again, https://stackoverflow.com/questions/23894196/outputting-a-projects-output-as-embedded-resource-in-another-project-in-vs2013
  - That's how we include the lib DLL as a resource in the main file
  - Don't mark the source as an embedded resource though

## Vulnerabilities

- Will not work on programs that use assembly to call Windows API

## FOR LATER

- Make it automatically build LunaLib when LunaJuice is compiled
- Delete the library from temp...

## Notes

- Hooking to process works for all threads
- Does not persist across child processes (LogRhythm will handle this? I could fix anyway)

# 