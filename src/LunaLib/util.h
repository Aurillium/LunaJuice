#pragma once
#include <Windows.h>
#include <winternl.h>

char* ConvertUnicodeStringToAnsi(const UNICODE_STRING& unicodeString);

DWORD GetParentProcessId(DWORD pid);

LPSTR OptimalSprintf(LPCSTR fmt, ...);