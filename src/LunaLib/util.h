#pragma once
#include <Windows.h>
#include <winternl.h>

#define NOT_WHITESPACE(expr) (expr != ' ' && expr != '\t' && expr != '\n' && expr != '\r')
#define IS_WHITESPACE(expr) (expr == ' ' || expr == '\t' || expr == '\n' || expr == '\r')

char* ConvertUnicodeStringToAnsi(const UNICODE_STRING& unicodeString);

DWORD GetParentProcessId(DWORD pid);