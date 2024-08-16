#pragma once
#include <windows.h>
#include <winternl.h>

char* ConvertUnicodeStringToAnsi(const UNICODE_STRING& unicodeString);