
#pragma once
#include <Windows.h>

DWORD FindPidByName(LPCSTR name);

bool NoCapCmp(const char* string, const char* other, size_t length);
bool NoCapCmp(const char* string, const char* other);