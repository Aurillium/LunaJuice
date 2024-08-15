#pragma once
#include <Windows.h>

#define LOG_NAME "LunaLog"

#define HANDLE_CHECK if (LOG_HANDLE == NULL) { std::cerr << "Log handle is closed." << std::endl; return FALSE; }

BOOL OpenLogger();
BOOL CloseLogger();

//BOOL LogFunctionCall(LPCSTR name, LPCSTR result);
BOOL LogStdin(LPCSTR content);
BOOL LogStdout(LPCSTR content);
BOOL LogStderr(LPCSTR content);