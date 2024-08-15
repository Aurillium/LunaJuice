#pragma once
#include <Windows.h>

#define LOG_NAME "LunaLog"

#if _DEBUG
#define HANDLE_CLOSED_MESSAGE std::cerr << "Log handle is closed." << std::endl;
#else
#define HANDLE_CLOSED_MESSAGE
#endif

#define HANDLE_CHECK if (LOG_HANDLE == NULL) { HANDLE_CLOSED_MESSAGE return FALSE; }

BOOL OpenLogger();
BOOL CloseLogger();

//BOOL LogFunctionCall(LPCSTR name, LPCSTR result);
BOOL LogStdin(LPCSTR content);
BOOL LogStdout(LPCSTR content);
BOOL LogStderr(LPCSTR content);