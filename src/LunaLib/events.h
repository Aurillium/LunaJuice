#pragma once
#include <Windows.h>

#define LOG_NAME "LunaJuice"

#if _DEBUG
#define HANDLE_CLOSED_MESSAGE std::cerr << "Log handle is closed." << std::endl;
#else
#define HANDLE_CLOSED_MESSAGE
#endif

#define LOG_FUNCTION_CALL(function, ...) {\
	SIGNATURE_FMT_HELPER* info = GetSignatureTemplate(String_##function); \
	LPSTR formatted = FormatSignature(info->fmtSignature, info->numArgs, __VA_ARGS__); \
	LogFunctionCall(formatted); \
	free(info->fmtSignature); \
	free(info); \
}

#define HANDLE_CHECK if (LOG_HANDLE == NULL) { HANDLE_CLOSED_MESSAGE return FALSE; }

BOOL OpenLogger();
BOOL CloseLogger();

//BOOL LogFunctionCall(LPCSTR name, LPCSTR result);
BOOL LogStdin(LPCSTR content);
BOOL LogStdout(LPCSTR content);
BOOL LogStderr(LPCSTR content);
BOOL LogParentSpoof(DWORD fakeParent, LPCSTR image, LPCSTR parameters, DWORD pid);
BOOL LogProcessCreate(LPCSTR image, LPCSTR parameters, DWORD pid);
BOOL LogPrivilegeAdjust(BOOL added, ULONG privilege);
BOOL LogFunctionCall(LPCSTR signature);

CONST LPCSTR GetOwnPath();
CONST LPCSTR GetOwnPid();
CONST LPCSTR GetParentPath();
CONST LPCSTR GetParentPid();
CONST DWORD GetParentPidInt();