#include "pch.h"

#include "events.h"
#include "messages.h"
#include <iostream>
#include <tlhelp32.h>

#include "hooks.h"

// One instance for the whole process ensures efficiency
HANDLE LOG_HANDLE;

LPCSTR PID;
LPCSTR PPID;
LPCSTR PATH;
LPCSTR PARENT_PATH;

#define DEFAULT_ARGS 5

EXTERN_HOOK(OpenProcess);

// https://gist.github.com/mattn/253013/d47b90159cf8ffa4d92448614b748aa1d235ebe4
static DWORD GetParentProcessId(DWORD pid) {
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}

static BOOL PopulateDetailFields() {
	char* pidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* pathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));
	char* ppidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* parentPathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));

	if (pidBuffer == NULL || pathBuffer == NULL || ppidBuffer == NULL || parentPathBuffer == NULL) {
		std::cerr << "Could not allocate memory for detail fields." << std::endl;
		return FALSE;
	}

	// TODO: More error handling
	DWORD pid = GetCurrentProcessId();
	sprintf_s(pidBuffer, 11, "%d", pid);

	GetModuleFileNameA(NULL, pathBuffer, MAX_PATH);

	DWORD ppid = GetParentProcessId(pid);
	sprintf_s(ppidBuffer, 11, "%d", ppid);

	// This should always run before hooking
#if _DEBUG
	if (Real_OpenProcess != NULL) {
		std::cerr << "ASSERTION FAILED: Real_OpenProcess == NULL. Unexpected behaviour will occur (probably a crash on the next line)." << std::endl;
		std::cerr << "Make sure to hook AFTER this code, or use Real_OpenProcess below." << std::endl;
	}
#endif
	HANDLE parentHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ppid);
	unsigned long bufferLen = MAX_PATH;
	QueryFullProcessImageNameA(parentHandle, 0, parentPathBuffer, &bufferLen);

	PID = pidBuffer;
	PPID = ppidBuffer;
	PATH = pathBuffer;
	PARENT_PATH = parentPathBuffer;

	return TRUE;
}

BOOL OpenLogger() {
	if (LOG_HANDLE != NULL) {
		std::cerr << "Log handle already registered." << std::endl;
		return FALSE;
	}

	// If this succeeds we definitely have all fields populated
	if (!PopulateDetailFields()) {
		std::cerr << "Could not populate details fields." << std::endl;
		return FALSE;
	}

	LOG_HANDLE = RegisterEventSourceA(NULL, LOG_NAME);
	if (LOG_HANDLE == NULL) {
		std::cerr << "Log registration failed. Error: " << GetLastError() << std::endl;
		return FALSE;
	}
	return TRUE;
}

BOOL CloseLogger() {
	if (LOG_HANDLE == NULL) {
		std::cerr << "Log handle already closed." << std::endl;
		return FALSE;
	}

	if (!DeregisterEventSource(LOG_HANDLE)) {
		std::cerr << "Failed to close log. Error: " << GetLastError() << std::endl;
		return FALSE;
	}
	LOG_HANDLE = NULL;
	return TRUE;
}
// Call after freeing your own arguments to avoid memory leaks
static void FreeEventBaseArguments(LPCSTR* arguments, size_t extra = 0) {
	for (size_t i = 0; i < DEFAULT_ARGS + extra; i++)
	{
		free((void*)arguments[i]);
	}
	free(arguments);
}

static LPCSTR GetThreadUsername() {
	char* usernameBuffer = (char*)calloc(SECURITY_MAX_SID_SIZE + 1, sizeof(char));
	char* domainBuffer = (char*)calloc(SECURITY_MAX_SID_SIZE + 1, sizeof(char));

	if (usernameBuffer == NULL || domainBuffer == NULL) {
		std::cerr << "Could not allocate memory to store username and domain." << std::endl;
		return NULL;
	}

	// Gets thread token or process token if no thread token
	HANDLE token = GetCurrentThreadEffectiveToken();
	if (token == NULL) {
		std::cerr << "Could not get current token." << std::endl;
		return NULL;
	}
	DWORD tokenUserSize = 0;
	PTOKEN_USER tokenUser;

	// There will be an error saying there isn't enough space because we're giving it a null pointer
	if (!GetTokenInformation(token, TokenUser, nullptr, 0, &tokenUserSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "Failed to get token user size: " << GetLastError() << std::endl;
		return NULL;
	}

	tokenUser = (PTOKEN_USER)malloc(tokenUserSize);
	if (tokenUser == NULL) {
		std::cerr << "Failed to allocate space for token user." << std::endl;
		return NULL;
	}

	if (!GetTokenInformation(token, TokenUser, tokenUser, tokenUserSize, &tokenUserSize)) {
		std::cerr << "Failed to get token user: " << GetLastError() << std::endl;
		free(tokenUser);
		return NULL;
	}

	DWORD usernameSize = SECURITY_MAX_SID_SIZE;
	DWORD domainSize = SECURITY_MAX_SID_SIZE;
	SID_NAME_USE SidType;
	if (!LookupAccountSidA(nullptr, tokenUser->User.Sid, usernameBuffer, &usernameSize, domainBuffer, &domainSize, &SidType)) {
		std::cerr << "Failed to lookup SID." << std::endl;
		free(tokenUser);
		return NULL;
	}

	DWORD usernameLength = lstrlenA(usernameBuffer);
	DWORD domainLength = lstrlenA(domainBuffer);
	// One extra for null byte, one extra for backslash
	DWORD totalSize = usernameLength + domainLength + 2;
	char* joinedName = (char*)calloc(totalSize, sizeof(char));
	if (joinedName == NULL) {
		std::cerr << "Failed to allocate memory to store username." << std::endl;
		return NULL;
	}
	memcpy_s(joinedName, domainLength, domainBuffer, domainLength);
	joinedName[domainLength] = '\\';
	memcpy_s(joinedName + domainLength + 1, usernameLength, usernameBuffer, usernameLength);

	// This must be freed
	return joinedName;
}

static LPCSTR* EventBaseArguments(size_t extra) {
	HANDLE_CHECK;

	LPCSTR* strings = (LPCSTR*)calloc(DEFAULT_ARGS + extra, sizeof(LPCSTR*));
	if (strings == NULL) {
		return NULL;
	}

	char* pidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* pathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));
	char* ppidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* parentPathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));

	

	if (pidBuffer == NULL || pathBuffer == NULL || ppidBuffer == NULL || parentPathBuffer == NULL) {
		std::cerr << "Could not allocate memory to copy details." << std::endl;
		return NULL;
	}

	memcpy_s(pidBuffer, 11, PID, 11);
	memcpy_s(pathBuffer, MAX_PATH + 1, PATH, MAX_PATH + 1);
	memcpy_s(ppidBuffer, 11, PPID, 11);
	memcpy_s(parentPathBuffer, MAX_PATH + 1, PARENT_PATH, MAX_PATH + 1);

	// This must be freed later
	LPCSTR joinedName = GetThreadUsername();
	if (joinedName == NULL) {
		std::cerr << "Could not get thread username" << std::endl;
		return NULL;
	}

	// These will all get freed by FreeEventBaseArguments
	strings[0] = pidBuffer;
	strings[1] = pathBuffer;
	strings[2] = ppidBuffer;
	strings[3] = joinedName;
	strings[4] = parentPathBuffer;

	return strings;
}

BOOL LogStdin(LPCSTR content) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(1);
	if (arguments == NULL) {
		std::cerr << "An error occurred while collecting base arguments." << std::endl;
		return FALSE;
	}
	arguments[5] = content;
	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_STANDARD_FILE, MSG_STDIN_READ, NULL, 6, 0, arguments, NULL)) {
		std::cerr << "Could not send event: " << GetLastError() << std::endl;
		FreeEventBaseArguments(arguments);
		return FALSE;
	}
	FreeEventBaseArguments(arguments);
	return TRUE;
}

BOOL LogStdout(LPCSTR content) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(1);
	if (arguments == NULL) {
		std::cerr << "An error occurred while collecting base arguments." << std::endl;
		return FALSE;
	}
	arguments[5] = content;
	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_STANDARD_FILE, MSG_STDOUT_WRITE, NULL, 6, 0, arguments, NULL)) {
		std::cerr << "Could not send event: " << GetLastError() << std::endl;
		FreeEventBaseArguments(arguments);
		return FALSE;
	}
	FreeEventBaseArguments(arguments);
	return TRUE;
}

BOOL LogStderr(LPCSTR content) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(1);
	if (arguments == NULL) {
		std::cerr << "An error occurred while collecting base arguments." << std::endl;
		return FALSE;
	}
	arguments[5] = content;
	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_STANDARD_FILE, MSG_STDERR_WRITE, NULL, 6, 0, arguments, NULL)) {
		std::cerr << "Could not send event: " << GetLastError() << std::endl;
		FreeEventBaseArguments(arguments);
		return FALSE;
	}
	FreeEventBaseArguments(arguments);
	return TRUE;
}