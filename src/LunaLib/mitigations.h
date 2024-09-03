#pragma once
#include <Windows.h>

#include "Config.h"

// Return STATUS_PRIVILEGE_NOT_HELD (not a defined header but found at https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
#define BLANKET_NOPERMS_NTSTATUS if (__LUNA->mitigations & LunaAPI::Mitigate_BlanketNoPerms) return 0xC0000061
#define BLANKET_NOPERMS_POINTER if (__LUNA->mitigations & LunaAPI::Mitigate_BlanketNoPerms) {SetLastError(ERROR_ACCESS_DENIED); return NULL;}
#define BLANKET_NOPERMS_BOOL if (__LUNA->mitigations & LunaAPI::Mitigate_BlanketNoPerms) {SetLastError(ERROR_ACCESS_DENIED); return FALSE;}
// 0 is success almost universally (and if we don't set an error and return 0, we handle pointers too)
#define BLANKET_SUCCESS if (__LUNA->mitigations & LunaAPI::Mitigate_BlanketFakeSuccess) return 0x00000000
#define BLANKET_SUCCESS_BOOL if (__LUNA->mitigations & LunaAPI::Mitigate_BlanketFakeSuccess) return TRUE

// If blocking escalation, return permission deined
#define BLOCK_ESC if (__LUNA->mitigations & LunaAPI::Mitigate_BlockEsc) return 0xC0000061

#define NTSTATUS_MITIGATIONS BLANKET_NOPERMS_NTSTATUS; BLANKET_SUCCESS;
#define POINTER_MITIGATIONS BLANKET_NOPERMS_POINTER; BLANKET_SUCCESS;
#define BOOL_MITIGATIONS BLANKET_NOPERMS_BOOL; BLANKET_SUCCESS_BOOL;