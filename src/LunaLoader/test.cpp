#include "pch.h"
#include <iostream>

#include "output.h"

#include "Implant.h"

#define RESP_CHECK(resp, expr) DISP_LOG(#expr "..."); \
resp = expr; \
if (resp != LunaAPI::Resp_Success) { \
	DISP_ERROR("Error in '" #expr "': " << resp); \
	return FALSE; \
}

BOOL TestRPC(LunaAPI::LunaImplant implant) {
	DISP_LOG("Testing connect...");
	LunaAPI::ResponseCode resp;
	// Connect
	RESP_CHECK(resp, implant.Connect());
	RESP_CHECK(resp, implant.RegisterHook("ntdll.dll!NtReadFile"));

	LunaAPI::MitigationFlags miti = LunaAPI::Mitigate_BlanketNoPerms | LunaAPI::Mitigate_BlanketFakeSuccess;
	LunaAPI::LogFlags logs = LunaAPI::Log_Signature | LunaAPI::Log_PrivilegeAdjust;

	RESP_CHECK(resp, implant.SetDefaultMitigations(miti));
	RESP_CHECK(resp, implant.SetDefaultLogs(logs));

	LunaAPI::Policy policy = LunaAPI::Policy();

	// This is failing saying invalid handle
	// Server also fails saying it can't read from pipe
	// Pipe is likely being broken either here or the return of the last function, unsure why
	RESP_CHECK(resp, implant.GetDefaultPolicy(&policy));

	return TRUE;
}