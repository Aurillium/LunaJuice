#include "pch.h"
#include <iostream>

#include "output.h"

#include "Implant.h"

#define RESP_CHECK(resp, expr) DISP_LOG(#expr "..."); \
resp = expr; \
if (resp != LunaAPI::Resp_Success) { \
	DISP_ERROR("Error in '" #expr "': " << resp << ", IsConnected() = " << implant.IsConnected()); \
	return FALSE; \
}

BOOL TestRPC(LunaAPI::LunaImplant implant) {
	DISP_LOG("Testing connect...");
	LunaAPI::ResponseCode resp;
	// Connect
	RESP_CHECK(resp, implant.Connect());

	int c;
	RESP_CHECK(resp, implant.AdditionTest(0x00002169, 0x000034, &c));
	printf("Addition result: %d\n", c);

	// Redo the rest when the RPC itself is working
	return TRUE;

	RESP_CHECK(resp, implant.RegisterHook("ntdll.dll!RtlAdjustPrivilege"));
	RESP_CHECK(resp, implant.RegisterHook("ntdll.dll!NtReadFile"));

	LunaAPI::MitigationFlags miti = LunaAPI::Mitigate_BlanketNoPerms | LunaAPI::Mitigate_BlanketFakeSuccess;
	LunaAPI::LogFlags logs = LunaAPI::Log_Signature | LunaAPI::Log_PrivilegeAdjust;

	printf("Logs: 0x%08x\n", logs);
	printf("Miti: 0x%08x\n", miti);

	RESP_CHECK(resp, implant.SetDefaultMitigations(miti));
	RESP_CHECK(resp, implant.SetDefaultLogs(logs));

	LunaAPI::Policy policy = LunaAPI::Policy();

	//RESP_CHECK(resp, implant.GetDefaultPolicy(&policy));

	printf("Logs: 0x%08x\n", policy.logs);
	printf("Miti: 0x%08x\n", policy.mitigations);
	printf("Sec:  0x%08x\n", policy.security);

	LunaAPI::HookID regSize = 0;
	RESP_CHECK(resp, implant.GetRegistrySize(&regSize));

	DISP_LOG("Registry size: " << regSize);

	miti = LunaAPI::Mitigate_BlanketFakeSuccess | LunaAPI::Mitigate_BlockEsc;
	logs = LunaAPI::Log_SpawnProcess | LunaAPI::Log_Stderr | LunaAPI::Log_PrivilegeAdjust;
	RESP_CHECK(resp, implant.SetFunctionConfig("ntdll.dll!NtReadFile", miti, logs));

	miti = LunaAPI::Mitigate_BlockEsc | (LunaAPI::MitigationFlags)0xffff;
	logs = LunaAPI::Log_SpawnProcess | LunaAPI::Log_Stdin | LunaAPI::Log_Stdout;
	RESP_CHECK(resp, implant.AddFunctionConfig("ntdll.dll!NtReadFile", miti, logs));

	miti = LunaAPI::Mitigate_BlockEsc | (LunaAPI::MitigationFlags)0xf0ff;
	logs = LunaAPI::Log_SpawnProcess | LunaAPI::Log_PrivilegeAdjust | LunaAPI::Log_SpoofPPID | LunaAPI::Log_Stdout;
	RESP_CHECK(resp, implant.DelFunctionConfig("ntdll.dll!NtReadFile", miti, logs));

	// Should now be LunaAPI::Log_Stderr | LunaAPI::Log_Stdin (10)
	LunaAPI::HookConfig config = LunaAPI::HookConfig();
	BOOL enabled;
	RESP_CHECK(resp, implant.GetFunctionInfo("ntdll.dll!NtReadFile", &config, &enabled));

	printf("Logs: 0x%08x\n", config.logs);
	printf("Miti: 0x%08x\n", config.mitigations);
	printf("Hook: 0x%016llx\n", config.hook);
	printf("Bool: %d\n", enabled);

	LunaAPI::HookID id;
	RESP_CHECK(resp, implant.QueryByIdentifier("ntdll.dll!NtReadFile", &id));
	DISP_LOG("Resolved hook ID: " << id);

	RESP_CHECK(resp, implant.SetSecuritySettings(LunaAPI::Sec_BlockAll));
	//RESP_CHECK(resp, implant.GetDefaultPolicy(&policy));
	printf("Security: 0x%08x\n", policy.security);

	RESP_CHECK(resp, implant.SetFunctionState(id, FALSE));
	RESP_CHECK(resp, implant.GetFunctionInfo(id, &config, &enabled));
	printf("Bool: %d\n", enabled);

	if (implant.IsConnected()) {
		DISP_LOG("I am still connected.");
	}
	else {
		DISP_LOG("I am no longer connected.");
	}

	return TRUE;
}