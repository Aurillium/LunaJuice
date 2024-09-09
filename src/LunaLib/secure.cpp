#include "pch.h"

#include "Config.h"

LunaAPI::SecuritySettings SECURITY = LunaAPI::DEFAULT_SECURITY;

LunaAPI::SecuritySettings GetSecuritySettings() {
	return SECURITY;
}
void SetSecuritySettings(LunaAPI::SecuritySettings security) {
	SECURITY = security;
}