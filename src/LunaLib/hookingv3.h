#pragma once

BOOL InstallHookV3(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction);

#define QUICK_HOOK_V3(dll, name) (InstallHookV3(dll, #name, (void*)Hooked_##name, (void**)&Real_##name))