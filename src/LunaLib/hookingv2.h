#pragma once

BOOL InstallHookV2(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction);

#define QUICK_HOOK_V2(dll, name) (InstallHookV2(dll, #name, (void*)Hooked_##name, (void**)&Real_##name))