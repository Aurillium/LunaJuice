#pragma once

namespace LunaAPI {

	typedef enum _OpCode {
		// 1 - 15 reserved for connection/encryption
		Op_RegisterHook				= 0x0010,
		Op_SetDefaultMitigations	= 0x0011,
		Op_SetDefaultLogging		= 0x0012,
		Op_SetFunctionConfig		= 0x0013,
		Op_AddFunctionConfig		= 0x0014,
		Op_DelFunctionConfig		= 0x0015,
		Op_SetFunctionState			= 0x0016,
		Op_SetSecuritySettings		= 0x0017,

		Op_GetDefaultPolicy			= 0x0020,
		Op_GetFunctionInfo			= 0x0021,
		Op_GetSecuritySettings		= 0x0022
	} OpCode;

	typedef enum _ResponseCode {
		Resp_Success		= 0x8000,
		Resp_Error			= 0xf000,
		Resp_InvalidRequest	= 0xf001,
		Resp_OutOfMemory	= 0xf002,
		Resp_InvalidCommand	= 0xf003,
		Resp_BadParameter	= 0xf004,
		Resp_UnknownError	= 0xf005
	} ResponseCode;

	typedef union _CommCode {
		ResponseCode response;
		OpCode opcode;
	} CommCode;

	typedef struct _PacketHeader {
		CommCode code;
		DWORD length;
	} PacketHeader;
}