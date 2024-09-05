#pragma once

namespace LunaAPI {

	typedef enum _OpCode {
		// 0 does not exist
		// 0x01 - 0x0F for connection/encryption
		Op_Marco					= 0x0001,
		Op_Polo						= 0x0002,
		Op_Disconnect				= 0x000F,

		// 0x10 - 0x2F for hook config
		Op_RegisterHook				= 0x0010,
		Op_SetDefaultMitigations	= 0x0011,
		Op_SetDefaultLogging		= 0x0012,
		Op_SetFunctionConfig		= 0x0013,	// = new
		Op_AddFunctionConfig		= 0x0014,	// = new | current
		Op_DelFunctionConfig		= 0x0015,	// = !new & current
		Op_SetFunctionState			= 0x0016,
		Op_SetSecuritySettings		= 0x0017,

		// 0x30 - 0x3F for security
		Op_GetDefaultPolicy			= 0x0030,
		Op_GetFunctionInfo			= 0x0031,
		Op_GetSecuritySettings		= 0x0032
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