#pragma once

namespace LunaAPI {

	// The registry is not designed to be used by the client, it is
	// only intended to be used to set up new connections
	typedef enum _OpCode {
		// 0 does not exist
		// 0x01 - 0x0F for connection/encryption
		Op_Marco					= 0x0001,
		Op_Polo						= 0x0002,
		Op_Disconnect				= 0x000F,

		// 0x10 - 0x2F for set config
		Op_RegisterHook				= 0x0010,	// Done
		Op_SetDefaultMitigations	= 0x0011,	// Untested - needs client
		Op_SetDefaultLogging		= 0x0012,	// Untested - needs client
		Op_SetFunctionConfig		= 0x0013,	// Untested - needs client
		Op_AddFunctionConfig		= 0x0014,	// Untested - needs client
		Op_DelFunctionConfig		= 0x0015,	// Untested - needs client
		Op_SetFunctionState			= 0x0016,	// Untested - needs client
		Op_SetSecuritySettings		= 0x0017,	// Untested - needs client

		// 0x30 - 0x3F for get config
		// x33 and x32 can be used to enumerate the registry
		Op_GetDefaultPolicy			= 0x0030,	// Untested - needs client
		Op_GetFunctionInfo			= 0x0031,	// Untested - needs client
		Op_GetFunctionIdentifier	= 0x0032,	
		Op_GetRegistrySize			= 0x0033,	// Untested - needs client
		Op_QueryByIdentifier		= 0x0034	// Untested - needs client
	} OpCode;

	typedef enum _ResponseCode {
		Resp_Success			= 0x8000,
		Resp_Error				= 0xf000,
		Resp_InvalidRequest		= 0xf001,
		Resp_OutOfMemory		= 0xf002,
		Resp_InvalidCommand		= 0xf003,
		Resp_BadParameter		= 0xf004,
		Resp_UnknownError		= 0xf005,	// In general we should aim to minimise this
		Resp_UnsupportedHook	= 0xf006,
		Resp_NotFound			= 0xf007,
		Resp_OperationFailed	= 0xf008,

		// "Virtual" codes, used by the client internally
		Resp_Disconnect			= 0xff00,
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