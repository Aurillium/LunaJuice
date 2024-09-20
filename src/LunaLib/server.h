
#pragma once
#include <Windows.h>
#include <functional>
#include <memory.h>
#include <mutex>

#include "Protocol.h"

// Currently no need for more than 2kB in one packet
const SIZE_T MAX_PACKET_BUFFER = 2048;

class LunaConnection {
private:
	HANDLE hPipe;
	std::recursive_mutex mtx;

	// Buffer info
	PVOID currentBuffer;
	SIZE_T currentLength;	// The current length of the whole packet
	SIZE_T bufferPosition;	// The current position within the buffer
	SIZE_T bufferBase;		// The base position of the buffer in the packet
	SIZE_T bufferLength;	// The length of the current buffer
							// Position within buffer = bufferBase + bufferPosition
							// Next read length = min(MAX_DATA, currentLength - (bufferBase + bufferLength))
	LunaAPI::ResponseCode lastResponse;
	BOOL LoadNextBuffer();
public:
	// Util
	LunaConnection(HANDLE hPipe);
	LunaAPI::ResponseCode GetLastError();
	template<typename T> BOOL GetData(T* buffer);	// The only function that should take data from the buffer

	// Helper
	LunaAPI::PacketHeader WaitForPacket();
	BOOL RunCommand();
	static BOOL ServeConnection(LunaConnection* connection);

	// Define important headers for sending data
	BOOL SendHeader(LunaAPI::ResponseCode code, DWORD length = 0);
	BOOL SendPacket(LunaAPI::ResponseCode code, LPCVOID buffer, DWORD length);
	BOOL SendData(LPCVOID buffer, DWORD length);

	// Impl
	BOOL ServerHandshake();
};

BOOL BeginServer(LPVOID lpParam);

template<typename T> BOOL LunaConnection::GetData(T* buffer) {
	std::lock_guard<std::recursive_mutex> lock(mtx);

	size_t length = sizeof(T);
	size_t loaded = 0;

	// Keep reading from the buffer until we have the whole object
	while (loaded < length) {
		size_t bufferAvailable = this->bufferLength - this->bufferPosition;
		if (!bufferAvailable) {
			if (!this->LoadNextBuffer()) {
				WRITELINE_DEBUG("Could not load data buffer.");
				return FALSE;
			}
			// Go back to the start and recalculate available length
			continue;
		}

		// How much data we can load
		size_t toLoad = min(length, bufferAvailable);
		// Not sure why we need this min when this is supposed to be a safe function, but it doesn't work without it :)
		memcpy_s(
			(void*)((uint64_t)buffer + loaded),
			toLoad,
			(void*)((uint64_t)this->currentBuffer + this->bufferPosition),
			toLoad
		);
		this->bufferPosition += toLoad;
		loaded += toLoad;
	}
	return TRUE;

	size_t bufferAvailable = this->bufferLength - this->bufferPosition;
	size_t load = 0;
	if (bufferAvailable) {
		load = min(length, bufferAvailable);
		// Not sure why we need this min when this is supposed to be a safe function, but it doesn't work without it :)
		memcpy_s(buffer, length, (void*)((uint64_t)this->currentBuffer + this->bufferPosition), load);
		WRITELINE_DEBUG("Did some thrunting");
		this->bufferPosition += load;
	}
	if (load < length) {
		if (!this->LoadNextBuffer()) {
			// Could not get data
			return FALSE;
		}

		if (this->bufferLength + load < length) {
			// Buffer not big enough
			this->lastResponse = LunaAPI::Resp_NotEnoughData;
			return FALSE;
		}
		size_t newLoad = min(length - load, this->bufferLength);

		printf("%llu %llu %llu %llu %llu\n", this->bufferLength, this->bufferPosition, load, length, newLoad);
		// Buffer position is 0
		if (newLoad) {
			WRITELINE_DEBUG("About to memcpy");
			// Since this is a new buffer we don't need to worry about the offset
			memcpy_s((void*)((uint64_t)buffer + load), newLoad, this->currentBuffer, newLoad);
		}
		else {
			WRITELINE_DEBUG("Could not load data from next buffer.");
			return FALSE;
		}
		this->bufferPosition += newLoad;

		WRITELINE_DEBUG("Did some more memcpy");
	}
	return TRUE;
}

struct RPCArguments {
	RPCArguments* next;
	void* value;
};
template<typename T> BOOL CollectArguments(LunaConnection* connection, RPCArguments* chain) {
	RPCArguments* node = (RPCArguments*)malloc(sizeof(RPCArguments));
	if (node == NULL) {
		WRITELINE_DEBUG("No room to store RPC call arguments (argument structure).");
		return FALSE;
	}
	chain->next = node;
	T* item = (T*)malloc(sizeof(T));
	if (item == NULL) {
		WRITELINE_DEBUG("No room to store RPC call arguments (argument value).");
		return FALSE;
	}
	if (!connection->GetData(item)) {
		WRITELINE_DEBUG("Could not get item from RPC arguents.");
		return FALSE;
	}
	node->value = item;
	node->next = NULL;
	WRITELINE_DEBUG("Got last argument.");

	return TRUE;
}
template<typename T, typename... Args>
typename std::enable_if<(sizeof...(Args) > 0), BOOL>::type
CollectArguments(LunaConnection* connection, RPCArguments* chain) {
	RPCArguments* node = (RPCArguments*)malloc(sizeof(RPCArguments));
	if (node == NULL) {
		WRITELINE_DEBUG("No room to store RPC call arguments (argument structure).");
		return FALSE;
	}
	chain->next = node;
	T* item = (T*)malloc(sizeof(T));
	if (item == NULL) {
		WRITELINE_DEBUG("No room to store RPC call arguments (argument value).");
		return FALSE;
	}
	if (!connection->GetData(item)) {
		WRITELINE_DEBUG("Could not get item from RPC arguents.");
		return FALSE;
	}
	node->value = item;

	return CollectArguments<Args...>(connection, node);
}


// This wrapper abstracts the RPC interface away and allows us to focus on the logic
template<typename Ret, typename... Args> BOOL RunRPC(LunaConnection* connection, std::function<LunaAPI::ResponseCode(LunaConnection*, Ret*, RPCArguments*)> func) {
	RPCArguments head = { 0 };
	if (!CollectArguments<Args...>(connection, &head)) {
		WRITELINE_DEBUG("Could not collect RPC call arguments.");
	}

	Ret out;
	LunaAPI::ResponseCode ret = func(connection, &out, head.next);

	// Send data back before we free in case arguments are used in response
	BOOL result = TRUE;
	if (ret == LunaAPI::Resp_Success) {
		result = connection->SendPacket(ret, &out, sizeof(out));
	}
	else {
		result = connection->SendHeader(ret);
	}

	// Free arguments
	RPCArguments* node = head.next;
	while (node != NULL) {
		RPCArguments* next = node->next;
		free(node->value);
		free(node);
		node = next;
	}
	return result;
}
