
#pragma once
#include <Windows.h>
#include <functional>
#include <memory.h>
#include <mutex>

#include "LunaConnection.h"
#include "Protocol.h"

class LunaServer : public LunaAPI::LunaConnection {
private:
public:
	// Constructor (just calls base class)
	LunaServer(HANDLE hPipe) : LunaAPI::LunaConnection(hPipe) {}

	// Helper
	BOOL RunCommand();
	static BOOL ServeConnection(LunaServer* connection);

	// Impl
	BOOL ServerHandshake();
};

BOOL BeginServer(LPVOID lpParam);


// Grab one argument from RPC input
// We use a dummy parameter here to tell the implementations apart
template<typename T> RPCArguments* GetArgumentNode(LunaConnection* connection, T* _ = NULL) {
	RPCArguments* node = (RPCArguments*)malloc(sizeof(RPCArguments));

	if (node == NULL) {
		WRITELINE_DEBUG("No room to store RPC call arguments (argument structure).");
		return NULL;
	}
	node->next = NULL;

	T* item = (T*)malloc(sizeof(T));
	if (item == NULL) {
		WRITELINE_DEBUG("No room to store RPC call arguments (argument value).");
		free(node);
		return NULL;
	}
	if (!connection->GetTyped(item)) {
		WRITELINE_DEBUG("Could not get item from RPC arguents.");
		free(item);
		free(node);
		return NULL;
	}
	node->value = item;
}
template<> RPCArguments* GetArgumentNode(LunaConnection* connection, char** _);

// Collect arguments into list
template<typename T> BOOL CollectArguments(LunaConnection* connection, RPCArguments* chain) {
	RPCArguments* node = GetArgumentNode<T>(connection);
	if (node == NULL) {
		return FALSE;
	}
	chain->next = node;

	WRITELINE_DEBUG("Got last argument.");

	return TRUE;
}
template<typename T, typename... Args>
typename std::enable_if<(sizeof...(Args) > 0), BOOL>::type
CollectArguments(LunaConnection* connection, RPCArguments* chain) {
	RPCArguments* node = GetArgumentNode<T>(connection);
	if (node == NULL) {
		return FALSE;
	}
	chain->next = node;

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
