// testServer.cpp : Defines the entry point for the console application.
//
#include "myProtocol.h"

#pragma comment(lib, "libuvWrapper.lib")

MyProtocol myProtocol(1001);
uv::TCPServer server(&myProtocol);

void clientDataRecv(int clientid, const char* buf, int bufsize) {
	printf("receive %d data from client %d : %s\n", bufsize, clientid, buf);
}

void newClientConnectCB(int clientid) {
	server.setrecvcb(clientid, clientDataRecv);
}

int main(int argc, char** argv)
{
	server.setnewconnectcb(newClientConnectCB);
	server.Start("0.0.0.0", 9090);
}
