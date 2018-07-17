// testServer.cpp : Defines the entry point for the console application.
//
#include <iostream>
#include "myProtocol.h"

#pragma comment(lib, "libuvWrapper.lib")

class MyServer : public uv::TCPServer {
public:
	MyServer(uv::Protocol* pro);
protected:
	void messageReceived(int cliendid, const char* buf, int bufsize) override;
};

MyServer::MyServer(uv::Protocol * pro):
	TCPServer(pro)
{
}

void MyServer::messageReceived(int cliendid, const char * buf, int bufsize)
{
	std::cout << "received " << bufsize
		<< " bytes from client " << cliendid << std::endl;
	SendPack(cliendid, buf, bufsize);
}

MyProtocol myProtocol(1001);
MyServer server(&myProtocol);

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
