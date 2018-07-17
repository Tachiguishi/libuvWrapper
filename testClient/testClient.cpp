// testClient.cpp : Defines the entry point for the console application.
//

#include <thread>
#include <string>
#include <iostream>
#include "myProtocol.h"

#pragma comment(lib, "libuvWrapper.lib")

class MyClient : public uv::TCPClient {
public:
	MyClient(uv::Protocol* protocol);
protected:
	void messageReceived(const char* buf, int bufsize);
};

MyClient::MyClient(uv::Protocol* protocol):
	TCPClient(protocol)
{

}
void MyClient::messageReceived(const char* buf, int bufsize) {
	std::cout << buf;
}

MyProtocol myProtocol(1001);
MyClient client(&myProtocol);
bool bTrackConnected(false);

void thread_main()
{
	bTrackConnected = client.connect("127.0.0.1", 9090);
}

int main()
{
	std::thread comm_thread(thread_main);
	comm_thread.detach();

	while (true)
	{
		if (bTrackConnected)
		{
			std::string text;
			std::cin >> text;
			client.Send(text.c_str(), text.size());
		}
	}
	return 0;
}
