#include "libuvWrapper/uv_wrapper.h"
#include <iostream>
#include <assert.h>

void PrintAddress(const struct sockaddr *address) {
	// Test for address and stream
	if (address == NULL)
		return;

	void *numericAddress; // Pointer to binary address
						  // Buffer to contain result (IPv6 sufficient to hold IPv4)
	char addrBuffer[INET6_ADDRSTRLEN];
	unsigned short port; // Port to print
						 // Set pointer to address based on address family
	switch (address->sa_family) {
	case AF_INET:
		numericAddress = &((struct sockaddr_in *) address)->sin_addr;
		port = ntohs(((struct sockaddr_in *) address)->sin_port);
		break;
	case AF_INET6:
		numericAddress = &((struct sockaddr_in6 *) address)->sin6_addr;
		port = ntohs(((struct sockaddr_in6 *) address)->sin6_port);
		break;
	default:
		printf("[unknown type]\n");    // Unhandled type
		return;
	}
	// Convert binary to printable address
	if (inet_ntop(address->sa_family, numericAddress, addrBuffer,
		sizeof(addrBuffer)) == NULL)
		printf("[invalid address]\n"); // Unable to convert
	else {
		printf("%s", addrBuffer);
		if (port != 0)                // Zero not valid in any socket addr
			printf("-%u", port);
		printf("\n");
	}
}

namespace uv
{
	std::string GetUVError(int retcode)
	{
		std::string err;
		err = uv_err_name(retcode);
		err += ":";
		err += uv_strerror(retcode);
		return std::move(err);
	}

	void clientdata::rawPackParse(const uv_buf_t * buf, int bufsize) {
		if (buf == nullptr || bufsize <= 0) {
			return;
		}

		assert(protocol != nullptr);

		for (int i = 0; i < bufsize; i++)
		{
			char item = buf->base[i];
			readStream.push_back(item);
		}

		int size = readStream.size();
		char* payload = const_cast<char*>(readStream.c_str());

		int length = 0;
		while (true)
		{
			length = protocol->ParsePack(payload, size);
			if (length > 0)
			{
				if (recvcb_)
				{
					recvcb_(client_id, payload, length);
				}
				payload += length;
				size -= length;
			}
			else
			{
				break;
			}
		}

		readStream.clear();
		for (int i = length; i < size; i++)
		{
			char item = payload[i];
			readStream.push_back(item);
		}
	}

	/*****************************************TCP Server*************************************************************/
	TCPServer::TCPServer(Protocol* protocol, uv_loop_t* loop)
		:mNewConnCBFun(nullptr), isinit_(false),
		_protocol(protocol)
	{
		loop_ = loop;
		_packBuf = (char*)malloc(BUFFERSIZE);
	}


	TCPServer::~TCPServer()
	{
		close();
		printf("tcp server exit.");

		if (_packBuf != nullptr) {
			free(_packBuf);
			_packBuf = nullptr;
		}
	}

	//初始化与关闭--服务器与客户端一致
	bool TCPServer::init()
	{
		if (isinit_) {
			return true;
		}
		if (!loop_) {
			printf("loop is null on tcp init.");
			return false;
		}
		int iret = uv_mutex_init(&mutex_handle_);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		iret = uv_tcp_init(loop_, &server_);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		isinit_ = true;
		server_.data = this;
		iret = uv_tcp_keepalive(&server_, 1, 60);
		if (iret) {
			errmsg_ = GetUVError(iret);
			return false;
		}
		return true;
	}

	void TCPServer::close()
	{
		for (auto it = clients_list_.begin(); it != clients_list_.end(); ++it) {
			auto data = it->second;
			uv_close((uv_handle_t*)data->client_handle, AfterClientClose);
		}
		clients_list_.clear();

		printf("close server");
		if (isinit_) {
			uv_close((uv_handle_t*)&server_, AfterServerClose);
			printf("close server");
		}
		isinit_ = false;
		uv_mutex_destroy(&mutex_handle_);
	}

	bool TCPServer::run(int status)
	{
		printf("server runing.");
		int iret = uv_run(loop_, (uv_run_mode)status);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}
	//属性设置--服务器与客户端一致
	bool TCPServer::setNoDelay(bool enable)
	{
		int iret = uv_tcp_nodelay(&server_, enable ? 1 : 0);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}

	bool TCPServer::setKeepAlive(int enable, unsigned int delay)
	{
		int iret = uv_tcp_keepalive(&server_, enable, delay);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}

	//作为server时的函数
	bool TCPServer::bind(const char* ip, int port)
	{
		struct sockaddr_in bind_addr;
		int iret = uv_ip4_addr(ip, port, &bind_addr);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		iret = uv_tcp_bind(&server_, (const struct sockaddr*)&bind_addr, 0);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		std::cout << "server bind to" << ip << ":" << port << std::endl;
		return true;
	}

	bool TCPServer::bind6(const char* ip, int port)
	{
		struct sockaddr_in6 bind_addr;
		int iret = uv_ip6_addr(ip, port, &bind_addr);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		iret = uv_tcp_bind(&server_, (const struct sockaddr*)&bind_addr, 0);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		std::cout << "server bind ip=" << ip << ", port=" << port;
		return true;
	}

	bool TCPServer::listen(int backlog)
	{
		int iret = uv_listen((uv_stream_t*)&server_, backlog, acceptConnection);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		printf("server listening\n");
		return true;
	}

	bool TCPServer::Start(const char *ip, int port)
	{
		// close();
		if (!init()) {
			return false;
		}
		if (!bind(ip, port)) {
			return false;
		}
		if (!listen(SOMAXCONN)) {
			return false;
		}
		if (!run()) {
			return false;
		}
		std::cout << "start listen " << ip << ": " << port;
		return true;
	}

	bool TCPServer::Start6(const char *ip, int port)
	{
		close();
		if (!init()) {
			return false;
		}
		if (!bind6(ip, port)) {
			return false;
		}
		if (!listen(SOMAXCONN)) {
			return false;
		}
		if (!run()) {
			return false;
		}
		return true;
	}

	//服务器发送函数
	int TCPServer::send(int clientid, const char* data, std::size_t len)
	{
		auto itfind = clients_list_.find(clientid);
		if (itfind == clients_list_.end()) {
			errmsg_ = "can't find cliendid ";
			errmsg_ += std::to_string((long long)clientid);
			printf(errmsg_.c_str());
			return -1;
		}
		//自己控制data的生命周期直到write结束
		if (itfind->second->writebuffer.len < len) {
			itfind->second->writebuffer.base = (char*)realloc(itfind->second->writebuffer.base, len);
			itfind->second->writebuffer.len = len;
		}
		memcpy(itfind->second->writebuffer.base, data, len);
		uv_buf_t buf = uv_buf_init((char*)itfind->second->writebuffer.base, len);
		uv_write_t *write_req = (uv_write_t*)malloc(sizeof(uv_write_t));
		int iret = uv_write(write_req, (uv_stream_t*)itfind->second->client_handle, &buf, 1, AfterSend);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}

	//服务器到所有客户端
	int TCPServer::push2All(const char* data, std::size_t len)
	{
		for (auto it = clients_list_.begin(); it != clients_list_.end(); ++it)
		{
			send(it->first, data, len);
		}
		return true;
	}

	//服务器-新客户端函数
	void TCPServer::acceptConnection(uv_stream_t *server, int status)
	{
		if (!server->data) {
			return;
		}
		TCPServer *tcpsock = (TCPServer *)server->data;
		int clientid = tcpsock->GetAvailaClientID();
		clientdata* cdata = new clientdata(clientid, tcpsock->_protocol);//uv_close回调函数中释放
		cdata->tcp_server = tcpsock;//保存服务器的信息
		int iret = uv_tcp_init(tcpsock->loop_, cdata->client_handle);//析构函数释放
		if (iret) {
			delete cdata;
			tcpsock->errmsg_ = GetUVError(iret);
			printf(tcpsock->errmsg_.c_str());
			return;
		}
		iret = uv_accept((uv_stream_t*)&tcpsock->server_, (uv_stream_t*)cdata->client_handle);
		if (iret) {
			tcpsock->errmsg_ = GetUVError(iret);
			uv_close((uv_handle_t*)cdata->client_handle, NULL);
			delete cdata;
			printf(tcpsock->errmsg_.c_str());
			return;
		}
		tcpsock->clients_list_.insert(std::make_pair(clientid, cdata));//加入到链接队列
		if (tcpsock->mNewConnCBFun) {
			tcpsock->mNewConnCBFun(clientid);
		}
		std::cout << "new client(" << cdata->client_handle << ") id=" << clientid << std::endl;
		sockaddr addr;
		int len = sizeof(addr);
		uv_tcp_getpeername(cdata->client_handle, &addr, &len);
		PrintAddress(&addr);
		iret = uv_read_start((uv_stream_t*)cdata->client_handle, onAllocBuffer, AfterServerRecv);//服务器开始接收客户端的数据
		return;
	}

	//服务器-接收数据回调函数
	void TCPServer::setrecvcb(int clientid, server_recvcb cb)
	{
		auto itfind = clients_list_.find(clientid);
		if (itfind != clients_list_.end()) {
			itfind->second->recvcb_ = cb;
		}
	}

	int TCPServer::SendPack(char * buf, int length)
	{
		if (!_protocol) return 0;

		std::size_t size = _protocol->FramePack(_packBuf, BUFFERSIZE, buf, length);
		push2All(_packBuf, size);
		return 0;
	}

	int TCPServer::SendPack(int clientid, char * buf, int length)
	{
		if (!_protocol) return 0;

		std::size_t size = _protocol->FramePack(_packBuf, BUFFERSIZE, buf, length);
		send(clientid, _packBuf, size);
		return 0;
	}

	//服务器-新链接回调函数
	void TCPServer::setnewconnectcb(newconnect cb)
	{
		mNewConnCBFun = cb;
	}

	//服务器分析空间函数
	void TCPServer::onAllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
	{
		if (!handle->data) {
			return;
		}
		clientdata *client = (clientdata*)handle->data;
		*buf = client->readbuffer;
	}

	void TCPServer::AfterServerRecv(uv_stream_t *handle, ssize_t nread, const uv_buf_t* buf)
	{
		if (!handle->data) {
			return;
		}
		clientdata *client = (clientdata*)handle->data;//服务器的recv带的是clientdata
		if (nread < 0) {/* Error or EOF */
			TCPServer *server = (TCPServer *)client->tcp_server;
			if (nread == UV_EOF) {
				fprintf(stdout, "客户端(%d)连接断开，关闭此客户端\n", client->client_id);
				std::cout << "客户端(" << client->client_id << ")主动断开" << std::endl;
			}
			else if (nread == UV_ECONNRESET) {
				fprintf(stdout, "客户端(%d)reset\n", client->client_id);
				std::cout << "客户端(" << client->client_id << ")异常断开" << std::endl;
			}
			else {
				fprintf(stdout, "%s\n", GetUVError(nread).c_str());
				std::cout << "客户端(" << client->client_id << ")异常断开：" << GetUVError(nread) << std::endl;
			}
			server->DeleteClient(client->client_id);//连接断开，关闭客户端
			return;
		}
		else if (0 == nread) {/* Everything OK, but nothing read. */

		}
		else if (client->protocol) {
			client->rawPackParse(buf, nread);
		}
	}

	//服务器与客户端一致
	void TCPServer::AfterSend(uv_write_t *req, int status)
	{
		if (status < 0) {
			fprintf(stderr, "send error %s\n", GetUVError(status).c_str());
		}
		free(req);
	}

	void TCPServer::AfterServerClose(uv_handle_t *handle)
	{
		//服务器,不需要做什么
	}

	void TCPServer::AfterClientClose(uv_handle_t *handle)
	{
		clientdata *cdata = (clientdata*)handle->data;
		std::cout << "client " << cdata->client_id << " had closed." << std::endl;
		delete cdata;
	}

	int TCPServer::GetAvailaClientID() const
	{
		static int s_id = 0;
		return ++s_id;
	}

	bool TCPServer::DeleteClient(int clientid)
	{
		uv_mutex_lock(&mutex_handle_);
		auto itfind = clients_list_.find(clientid);
		if (itfind == clients_list_.end()) {
			errmsg_ = "can't find client ";
			errmsg_ += std::to_string((long long)clientid);
			printf(errmsg_.c_str());
			uv_mutex_unlock(&mutex_handle_);
			return false;
		}
		if (uv_is_active((uv_handle_t*)itfind->second->client_handle)) {
			uv_read_stop((uv_stream_t*)itfind->second->client_handle);
		}
		uv_close((uv_handle_t*)itfind->second->client_handle, AfterClientClose);

		clients_list_.erase(itfind);
		std::cout << "从队列中删除客户端" << clientid << std::endl;
		uv_mutex_unlock(&mutex_handle_);
		return true;
	}


	/*****************************************TCP Client*************************************************************/
	TCPClient::TCPClient(Protocol* protocol, uv_loop_t* loop)
		:recvcb_(nullptr), userdata_(nullptr), _packBuf(nullptr)
		, connectstatus_(CONNECT_DIS)
		, isinit_(false),
		protocol_(protocol)
	{
		readbuffer_ = uv_buf_init((char*)malloc(BUFFERSIZE), BUFFERSIZE);
		writebuffer_ = uv_buf_init((char*)malloc(BUFFERSIZE), BUFFERSIZE);
		loop_ = loop;
		connect_req_.data = this;
		write_req_.data = this;
		_packBuf = (char*)malloc(BUFFERSIZE);
	}


	TCPClient::~TCPClient()
	{
		free(readbuffer_.base);
		readbuffer_.base = nullptr;
		readbuffer_.len = 0;
		free(writebuffer_.base);
		writebuffer_.base = nullptr;
		writebuffer_.len = 0;
		close();
		std::cout << "客户端(" << this << ")退出";
		if (_packBuf != nullptr) {
			free(_packBuf);
			_packBuf = nullptr;
		}
	}
	//初始化与关闭--服务器与客户端一致
	bool TCPClient::init()
	{
		if (isinit_) {
			return true;
		}

		if (!loop_) {
			errmsg_ = "loop is null on tcp init.";
			printf(errmsg_.c_str());
			return false;
		}
		int iret = uv_tcp_init(loop_, &client_);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		iret = uv_mutex_init(&write_mutex_handle_);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		isinit_ = true;
		fprintf(stdout, "客户端(%p) init type = %d\n", &client_, client_.type);
		client_.data = this;
		iret = uv_tcp_keepalive(&client_, 1, 60);
		if (iret) {
		    errmsg_ = GetUVError(iret);
			std::cout << errmsg_ << std::endl;
		    return false;
		}
		std::cout << "客户端(" << this << ")Init" << std::endl;
		return true;
	}

	void TCPClient::close()
	{
		if (!isinit_) {
			return;
		}
		uv_mutex_destroy(&write_mutex_handle_);
		uv_close((uv_handle_t*)&client_, AfterClose);
		std::cout << "客户端(" << this << ")close";
		isinit_ = false;
	}

	bool TCPClient::run(int status)
	{
		std::cout << "客户端(" << this << ")run";
		int iret = uv_run(loop_, (uv_run_mode)status);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}

	//属性设置--服务器与客户端一致
	bool TCPClient::setNoDelay(bool enable)
	{
		//http://blog.csdn.net/u011133100/article/details/21485983
		int iret = uv_tcp_nodelay(&client_, enable ? 1 : 0);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}

	bool TCPClient::setKeepAlive(int enable, unsigned int delay)
	{
		int iret = uv_tcp_keepalive(&client_, enable, delay);
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}

	//作为client的connect函数
	bool TCPClient::connect(const char* ip, int port)
	{
		close();
		init();
		connectip_ = ip;
		connectport_ = port;
		std::cout << "客户端(" << this << ")start connect to server(" << ip << ":" << port << ")";
		int iret = uv_thread_create(&connect_threadhanlde_, ConnectThread, this);//触发AfterConnect才算真正连接成功，所以用线程
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		while (connectstatus_ == CONNECT_DIS) {
#if defined (WIN32) || defined(_WIN32)
			Sleep(100);
#else
			usleep((100) * 1000)
#endif
		}
		return connectstatus_ == CONNECT_FINISH;
	}

	bool TCPClient::connect6(const char* ip, int port)
	{
		close();
		init();
		connectip_ = ip;
		connectport_ = port;
		std::cout << "客户端(" << this << ")start connect to server(" << ip << ":" << port << ")";
		int iret = uv_thread_create(&connect_threadhanlde_, ConnectThread6, this);//触发AfterConnect才算真正连接成功，所以用线程
		if (iret) {
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		while (connectstatus_ == CONNECT_DIS) {
			//fprintf(stdout,"client(%p) wait, connect status %d\n",this,connectstatus_);
#if defined (WIN32) || defined(_WIN32)
			Sleep(100);
#else
			usleep((100) * 1000)
#endif
		}
		return connectstatus_ == CONNECT_FINISH;
	}

	void TCPClient::ConnectThread(void* arg)
	{
		TCPClient *pclient = (TCPClient*)arg;
		fprintf(stdout, "client(%p) ConnectThread start\n", pclient);
		struct sockaddr_in bind_addr;
		int iret = uv_ip4_addr(pclient->connectip_.c_str(), pclient->connectport_, &bind_addr);
		if (iret) {
			pclient->errmsg_ = GetUVError(iret);
			printf(pclient->errmsg_.c_str());
			return;
		}
		while (true)
		{
			iret = uv_tcp_connect(&pclient->connect_req_, &pclient->client_, (const sockaddr*)&bind_addr, AfterConnect);
			if (iret) {
				pclient->errmsg_ = GetUVError(iret);
				printf("%s\n", pclient->errmsg_.c_str());
				Sleep(500);

				if (!pclient->isinit_)
				{
					break;
				}

				iret = uv_tcp_init(pclient->loop_, &pclient->client_);
				if (iret) {
					pclient->errmsg_ = GetUVError(iret);
					printf(pclient->errmsg_.c_str());
					return;
				}
				continue;
			}
			fprintf(stdout, "client(%p) ConnectThread end, connect status %d\n", pclient, pclient->connectstatus_);
			pclient->run();
		}
	}


	void TCPClient::ConnectThread6(void* arg)
	{
		TCPClient *pclient = (TCPClient*)arg;
		std::cout << "客户端(" << pclient << ")Enter Connect Thread.";
		fprintf(stdout, "client(%p) ConnectThread start\n", pclient);
		struct sockaddr_in6 bind_addr;
		int iret = uv_ip6_addr(pclient->connectip_.c_str(), pclient->connectport_, &bind_addr);
		if (iret) {
			pclient->errmsg_ = GetUVError(iret);
			printf(pclient->errmsg_.c_str());
			return;
		}
		iret = uv_tcp_connect(&pclient->connect_req_, &pclient->client_, (const sockaddr*)&bind_addr, AfterConnect);
		if (iret) {
			pclient->errmsg_ = GetUVError(iret);
			printf(pclient->errmsg_.c_str());
			return;
		}
		fprintf(stdout, "client(%p) ConnectThread end, connect status %d\n", pclient, pclient->connectstatus_);
		std::cout << "客户端(" << pclient << ")Leave Connect Thread. connect status " << pclient->connectstatus_;
		pclient->run();
	}

	void TCPClient::AfterConnect(uv_connect_t* handle, int status)
	{
		fprintf(stdout, "start after connect\n");
		TCPClient *pclient = (TCPClient*)handle->handle->data;
		if (status) {
			pclient->connectstatus_ = CONNECT_ERROR;
			fprintf(stdout, "connect error:%s\n", GetUVError(status).c_str());
			return;
		}

		int iret = uv_read_start(handle->handle, onAllocBuffer, AfterClientRecv);//客户端开始接收服务器的数据
		if (iret) {
			fprintf(stdout, "uv_read_start error:%s\n", GetUVError(iret).c_str());
			pclient->connectstatus_ = CONNECT_ERROR;
		}
		else {
			pclient->connectstatus_ = CONNECT_FINISH;
		}
		std::cout << "客户端(" << pclient << ")run";
		fprintf(stdout, "end after connect\n");
	}

	int TCPClient::Send(const char* data, std::size_t len) {
		if (!protocol_) return 0;

		std::size_t size = protocol_->FramePack(_packBuf, BUFFERSIZE, data, len);
		return send(_packBuf, size);;
	}

	//客户端的发送函数
	int TCPClient::send(const char* data, std::size_t len)
	{
		//自己控制data的生命周期直到write结束
		if (!data || len <= 0) {
			errmsg_ = "send data is null or len less than zero.";
			return 0;
		}

		uv_mutex_lock(&write_mutex_handle_);
		if (writebuffer_.len < len) {
			writebuffer_.base = (char*)realloc(writebuffer_.base, len);
			writebuffer_.len = len;
		}
		memcpy(writebuffer_.base, data, len);
		uv_buf_t buf = uv_buf_init((char*)writebuffer_.base, len);
		uv_write_t *write_req = (uv_write_t*)malloc(sizeof(uv_write_t));
		int iret = uv_write(write_req, (uv_stream_t*)&client_, &buf, 1, AfterSend);
		if (iret) {
			uv_mutex_unlock(&write_mutex_handle_);
			errmsg_ = GetUVError(iret);
			printf(errmsg_.c_str());
			return false;
		}
		return true;
	}

	//客户端-接收数据回调函数
	void TCPClient::setrecvcb(client_recvcb cb, void* userdata)
	{
		recvcb_ = cb;
		userdata_ = userdata;
	}

	//客户端分析空间函数
	void TCPClient::onAllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
	{
		if (!handle->data) {
			return;
		}
		TCPClient *client = (TCPClient*)handle->data;
		*buf = client->readbuffer_;
	}


	void TCPClient::AfterClientRecv(uv_stream_t *handle, ssize_t nread, const uv_buf_t* buf)
	{
		if (!handle->data) {
			return;
		}
		TCPClient *client = (TCPClient*)handle->data;//服务器的recv带的是TCPClient
		if (nread < 0) {
			if (nread == UV_EOF) {
				fprintf(stdout, "服务器(%p)主动断开\n", handle);
				printf("服务器主动断开");
			}
			else if (nread == UV_ECONNRESET) {
				fprintf(stdout, "服务器(%p)异常断开\n", handle);
				printf("服务器异常断开");
			}
			else {
				fprintf(stdout, "服务器(%p)异常断开:%s\n", handle, GetUVError(nread).c_str());
				std::cout << "服务器异常断开" << GetUVError(nread);
			}
			uv_close((uv_handle_t*)handle, AfterClose);
			return;
		}
		if (nread > 0 && client->recvcb_) {
			client->recvcb_(buf->base, nread, client->userdata_);
		}
	}

	//服务器与客户端一致
	void TCPClient::AfterSend(uv_write_t *req, int status)
	{
		TCPClient *client = (TCPClient *)req->handle->data;
		uv_mutex_unlock(&client->write_mutex_handle_);
		free(req);
		if (status < 0) {
			std::cout << "发送数据有误:" << GetUVError(status);
			fprintf(stderr, "Write error %s\n", GetUVError(status).c_str());
		}
	}
	//服务器与客户端一致
	void TCPClient::AfterClose(uv_handle_t *handle)
	{
		fprintf(stdout, "客户端(%p)已close\n", handle);
		std::cout << "客户端(" << handle << ")已close";
	}
}