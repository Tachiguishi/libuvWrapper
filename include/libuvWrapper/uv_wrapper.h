#ifndef TCPSocket_H
#define TCPSocket_H

#define _WIN32_WINNT 0x600

#include "libuvWrapper/uv.h"
#include <string>
#include <list>
#include <map>
#define BUFFERSIZE (1024*1024)

#ifdef _DEBUG
#pragma comment(lib, "libuvMDd.lib")
#else
#pragma comment(lib, "libuvMD.lib")
#endif // _DEBUG

namespace uv
{
	typedef void(*newconnect)(int clientid);
	typedef void(*server_recvcb)(int cliendid, const char* buf, int bufsize);
	typedef void(*client_recvcb)(const char* buf, int bufsize, void* userdata);

	std::string GetUVError(int retcode);

	class Protocol
	{
	public:
		virtual ~Protocol() {};

		virtual int FramePack(char* pack, int packLen, const char* rawData, int dataLength) = 0;
		virtual int ParsePack(char* &packCache, int &size) = 0;
	};

	class TCPServer;
	class clientdata
	{
	public:
		clientdata(int clientid, Protocol* pro) :client_id(clientid), recvcb_(nullptr), protocol(pro){
			client_handle = (uv_tcp_t*)malloc(sizeof(*client_handle));
			client_handle->data = this;
			readbuffer = uv_buf_init((char*)malloc(BUFFERSIZE), BUFFERSIZE);
			writebuffer = uv_buf_init((char*)malloc(BUFFERSIZE), BUFFERSIZE);
			readStream.clear();
		}
		virtual ~clientdata() {
			free(readbuffer.base);
			readbuffer.base = nullptr;
			readbuffer.len = 0;

			free(writebuffer.base);
			writebuffer.base = nullptr;
			writebuffer.len = 0;

			free(client_handle);
			client_handle = nullptr;
		}
		void rawPackParse(const uv_buf_t * buf, int bufsize);
		int client_id;//客户端id,惟一
		uv_tcp_t* client_handle;//客户端句柄
		TCPServer* tcp_server;//服务器句柄(保存是因为某些回调函数需要到)
		uv_buf_t readbuffer;//接受数据的buf
		uv_buf_t writebuffer;//写数据的buf
		uv_write_t write_req;
		server_recvcb recvcb_;//接收数据回调给用户的函数
		Protocol* protocol;
		std::string readStream;	// 有效数据缓存
	};

	class TCPServer
	{
	public:
		TCPServer(Protocol* protocol, uv_loop_t* loop = uv_default_loop());
		virtual ~TCPServer();
	public:
		//基本函数
		bool Start(const char *ip, int port);//启动服务器,地址为IP4
		bool Start6(const char *ip, int port);//启动服务器，地址为IP6
		void close();

		bool setNoDelay(bool enable);
		bool setKeepAlive(int enable, unsigned int delay);

		const char* GetLastErrMsg() const {
			return errmsg_.c_str();
		};

		int SendPack(char* buf, int length);
		int SendPack(int clientid, char* buf, int length);
		void setnewconnectcb(newconnect cb);
		void setrecvcb(int clientid, server_recvcb cb);//设置接收回调函数，每个客户端各有一个
		bool DeleteClient(int clientid);//删除链表中的客户端
	protected:
		int GetAvailaClientID()const;//获取可用的client id
		int send(int clientid, const char* data, std::size_t len);
		int push2All(const char* data, std::size_t len);

		//静态回调函数
		static void AfterServerRecv(uv_stream_t *client, ssize_t nread, const uv_buf_t* buf);
		static void AfterSend(uv_write_t *req, int status);
		static void onAllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
		static void AfterServerClose(uv_handle_t *handle);
		static void AfterClientClose(uv_handle_t *handle);
		static void acceptConnection(uv_stream_t *server, int status);

	private:
		bool init();
		bool run(int status = UV_RUN_DEFAULT);
		bool bind(const char* ip, int port);
		bool bind6(const char* ip, int port);
		bool listen(int backlog = 1024);

		uv_tcp_t server_;//服务器链接
		std::map<int, clientdata*> clients_list_;//子客户端链接
		uv_mutex_t mutex_handle_;//保护clients_list_
		uv_loop_t *loop_;
		std::string errmsg_;
		newconnect mNewConnCBFun;	// 新连接建立回调函数
		Protocol* _protocol;
		char* _packBuf;
		bool isinit_;//是否已初始化，用于close函数中判断
	};



	class TCPClient
	{
		//直接调用connect/connect6会进行连接
	public:
		TCPClient(Protocol* protocol, uv_loop_t* loop = uv_default_loop());
		virtual ~TCPClient();
	public:
		//基本函数
		bool connect(const char* ip, int port);//启动connect线程，循环等待直到connect完成
		virtual bool connect6(const char* ip, int port);//启动connect线程，循环等待直到connect完成
		int Send(const char* data, std::size_t len);
		
		void setrecvcb(client_recvcb cb, void* userdata);////设置接收回调函数，只有一个
		void close();

		//是否启用Nagle算法
		bool setNoDelay(bool enable);
		bool setKeepAlive(int enable, unsigned int delay);

		const char* GetLastErrMsg() const {
			return errmsg_.c_str();
		};
	protected:
		//静态回调函数
		static void AfterConnect(uv_connect_t* handle, int status);
		static void AfterClientRecv(uv_stream_t *client, ssize_t nread, const uv_buf_t* buf);
		static void AfterSend(uv_write_t *req, int status);
		static void onAllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
		static void AfterClose(uv_handle_t *handle);

		static void ConnectThread(void* arg);//真正的connect线程
		static void ConnectThread6(void* arg);//真正的connect线程

		bool init();
		bool run(int status = UV_RUN_DEFAULT);
		int  send(const char* data, std::size_t len);
	private:
		enum {
			CONNECT_TIMEOUT,
			CONNECT_FINISH,
			CONNECT_ERROR,
			CONNECT_DIS,
		};
		uv_tcp_t client_;//客户端连接
		uv_loop_t *loop_;
		uv_write_t write_req_;//写时请求
		uv_connect_t connect_req_;//连接时请求
		uv_thread_t connect_threadhanlde_;//线程句柄
		std::string errmsg_;//错误信息
		uv_buf_t readbuffer_;//接受数据的buf
		uv_buf_t writebuffer_;//写数据的buf
		uv_mutex_t write_mutex_handle_;//保护write,保存前一write完成才进行下一write

		int connectstatus_;//连接状态
		client_recvcb recvcb_;//回调函数
		void* userdata_;//回调函数的用户数据
		std::string connectip_;//连接的服务器IP
		int connectport_;//连接的服务器端口号
		Protocol* protocol_;
		char* _packBuf;
		bool isinit_;//是否已初始化，用于close函数中判断
	};

}

#endif // TCPSocket_H
