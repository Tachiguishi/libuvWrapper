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
		int client_id;//�ͻ���id,Ωһ
		uv_tcp_t* client_handle;//�ͻ��˾��
		TCPServer* tcp_server;//���������(��������ΪĳЩ�ص�������Ҫ��)
		uv_buf_t readbuffer;//�������ݵ�buf
		uv_buf_t writebuffer;//д���ݵ�buf
		uv_write_t write_req;
		server_recvcb recvcb_;//�������ݻص����û��ĺ���
		Protocol* protocol;
		std::string readStream;	// ��Ч���ݻ���
	};

	class TCPServer
	{
	public:
		TCPServer(Protocol* protocol, uv_loop_t* loop = uv_default_loop());
		virtual ~TCPServer();
	public:
		//��������
		bool Start(const char *ip, int port);//����������,��ַΪIP4
		bool Start6(const char *ip, int port);//��������������ַΪIP6
		void close();

		bool setNoDelay(bool enable);
		bool setKeepAlive(int enable, unsigned int delay);

		const char* GetLastErrMsg() const {
			return errmsg_.c_str();
		};

		int SendPack(char* buf, int length);
		int SendPack(int clientid, char* buf, int length);
		void setnewconnectcb(newconnect cb);
		void setrecvcb(int clientid, server_recvcb cb);//���ý��ջص�������ÿ���ͻ��˸���һ��
		bool DeleteClient(int clientid);//ɾ�������еĿͻ���
	protected:
		int GetAvailaClientID()const;//��ȡ���õ�client id
		int send(int clientid, const char* data, std::size_t len);
		int push2All(const char* data, std::size_t len);

		//��̬�ص�����
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

		uv_tcp_t server_;//����������
		std::map<int, clientdata*> clients_list_;//�ӿͻ�������
		uv_mutex_t mutex_handle_;//����clients_list_
		uv_loop_t *loop_;
		std::string errmsg_;
		newconnect mNewConnCBFun;	// �����ӽ����ص�����
		Protocol* _protocol;
		char* _packBuf;
		bool isinit_;//�Ƿ��ѳ�ʼ��������close�������ж�
	};



	class TCPClient
	{
		//ֱ�ӵ���connect/connect6���������
	public:
		TCPClient(Protocol* protocol, uv_loop_t* loop = uv_default_loop());
		virtual ~TCPClient();
	public:
		//��������
		bool connect(const char* ip, int port);//����connect�̣߳�ѭ���ȴ�ֱ��connect���
		virtual bool connect6(const char* ip, int port);//����connect�̣߳�ѭ���ȴ�ֱ��connect���
		int Send(const char* data, std::size_t len);
		
		void setrecvcb(client_recvcb cb, void* userdata);////���ý��ջص�������ֻ��һ��
		void close();

		//�Ƿ�����Nagle�㷨
		bool setNoDelay(bool enable);
		bool setKeepAlive(int enable, unsigned int delay);

		const char* GetLastErrMsg() const {
			return errmsg_.c_str();
		};
	protected:
		//��̬�ص�����
		static void AfterConnect(uv_connect_t* handle, int status);
		static void AfterClientRecv(uv_stream_t *client, ssize_t nread, const uv_buf_t* buf);
		static void AfterSend(uv_write_t *req, int status);
		static void onAllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
		static void AfterClose(uv_handle_t *handle);

		static void ConnectThread(void* arg);//������connect�߳�
		static void ConnectThread6(void* arg);//������connect�߳�

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
		uv_tcp_t client_;//�ͻ�������
		uv_loop_t *loop_;
		uv_write_t write_req_;//дʱ����
		uv_connect_t connect_req_;//����ʱ����
		uv_thread_t connect_threadhanlde_;//�߳̾��
		std::string errmsg_;//������Ϣ
		uv_buf_t readbuffer_;//�������ݵ�buf
		uv_buf_t writebuffer_;//д���ݵ�buf
		uv_mutex_t write_mutex_handle_;//����write,����ǰһwrite��ɲŽ�����һwrite

		int connectstatus_;//����״̬
		client_recvcb recvcb_;//�ص�����
		void* userdata_;//�ص��������û�����
		std::string connectip_;//���ӵķ�����IP
		int connectport_;//���ӵķ������˿ں�
		Protocol* protocol_;
		char* _packBuf;
		bool isinit_;//�Ƿ��ѳ�ʼ��������close�������ж�
	};

}

#endif // TCPSocket_H
