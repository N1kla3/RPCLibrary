//
// Created by nicola on 15/02/2021.
//

#pragma once


class SocketAddress;

/** @brief Non-blocking by default */
class TCPSocket
{
public:
	virtual ~TCPSocket();

	int Connect(const SocketAddress& inAddress);

	int Bind(const SocketAddress& inToAddress);

	int Listen(int inBackLog = 32);

	std::shared_ptr<TCPSocket> Accept(SocketAddress& inFromAddress);

	int32_t Send(const void* inData, size_t inLen);

	int32_t Receive(void* inBuffer, size_t inLen);

	void SetNonBlocking();

	void SetBlocking();
private:

	friend class SocketUtil;

	explicit TCPSocket(int inSocket)
			: m_Socket(inSocket)
	{
		SetNonBlocking();
	}

	int m_Socket;
};

typedef std::shared_ptr<TCPSocket> TCPSocketPtr;