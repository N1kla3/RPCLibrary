//
// Created by nicola on 15/02/2021.
//

#include "RPC.h"
#include "TCPSocket.h"
#include "Socket.h"
#include "SocketUtil.h"

TCPSocket::~TCPSocket() { close(m_Socket); }

int TCPSocket::Connect(const SocketAddress& inAddress)
{
    int err = connect(m_Socket, &inAddress.m_SockAddr, inAddress.GetSize());
    if (err < 0)
    {
        LOG_ERROR(TCPSocket::Connect);
        return -SocketUtil::GetLastError();
    }
    return 0;
}

int TCPSocket::Bind(const SocketAddress& inToAddress)
{
    int error = bind(m_Socket, &inToAddress.m_SockAddr, inToAddress.GetSize());
    if (error != 0)
    {
        LOG_ERROR(TCPSocket::Bind);
        return SocketUtil::GetLastError();
    }

    return 0;
}

int TCPSocket::Listen(int inBackLog)
{
    int err = listen(m_Socket, inBackLog);
    if (err < 0)
    {
        LOG_ERROR(TCPSocket::Listen);
        return -SocketUtil::GetLastError();
    }
    return 0;
}

std::shared_ptr<TCPSocket> TCPSocket::Accept(SocketAddress& inFromAddress)
{
    socklen_t length = inFromAddress.GetSize();
    int newSocket = accept(m_Socket, &inFromAddress.m_SockAddr, &length);

    if (newSocket != -1) { return TCPSocketPtr(new TCPSocket(newSocket)); }
    else
    {
        LOG_ERROR(TCPSocket::Accept);
        return nullptr;
    }
}

int32_t TCPSocket::Send(const void* inData, size_t inLen)
{
    int bytesSentCount = send(m_Socket, static_cast<const char*>(inData), inLen, 0);
    if (bytesSentCount < 0)
    {
        LOG_ERROR(TCPSocket::Send);
        return -SocketUtil::GetLastError();
    }
    return bytesSentCount;
}

int32_t TCPSocket::Receive(void* inBuffer, size_t inLen)
{
    int bytesReceivedCount = recv(m_Socket, static_cast<char*>(inBuffer), inLen, 0);
    if (bytesReceivedCount < 0)
    {
        LOG_ERROR(TCPSocket::Receive);
        return -SocketUtil::GetLastError();
    }
    return bytesReceivedCount;
}

void TCPSocket::SetNonBlocking()
{
	fcntl(m_Socket, F_SETFL, fcntl(m_Socket, F_GETFL) | O_NONBLOCK);
}

void TCPSocket::SetBlocking()
{
	fcntl(m_Socket, F_SETFL, fcntl(m_Socket, F_GETFL) ^ ~O_NONBLOCK);
}
