//
// Created by nicola on 17/02/2021.
//

#include "SocketUtil.h"

int SocketUtil::GetLastError()
{
    return errno;
}

TCPSocketPtr SocketUtil::CreateTCPSocket(SocketAddressFamily inFamily)
{
    auto sock = socket(inFamily, SOCK_STREAM, IPPROTO_TCP);
    if (sock != 0)
    {
        return TCPSocketPtr(new TCPSocket(sock));
    }
    else
    {
        LOG_ERROR(cant create socket);
    }
    return TCPSocketPtr();
}

