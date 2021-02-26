//
// Created by nicola on 17/02/2021.
//

#pragma once

#include "TCPSocket.h"

enum SocketAddressFamily
{
    INET = AF_INET,
    INET6 = AF_INET6
};

class SocketUtil
{
public:
    static int GetLastError();

    static TCPSocketPtr CreateTCPSocket(SocketAddressFamily inFamily);
};
