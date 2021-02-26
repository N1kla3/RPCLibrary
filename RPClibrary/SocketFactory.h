//
// Created by nicola on 15/02/2021.
//

#pragma once

#include "Socket.h"

class SocketFactory
{
public:
    static SocketAddressPtr CreateIPv4FromString(const std::string& inString);
};
