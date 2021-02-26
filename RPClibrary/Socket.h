//
// Created by nicola on 15/02/2021.
//

#pragma once


class SocketAddress
{
public:
    SocketAddress(uint32_t inAddress, uint16_t inPort)
    {
        GetAsSockAddrIn()->sin_family = AF_INET;
        GetIP4Ref() = htonl(inAddress);
        GetAsSockAddrIn()->sin_port = htons(inPort);
    }

    SocketAddress(const sockaddr& inSockAddr) { memcpy(&m_SockAddr, &inSockAddr, sizeof(sockaddr)); }

    SocketAddress()
    {
        GetAsSockAddrIn()->sin_family = AF_INET;
        GetIP4Ref() = INADDR_ANY;
        GetAsSockAddrIn()->sin_port = 0;
    }

    bool operator==(const SocketAddress& inOther) const
    {
        return (m_SockAddr.sa_family == AF_INET && GetAsSockAddrIn()->sin_port == inOther.GetAsSockAddrIn()->sin_port) &&
               (GetIP4Ref() == inOther.GetIP4Ref());
    }

    [[nodiscard]] size_t GetHash() const
    {
        return (GetIP4Ref()) | ((static_cast<uint32_t>(GetAsSockAddrIn()->sin_port)) << 13) | m_SockAddr.sa_family;
    }


    [[nodiscard]] uint32_t GetSize() const { return sizeof(sockaddr); }

private:
    friend class TCPSocket;

    sockaddr m_SockAddr;

    uint32_t& GetIP4Ref() { return GetAsSockAddrIn()->sin_addr.s_addr; }
    [[nodiscard]] const uint32_t& GetIP4Ref() const { return GetAsSockAddrIn()->sin_addr.s_addr; }

    sockaddr_in* GetAsSockAddrIn() { return reinterpret_cast<sockaddr_in*>(&m_SockAddr); }
    [[nodiscard]] const sockaddr_in* GetAsSockAddrIn() const { return reinterpret_cast<const sockaddr_in*>(&m_SockAddr); }
};

typedef std::shared_ptr<SocketAddress> SocketAddressPtr;

namespace std
{
    template<>
    struct hash<SocketAddress> {
        size_t operator()(const SocketAddress& inAddress) const { return inAddress.GetHash(); }
    };
}// namespace std
