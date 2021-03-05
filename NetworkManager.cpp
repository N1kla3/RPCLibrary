//
// Created by nicola on 22/02/2021.
//

#include "RPC.h"
#include "Stream.h"
#include "SocketFactory.h"
#include <memory>
#include "Socket.h"
#include "NetworkManager.h"


NetworkManager::NetworkManager(MANAGER_TYPE type, int port)
		:
		m_Type(type),
		m_Port(port)
{

	m_Socket = SocketUtil::CreateTCPSocket(INET);
	if (type == MANAGER_TYPE::SERVER)
	{
		SocketAddress addr(INADDR_ANY, port);
		m_Socket->Bind(addr);
		LOG_INFO(Server at port) << port;
		m_AcceptingThread = std::thread(&NetworkManager::AcceptConnections, this);
		LOG_INFO(Maximum threads supported - ) << std::thread::hardware_concurrency();
	}
	else if (type == MANAGER_TYPE::CLIENT)
	{
		LOG_INFO(Client init);
	}
}

NetworkManager::~NetworkManager()
= default;


void NetworkManager::SetNetFrequency(float frequency)
{
	m_NetFrequency = frequency;
}

void NetworkManager::SetManagerMode(MANAGER_MODE mode)
{
	m_Mode = mode;
}

MANAGER_MODE NetworkManager::GetManagerMode() const
{
	return m_Mode;
}

/** Client-Side only */
void NetworkManager::Connect(const std::string& address)
{
	if (m_Type == MANAGER_TYPE::CLIENT)
	{
		if (m_Socket->Connect(*SocketFactory::CreateIPv4FromString(address)) < 0)
		{
			LOG_ERROR(NetworkManager::Connect ) << address;
		}
		else bClientConnected = true;

		if (bClientConnected)
		{
			m_OutStreamPtr = std::make_unique<OutputMemoryBitStream>();
			SendHello();
			m_Socket->Send(m_OutStreamPtr->GetBufferPtr(), m_OutStreamPtr->GetByteLength());

			char buffer[32];
			for (int i = 0; i < m_ConnectionTimeLimit; i++)
			{
				int received = m_Socket->Receive(buffer, 1);
				if (received > 0)
				{
					m_InStreamPtr = std::make_unique<InputMemoryBitStream>(buffer, GetRequiredBits<PACKET::MAX>::VALUE);
					PACKET packet;
					m_InStreamPtr->Read(packet);
					if (packet == HELLO)
					{
						LOG_INFO(Connected to Server);
						bClientApproved = true;
					}
					else if (packet == REJECT)
					{
						LOG_INFO(Server reject you);
						bClientConnected = false;
					}
				}
				else
				{
					LOG_INFO(wait responce - ) << i;
					sleep(1);
				}
			}
		}
	}
	else LOG_WARNING(Connect can only be used in client);
}

void NetworkManager::Tick(float deltaTime)
{
	if (m_Mode == MANAGER_MODE::FREQUENCY && !bPendingShutdown)
	{
		float per_second = 1 / m_NetFrequency;
		if (per_second < deltaTime + m_PreviousDelta)
		{
			m_PreviousDelta = deltaTime + m_PreviousDelta;
			return;
		}
		else if (per_second > deltaTime + m_PreviousDelta)
		{
			m_PreviousDelta = 0.f;
		}
		if (m_Type == MANAGER_TYPE::SERVER)
		{
			Server_HandleClients();
		}
		else if (m_Type == MANAGER_TYPE::CLIENT && bClientConnected && bClientApproved)
		{
			HandlePacket(m_Socket);
		}
		SendPacket();
	}
}

MANAGER_TYPE NetworkManager::GetManagerType() const noexcept
{
	return m_Type;
}

/** Server-Only */
void NetworkManager::HandleHelloPacket(const TCPSocketPtr& socket)
{
	if (m_Type == MANAGER_TYPE::SERVER)
	{
		ManagerInfo info;
		info.Read(*m_InStreamPtr);

		bool validation = false;
		if      (m_Level == SECURITY_LEVEL::LOW) validation = ValidateLowLevel(info);
		else if (m_Level == SECURITY_LEVEL::COMMON) validation = ValidateCommonLevel(info);
		else if (m_Level == SECURITY_LEVEL::HIGH) validation = ValidateHighLevel(info);

		if (validation)
		{
			OutputMemoryBitStream stream;
			stream.WriteBits(PACKET::HELLO, GetRequiredBits<PACKET::MAX>::VALUE);
			socket->Send(stream.GetBufferPtr(), stream.GetByteLength());
			m_ConnectionsMutex.lock();
			m_ServerConnections->insert(std::make_pair(info.name, socket));
			m_ServerClientsInfo->insert(std::make_pair(info.name, info));
			m_ConnectionsMutex.unlock();
			LOG_INFO(Client added to clients - ) << info.name;
		}
		else
		{
			LOG_WARNING(Client rejected level validation ) << info.name;
			SendRejected(socket);
		}
	}
}

/** @brief Read function and executes it */
void NetworkManager::HandleFunctionPacket(InputMemoryBitStream& stream)
{
	std::string function_id;
	stream.Read(function_id);
	RPCManager::Proccess(function_id, stream);
}

/** Write to member streams */
void NetworkManager::SendHello()
{
	m_OutStreamPtr->WriteBits(PACKET::HELLO, GetRequiredBits<PACKET::MAX>::VALUE);
	if (m_Type == MANAGER_TYPE::CLIENT)
	{
		m_Info.Write(*m_OutStreamPtr);
	}
}

void NetworkManager::SendRejected(const TCPSocketPtr& socket)
{
	OutputMemoryBitStream stream;
	stream.WriteBits(PACKET::REJECT, GetRequiredBits<PACKET::MAX>::VALUE);
	socket->Send(stream.GetBufferPtr(), stream.GetByteLength());
}

void NetworkManager::HandlePacket(const TCPSocketPtr& socket)
{
	PACKET packet;
	int received = socket->Receive(&packet, 1);
	if (received > 0)
	{
		if (packet == PACKET::DATA)
		{
			socket->SetBlocking();
			uint32_t data_len = 0;
			received = socket->Receive(&data_len, sizeof(data_len));
			if (received > 0)
			{
				char buffer[2048];
				received = socket->Receive(buffer, data_len);
				if (received > 0)
				{
					InputMemoryBitStream stream(buffer, data_len);
					while (stream.GetRemainingBitCount() > 0)
					{
						stream.ReadBits(&packet, GetRequiredBits<PACKET::MAX>::VALUE);
						if (packet == PACKET::FUNCTION)
						{//TODO check parser
							HandleFunctionPacket(stream);
						}//TODO accept of clients on server
					}
				}//TODO send with propriate bytes , question
			}
			socket->SetNonBlocking();
		}
		else if (packet == PACKET::REJECT && m_Type == MANAGER_TYPE::CLIENT)
		{
			bClientConnected = false;
			bClientApproved = false;
			LOG_WARNING(you have been disconnected);
		}
		else if (packet == PACKET::REJECT && m_Type == MANAGER_TYPE::SERVER)
        {
			LOG_INFO(receiving disconnect information);
			socket->SetBlocking();
			char buffer[512];
			received = socket->Receive(buffer, sizeof(uint32_t));
			if (received > 0)
            {
				uint32_t len = buffer[0];
			    received = socket->Receive(buffer, len);
				if (received > 0)
                {
                    InputMemoryBitStream stream(buffer, len);
                    std::string name;
                    stream.Read(name);
                    Server_DisconnectClient(name);
				}
			}
			socket->SetNonBlocking();
		}
	}
}

void NetworkManager::Server_HandleClients()
{
	m_ConnectionsMutex.lock();
	for (auto [name, socket] : *m_ServerConnections)
	{
		 LOG_INFO(handling client ) << name;
		 HandlePacket(socket);
	}
	m_ConnectionsMutex.unlock();
}

void NetworkManager::ReceiveData()
{
	if (m_Mode == MANAGER_MODE::MANUAL)
	{
		if (m_Type == MANAGER_TYPE::CLIENT)
        {
            HandlePacket(m_Socket);
		}
		else if (m_Type == MANAGER_TYPE::SERVER)
        {
		    Server_HandleClients();
		}
	}
}

void NetworkManager::EndFunction()
{
	if (bReadyToWriteFunction)
    {
		bReadyToWriteFunction = false;
		bContainSendData = true;
	}
}

void NetworkManager::SendPacket()
{
    if (bReadyToWritePacket && bContainSendData)
    {
		OutputMemoryBitStream stream;
		stream.WriteBits(PACKET::DATA, GetRequiredBits<PACKET::MAX>::VALUE);
		stream.Write(m_OutStreamPtr->GetByteLength());
        if (m_Type == MANAGER_TYPE::SERVER)
        {
			m_ConnectionsMutex.lock();
		    for (auto& [name, socket] : *m_ServerConnections)
            {
				socket->Send(stream.GetBufferPtr(), stream.GetByteLength());
				socket->Send(m_OutStreamPtr->GetBufferPtr(), m_OutStreamPtr->GetByteLength());
				LOG_INFO(Send packet to client - ) << name;
			}
			m_ConnectionsMutex.unlock();
		}
		else if (m_Type == MANAGER_TYPE::CLIENT && bClientApproved && bClientConnected)
        {
			m_Socket->Send(stream.GetBufferPtr(), stream.GetByteLength());
			m_Socket->Send(m_OutStreamPtr->GetBufferPtr(), m_OutStreamPtr->GetByteLength());
			LOG_INFO(Send packet to server);
		}
	}
}
void NetworkManager::AcceptConnections()
{
	if (m_Type == MANAGER_TYPE::SERVER)
    {
		m_Socket->SetNonBlocking();
		while (!bPendingShutdown)
        {
            SocketAddress addr;
            auto client = m_Socket->Accept(addr);
            if (client)
            {
				LOG_INFO(Accepting client);
                for (int wait = 0; wait < m_ConnectionTimeLimit; wait++)
                {
					char buffer[128];
					auto received = client->Receive(buffer, 1);
					if (received > 0)
                    {
                        PACKET packet = (PACKET)buffer[0];
                        if (packet == HELLO)
                        {
                            client->Receive(buffer, sizeof(ManagerInfo));
                            m_InStreamPtr = std::make_unique<InputMemoryBitStream>(buffer, sizeof(ManagerInfo));
                            HandleHelloPacket(client);
                            break;
                        }
					}
                    sleep(1);
                }
            }
		}
		m_Socket->SetBlocking();
	}
}

void NetworkManager::SetConnectionTimeLimit(int newLimit)
{
	if (newLimit > 0)
    {
        m_ConnectionTimeLimit = newLimit;
	}
}

int NetworkManager::GetConnectionTimeLimit() const
{
	return m_ConnectionTimeLimit;
}

/** after shutdown better not to use object FOR NOW */
void NetworkManager::Server_Shutdown()
{
	if (m_Type == MANAGER_TYPE::SERVER)
    {
        bPendingShutdown = true;
        m_AcceptingThread.join();
        for (auto& [name, socket] : *m_ServerConnections)
        {
            PACKET packet = PACKET::REJECT;
            socket->Send(&packet, 1);
        }
        m_ServerConnections->clear();
        m_ServerClientsInfo->clear();
	}
}

void NetworkManager::Server_DisconnectClient(std::string name)
{
	if (m_Type == MANAGER_TYPE::SERVER)
    {
        m_ConnectionsMutex.lock();

        auto to_delete_iter = m_ServerConnections->find(name);
        if (to_delete_iter != m_ServerConnections->end())
        {
			PACKET packet = PACKET::REJECT;
			to_delete_iter->second->Send(&packet, 1);
            m_ServerConnections->erase(to_delete_iter);
			LOG_INFO(Disconnecting user ) << name;
        }
	    auto to_delete_info = m_ServerClientsInfo->find(name);
		if (to_delete_info != m_ServerClientsInfo->end())
        {
			m_ServerClientsInfo->erase(to_delete_info);
			LOG_INFO(Deleting user information of ) << name;
		}

		m_ConnectionsMutex.unlock();
	}
}

void NetworkManager::Client_Disconnect()
{
	if (m_Type == MANAGER_TYPE::CLIENT)
    {
        OutputMemoryBitStream stream;
		stream.WriteBits(PACKET::REJECT, GetRequiredBits<PACKET::MAX>::VALUE);
		stream.Write((uint32_t)m_Info.name.size());
		stream.Write(m_Info.name);
		m_Socket->Send(stream.GetBufferPtr(), stream.GetByteLength());
	}
}

//TODO packet data limit
void ManagerInfo::Write(OutputMemoryBitStream& stream)
{
	stream.Write(name);
}

void ManagerInfo::Read(InputMemoryBitStream& stream)
{
	stream.Read(name);
}
