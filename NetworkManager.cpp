//
// Created by nicola on 22/02/2021.
//

#include "NetworkManager.h"
#include "RPC.h"
#include "Socket.h"
#include "SocketFactory.h"
#include "Stream.h"
#include <libnetlink.h>
#include <memory>

/** Utility structure for non blocking packet receive */
struct ReceivePacketInfo
{
    char* buffer = nullptr;
    uint16_t current = 0;
    uint16_t want_to_receive = 0;
    uint16_t required_bits = 0;
	bool is_initialized = false;
	bool is_len_received = false;

    void Init(uint16_t wantToReceive, uint16_t requiredBits)
    {
		buffer = new char[wantToReceive];
        want_to_receive = wantToReceive;
		required_bits = requiredBits;
		is_initialized = true;
    }
    bool IsInit()
    {
        return is_initialized;
    }
    void Destroy()
    {
        delete[] buffer;
        current = 0;
		is_initialized = false;
    }
	~ReceivePacketInfo()
    {
		if (is_initialized) delete buffer;
	}
};

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
		LOG_INFO("Server at port") << port;
		if (m_Socket->Listen() < 0) LOG_FATAL("SERVER CANT LISTEN");
		m_AcceptingThread = std::thread(&NetworkManager::AcceptConnections, this);
		LOG_INFO("Maximum threads supported - ") << std::thread::hardware_concurrency();
		m_ServerConnections = std::make_unique<std::unordered_map<std::string, TCPSocketPtr>>();
        m_ServerClientsInfo = std::make_unique<std::unordered_map<std::string, ManagerInfo>>();
		m_ServerPacketConditions = std::make_unique<std::unordered_map<std::string, ReceivePacketInfo>>();
	}
	else if (type == MANAGER_TYPE::CLIENT)
	{
		m_ClientPacketConditionPtr = std::make_unique<ReceivePacketInfo>();
		LOG_INFO("Client init");
	}
}

NetworkManager::~NetworkManager()
{
	Server_Shutdown();
	LOG_INFO("DESTORYING NETWORK MANAGER");
}



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
void NetworkManager::Connect(const std::string& address, int port)
{
	if (m_Type == MANAGER_TYPE::CLIENT)
	{
		if (bClientConnected) return;
        SocketAddress addr(inet_addr(address.c_str()), port);
		if (m_Socket->Connect(addr) < 0)
		{
			LOG_ERROR("NetworkManager::Connect ") << address << SocketUtil::GetLastError();
		}
		else bClientConnected = true;

		if (bClientConnected)
		{
			auto packet = PACKET::HELLO;
			m_Socket->Send(&packet, 1);
			m_OutStreamPtr = std::make_unique<OutputMemoryBitStream>();
			SendHello();
			LOG_INFO("Send info");

			char buffer[32];
			for (int i = 0; i < m_ConnectionTimeLimit; i++)
			{
				LOG_INFO("Wait result");
				int received = m_Socket->Receive(buffer, 1);
				if (received > 0)
				{
					LOG_INFO("Received answer");
                    packet = (PACKET)buffer[0];
					if (packet == HELLO)
					{
						LOG_INFO("Connected to Server");
						bClientApproved = true;
						return;
					}
					else if (packet == REJECT)
					{
						LOG_INFO("Server reject you");
						bClientConnected = false;
						return;
					}
				}
				else
				{
					LOG_INFO("wait responce - ") << i;
					sleep(1);
				}
			}
		}
	}
	else LOG_WARNING("Connect can only be used in client");
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
			PACKET packet = PACKET::HELLO;
			socket->Send(&packet, 1);
			m_ConnectionsMutex.lock();
			m_ServerConnections->insert(std::make_pair(info.name, socket));
			m_ServerClientsInfo->insert(std::make_pair(info.name, info));
			m_ConnectionsMutex.unlock();
			LOG_INFO("Client added to clients - ") << info.name;
		}
		else
		{
			LOG_WARNING("Client rejected level validation ") << info.name;
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

/** CLIENT ONLY Write to member streams */
void NetworkManager::SendHello()
{
	if (m_Type == MANAGER_TYPE::CLIENT)
	{
		m_Info.Write(*m_OutStreamPtr);
		uint32_t len = m_OutStreamPtr->GetBitLength();
		m_Socket->Send(&len, sizeof(uint32_t));
		m_Socket->Send(m_OutStreamPtr->GetBufferPtr(), m_OutStreamPtr->GetByteLength());
	}
}

void NetworkManager::SendRejected(const TCPSocketPtr& socket)
{
	OutputMemoryBitStream stream;
	stream.WriteBits(PACKET::REJECT, GetRequiredBits<PACKET::MAX>::VALUE);
	socket->Send(stream.GetBufferPtr(), stream.GetByteLength());
}

void NetworkManager::HandlePacket(const TCPSocketPtr& socket, const std::string& name)
{
	if (bReceivedNotAll)
    {

	}
	if ((m_ServerPacketConditions->find(name) != m_ServerPacketConditions->end())
	    && (m_ServerPacketConditions->at(name).is_initialized))
    {

	}
	PACKET packet;
	char buf[1];
	int received = socket->Receive(&buf, 1);
	if (received > 0)
	{
        packet = (PACKET)buf[0];
        LOG_INFO("Prepare packet receive-") << packet;
		if (packet == PACKET::DATA)
		{
			LOG_INFO("Wait packet");
			//TODO make non blocking
			uint32_t data_len = 0;
			received = socket->Receive(&data_len, sizeof(uint32_t));
			if (received > 0)
			{
				char buffer[2048];
				received = socket->Receive(buffer, data_len);
				if (received > 0)
				{
					InputMemoryBitStream stream(buffer, data_len);
					while (stream.GetRemainingBitCount() > 0)
					{
						LOG_DEBUG("Reading packet buffer") << data_len;
						stream.ReadBits(&packet, GetRequiredBits<PACKET::MAX>::VALUE);
						if (packet == PACKET::FUNCTION)
						{
							HandleFunctionPacket(stream);
						}
					}
				}
			}
		}
		else if (packet == PACKET::REJECT && m_Type == MANAGER_TYPE::CLIENT)
		{
			bClientConnected = false;
			bClientApproved = false;
			LOG_WARNING("you have been disconnected");
		}
		else if (packet == PACKET::REJECT && m_Type == MANAGER_TYPE::SERVER)
        {
			LOG_INFO("receiving disconnect information");
			socket->SetBlocking();
			char buffer[512];
			received = socket->Receive(buffer, sizeof(uint32_t));
			if (received > 0)
            {
				uint32_t len = *reinterpret_cast<uint32_t *>(&buffer[0]);
				LOG_DEBUG("name len ") << len;
			    received = socket->Receive(buffer, len);
				if (received > 0)
                {
                    InputMemoryBitStream stream(buffer, len << 3);
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
	for (auto& [name, socket] : *m_ServerConnections)
	{
		 LOG_INFO("handling client ") << name;
		 HandlePacket(socket, name);
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
        if (m_Type == MANAGER_TYPE::SERVER)
        {
			m_ConnectionsMutex.lock();
		    for (auto& [name, socket] : *m_ServerConnections)
            {
				PACKET packet = PACKET::DATA;
				socket->Send(&packet, 1);
				uint32_t len = m_OutStreamPtr->GetBitLength();
				socket->Send(&len, sizeof(uint32_t));
				socket->Send(m_OutStreamPtr->GetBufferPtr(), m_OutStreamPtr->GetByteLength());
				LOG_INFO("Send packet to client - ") << name << (m_OutStreamPtr->GetBitLength());
			}
			m_ConnectionsMutex.unlock();
		}
		else if (m_Type == MANAGER_TYPE::CLIENT && bClientApproved && bClientConnected)
        {
            PACKET packet = PACKET::DATA;
            m_Socket->Send(&packet, 1);
            uint32_t len = m_OutStreamPtr->GetBitLength();
            m_Socket->Send(&len, sizeof(uint32_t));
			m_Socket->Send(m_OutStreamPtr->GetBufferPtr(), m_OutStreamPtr->GetByteLength());
			LOG_INFO("Send packet to server");
		}
		bContainSendData = false;
		bReadyToWriteFunction = false;
		bReadyToWritePacket = false;
	}
}
void NetworkManager::AcceptConnections()
{
	if (m_Type == MANAGER_TYPE::SERVER)
    {
		while (!bPendingShutdown)
        {
            SocketAddress addr;
            auto client = m_Socket->Accept(addr);
            if (client)
            {
				LOG_INFO("Accepting client");
                for (int wait = 0; wait < m_ConnectionTimeLimit; wait++)
                {
					char buffer[128];
					auto received = client->Receive(buffer, 1);
					if (received > 0)
                    {
                        PACKET packet = (PACKET)buffer[0];
                        if (packet == HELLO)
                        {
                            client->Receive(buffer, sizeof(uint32_t));
                            uint32_t len = *reinterpret_cast<uint32_t *>(&buffer[0]);
							client->Receive(buffer, len);
                            m_InStreamPtr = std::make_unique<InputMemoryBitStream>(buffer, len);
                            HandleHelloPacket(client);
                            break;
                        }
						else LOG_DEBUG("Hello received");
					}
					else LOG_INFO("Thread::Waiting data");
					LOG_DEBUG("Received but not all");
                    sleep(1);
                }
            }
		}
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
	if (bPendingShutdown) return;
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
        LOG_INFO("Start disconnecting");
        auto to_delete_iter = m_ServerConnections->find(name);
        if (to_delete_iter != m_ServerConnections->end())
        {
			PACKET packet = PACKET::REJECT;
			to_delete_iter->second->Send(&packet, 1);
            m_ServerConnections->erase(to_delete_iter);
			LOG_INFO("Disconnecting user ") << name;
        }
	    auto to_delete_info = m_ServerClientsInfo->find(name);
		if (to_delete_info != m_ServerClientsInfo->end())
        {
			m_ServerClientsInfo->erase(to_delete_info);
			LOG_INFO("Deleting user information of ") << name;
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

void NetworkManager::SetManagerInfo(ManagerInfo&& info)
{
	if (bInfoExists) return;
	m_Info = info;
	bInfoExists = true;
}

bool NetworkManager::IsConnected() const
{
	return bClientConnected && bClientApproved;
}

bool NetworkManager::WaitAllDataFromNet(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::SERVER && !clientName.empty())
    {
		//TODO thread safe
	    if (m_ServerConnections->find(clientName) != m_ServerConnections->end()
		    && (m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end()))
        {
		    auto wanted_bytes = m_ServerPacketConditions->at(clientName).want_to_receive;
			auto current_byte = m_ServerPacketConditions->at(clientName).current;
			auto rec_now = wanted_bytes - current_byte;
			auto buffer = new char[rec_now];
            auto received = m_ServerConnections->at(clientName)->Receive(&buffer, rec_now);
			if (received > 0)
            {
                std::memcpy((m_ServerPacketConditions->at(clientName).buffer)+current_byte, buffer, received);
			    current_byte += received;
				m_ServerPacketConditions->at(clientName).current = current_byte;
			}
			delete[] buffer;
			if (current_byte == wanted_bytes)
            {
				return true;
			}
		}
	}
	else if (m_Type == MANAGER_TYPE::CLIENT)
    {
        auto wanted_bytes = m_ClientPacketConditionPtr->want_to_receive;
        auto current_byte = m_ClientPacketConditionPtr->current;
        auto rec_now = wanted_bytes - current_byte;
        auto buffer = new char[rec_now];
        auto received = m_Socket->Receive(&buffer, rec_now);
        if (received > 0)
        {
            std::memcpy(m_ClientPacketConditionPtr->buffer + current_byte, buffer, received);
            current_byte += received;
            m_ClientPacketConditionPtr->current = current_byte;
        }
        delete[] buffer;
        if (current_byte == wanted_bytes)
        {
            return true;
        }
	}
	return false;
}

bool NetworkManager::WaitAllPacket(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::SERVER)
    {
		bool client_exists = m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end();
		if (!client_exists)
        {
			LOG_DEBUG("NetworkManager::WaitAllPacket Client not exists - ") << clientName;
			return false;
		}
		if (!m_ServerPacketConditions->at(clientName).is_len_received)
        {
		    bool len_rec = WaitAllDataFromNet(clientName);
			m_ServerPacketConditions->at(clientName).is_len_received = len_rec;
			if (len_rec)
            {
                uint32_t require_bits = *reinterpret_cast<uint32_t *>(m_ServerPacketConditions->at(clientName).buffer);
                m_ServerPacketConditions->at(clientName).Destroy();
                m_ServerPacketConditions->at(clientName).Init((require_bits+7)>>3, require_bits);
                bool receive_all = WaitAllDataFromNet(clientName);
                if (receive_all) return true;
			}
		}
		else if (m_ServerPacketConditions->at(clientName).is_len_received)
        {
            bool res = WaitAllDataFromNet(clientName);
			if (res) return true;
		}
        else if (!m_ServerPacketConditions->at(clientName).is_initialized)
        {
			m_ServerPacketConditions->at(clientName).Init(sizeof(uint32_t), 0);
			bool res = WaitAllDataFromNet(clientName);
			m_ServerPacketConditions->at(clientName).is_len_received = res;
			if (res)
            {
				uint32_t require_bits = *reinterpret_cast<uint32_t *>(m_ServerPacketConditions->at(clientName).buffer);
				m_ServerPacketConditions->at(clientName).Destroy();
				m_ServerPacketConditions->at(clientName).Init((require_bits+7)>>3, require_bits);
				bool receive_all = WaitAllDataFromNet(clientName);
				if (receive_all) return true;
			}
		}
	}
	else if (m_Type == MANAGER_TYPE::CLIENT)
    {

	}
}

void ManagerInfo::Write(OutputMemoryBitStream& stream)
{
	stream.Write(name);
}

void ManagerInfo::Read(InputMemoryBitStream& stream)
{
	stream.Read(name);
}
