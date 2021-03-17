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

/**
 *  @details Utility structure for non blocking packet receive
 */
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
	m_ServerBindSocket = SocketUtil::CreateTCPSocket(INET);
	if (type == MANAGER_TYPE::SERVER)
	{
		SocketAddress addr(INADDR_ANY, port);
		m_ServerBindSocket->Bind(addr);
		LOG_INFO("Creating Server at port ") << port;
		if (m_ServerBindSocket->Listen() < 0) LOG_FATAL("SERVER CANT LISTEN");
		m_AcceptingThread = std::thread(&NetworkManager::AcceptConnections, this);
		LOG_INFO("Maximum threads supported - ") << std::thread::hardware_concurrency();
		m_ServerConnections = std::make_unique<std::unordered_map<std::string, TCPSocketPtr>>();
        m_ServerClientsInfo = std::make_unique<std::unordered_map<std::string, ManagerInfo>>();
		m_ServerPacketConditions = std::make_unique<std::unordered_map<std::string, ReceivePacketInfo>>();
        m_ClientPacketConditionPtr = std::make_unique<ReceivePacketInfo>();
	}
	else if (type == MANAGER_TYPE::CLIENT)
	{
		m_ClientPacketConditionPtr = std::make_unique<ReceivePacketInfo>();
		LOG_INFO("Client manager init");
	}
}

NetworkManager::~NetworkManager()
{
	Server_Shutdown();
	LOG_INFO("DESTROYING NETWORK MANAGER");
}


/**
 * @details Set tick frequency
 * @param frequency Amount of times tick will be executed in one second
 */
void NetworkManager::SetNetFrequency(float frequency)
{
	m_NetFrequency = frequency;
}

/**
 * @details Set manager type
 * @param mode FREQUENCY or MANUAL
 */
void NetworkManager::SetManagerMode(MANAGER_MODE mode)
{
	m_Mode = mode;
}

MANAGER_MODE NetworkManager::GetManagerMode() const
{
	return m_Mode;
}

/**
 * @attention CLIENT-ONLY
 * @details Establish connect to a server
 * @param address address and port of server
 */
void NetworkManager::Connect(const std::string& address)
{
	if (m_Type == MANAGER_TYPE::CLIENT)
	{
		if (bClientConnected) return;
		if (m_Socket->Connect(*SocketFactory::CreateIPv4FromString(address)) < 0)
		{
			LOG_ERROR("NetworkManager::Connect try address") << address << " error code - " << SocketUtil::GetLastError();
		}
		else bClientConnected = true;

		if (bClientConnected)
		{
			LOG_INFO("Connection established - ") << address;
			auto packet = PACKET::HELLO;
			m_Socket->Send(&packet, 1);
			m_OutStreamPtr = std::make_unique<OutputMemoryBitStream>();
			SendHello();
			LOG_DEBUG("Sending our info to Server");

			char buffer[32];
			for (int i = 0; i < m_ConnectionTimeLimit; i++)
			{
				LOG_DEBUG("Wait answer of server");
				int received = m_Socket->Receive(buffer, 1);
				if (received > 0)
				{
					LOG_DEBUG("Received answer");
                    packet = (PACKET)buffer[0];
					if (packet == HELLO)
					{
						LOG_INFO("Connected and accepted to Server");
						bClientApproved = true;
						return;
					}
					else if (packet == REJECT)
					{
						LOG_INFO("Server rejects you");
						bClientConnected = false;
						return;
					}
				}
				else
				{
					LOG_DEBUG("Wait response seconds - ") << i;
					sleep(1);
				}
			}
		}
	}
	else LOG_WARNING("Connect can only be used in client");
}

/**
 * @details Handle sending and receiving of packets. Should be executed in loop
 * @param deltaTime Time from previous call in seconds
 */
void NetworkManager::Tick(float deltaTime)
{
	Timer timer("NetworkManager::Tick");
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

/**
 * @attention SERVER-ONLY
 * @details Check accepting packet from client on correctness, then accept or rejects client
 * @param socket Established socket to client
 */
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
			if (m_ServerConnections->find(info.name) == m_ServerConnections->end())
            {
                PACKET packet = PACKET::HELLO;
                socket->Send(&packet, 1);
                m_ConnectionsMutex.lock();
                m_ServerConnections->insert(std::make_pair(info.name, socket));
                m_ServerClientsInfo->insert(std::make_pair(info.name, info));
				m_ServerPacketConditions->insert(std::make_pair(info.name, ReceivePacketInfo()));
                LOG_INFO("Client added to clients - ") << info.name;
                m_ConnectionsMutex.unlock();
			}
			else
            {
                SendRejected(socket);
                LOG_WARNING("Client with such name already exits - ") << info.name;
			}
		}
		else
		{
			LOG_WARNING("Client rejected level validation - ") << info.name;
			SendRejected(socket);
		}
	}
}

/**
 * @details Read function id, and function parameters from packet, then executes function
 * @param stream Read from
 */
void NetworkManager::HandleFunctionPacket(InputMemoryBitStream& stream)
{
	std::string function_id;
	stream.Read(function_id);
	RPCManager::Proccess(function_id, stream);
}

/**
 * @attention CLIENT-ONLY
 * @details Send Client info such as name, etc... to server
 */
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

/**
 * @details Main function to receive packets, if receives function executes it. Remember received data from previous call, non-blocking(almost).
 * @param socket Established socket
 * @param name Client names, optional in client (do nothing)
 */
void NetworkManager::HandlePacket(const TCPSocketPtr& socket, const std::string& name)
{
	if (IsInitilizedPacketBuffer(name))
    {
	    ReadIfReceivePacket(name);
		return;
	}
	PACKET packet = PACKET::MAX;
	char buf[1];
	int received = socket->Receive(&buf, 1);
	if (received > 0)
	{
        packet = (PACKET)buf[0];
        LOG_DEBUG("Prepare packet receive - ") << packet;
		if (packet == PACKET::DATA)
		{
			LOG_DEBUG("Wait packet");
            ReadIfReceivePacket(name);
		}
		else if (packet == PACKET::REJECT && m_Type == MANAGER_TYPE::CLIENT)
		{
			bClientConnected = false;
			bClientApproved = false;
			LOG_WARNING("You have been disconnected");
		}
		else if (packet == PACKET::REJECT && m_Type == MANAGER_TYPE::SERVER)
        {
			LOG_INFO("Receiving disconnect information from - ") << name;
			char buffer[512];
			received = socket->Receive(buffer, sizeof(uint32_t));
			if (received > 0)
            {
				uint32_t len = *reinterpret_cast<uint32_t *>(&buffer[0]);
				LOG_DEBUG("Client Name len in bytes - ") << len;
			    received = socket->Receive(buffer, len);
				if (received > 0)
                {
                    InputMemoryBitStream stream(buffer, len << 3);
                    std::string rec_name;
                    stream.Read(rec_name);
                    Server_DisconnectClient(rec_name);
				}//TODO make non blocking
			}
		}
		else LOG_DEBUG("Receive some shit!!!");
	}
	else LOG_DEBUG("Nothing receive!");
}

void NetworkManager::Server_HandleClients()
{
    if (m_ServerConnections->empty()) return;
	m_ConnectionsMutex.lock();
	LOG_INFO(m_ServerConnections->size());
	for (auto& [name, socket] : *m_ServerConnections)
	{
		 LOG_INFO("Handling client now - ") << name;
		 HandlePacket(socket, name);
	}
	for (const auto& name : m_PendingDisconnectClients)
    {
        LOG_INFO("Start disconnecting - ") << name;
        auto to_delete_iter = m_ServerConnections->find(name);
        if (to_delete_iter != m_ServerConnections->end())
        {
            PACKET packet = PACKET::REJECT;
            to_delete_iter->second->Send(&packet, 1);
            m_ServerConnections->erase(to_delete_iter);
            LOG_INFO("Disconnecting user - ") << name;
        }
        bool info_res = m_ServerClientsInfo->erase(name);
        if (info_res) LOG_INFO("Deleting user information of - ") << name;
	}
	m_PendingDisconnectClients.clear();
	m_ConnectionsMutex.unlock();
}

/**
 * @attention MANUAL-MODE
 * @details Replacement of tick in MANUAL mode, but without sending of packets.
 */
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

/**
 * @details If packet ready, send it
 */
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
				LOG_DEBUG("Send packet to client - ") << name << " Packet len in bits - " << (m_OutStreamPtr->GetBitLength());
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
			LOG_DEBUG("Send packet to server, bit len - ") << m_OutStreamPtr->GetBitLength();
		}
		bContainSendData = false;
		bReadyToWriteFunction = false;
		bReadyToWritePacket = false;
	}
}

/**
 * @attention SERVER-ONLY
 * @details Async function to accept clients
 */
void NetworkManager::AcceptConnections()
{
	if (m_Type == MANAGER_TYPE::SERVER)
    {
		while (!bPendingShutdown)
        {
            SocketAddress addr;
            auto client = m_ServerBindSocket->Accept(addr);
			m_Socket = client;
            if (client)
            {
				LOG_INFO("NetworkManager::AcceptConnections - Accepting client");
                for (int wait = 0; wait < m_ConnectionTimeLimit; wait++)
                {
					if (IsInitilizedPacketBuffer())
                    {
						LOG_DEBUG("AcceptConnections initilized");
						if (HandleIfReceiveConnectionPacket(client)) break;
						else continue;
					}
					char buffer[1];
					auto received = client->Receive(buffer, 1);
					if (received > 0)
                    {
						LOG_DEBUG("AcceptConnections hello");
                        PACKET packet = (PACKET)buffer[0];
                        if (packet == HELLO)
                        {
                            if (HandleIfReceiveConnectionPacket(client)) break;
                        }
					}
					else LOG_INFO("Thread::Waiting data - ") << wait << " seconds";
                    sleep(1);
                }
            }
		}
	}
}

/**
 * @details Sets connection time limit in seconds
 * @param newLimit Time in seconds
 */
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

/**
 * @attention NOT USABLE AFTER
 * @details Shutdown server, waiting for accepting thread, and send information about shutdown to connected clients.
 */
void NetworkManager::Server_Shutdown()
{
	if (bPendingShutdown) return;
	if (m_Type == MANAGER_TYPE::SERVER)
    {
		LOG_INFO("Server shutdown started");
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

/**
 * @details Disconnects client from server.
 * @param name Client name to disconnect, if exists
 */
void NetworkManager::Server_DisconnectClient(std::string name)
{
	if (m_Type == MANAGER_TYPE::SERVER)
    {
		m_PendingDisconnectClients.emplace_back(name);

	}
}

/**
 * @details Self disconnect from server.
 */
void NetworkManager::Client_Disconnect()
{
	if (m_Type == MANAGER_TYPE::CLIENT)
    {
        OutputMemoryBitStream stream;
		stream.Write(m_Info.name);

		OutputMemoryBitStream info_stream;
		info_stream.WriteBits(PACKET::REJECT, 8);//Byte len, cause HandlePacket get bytes
		info_stream.Write(stream.GetByteLength());

		m_Socket->Send(info_stream.GetBufferPtr(), info_stream.GetByteLength());
		m_Socket->Send(stream.GetBufferPtr(), stream.GetByteLength());
	}
}

/**
 * @attention Must be explicitly set or server will rejects you
 * @param info Client info
 */
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

/**
 * @details Remembers data partly received packet, and use it in next call.
 * @param clientName Name of client.
 * @return TRUE if packet received without losses.
 */
bool NetworkManager::WaitAllDataFromNet(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::CLIENT || clientName.empty())
    {
        auto wanted_bytes = m_ClientPacketConditionPtr->want_to_receive;
        auto current_byte = m_ClientPacketConditionPtr->current;
        auto rec_now = wanted_bytes - current_byte;
        auto buffer = new char[rec_now];
        auto received = m_Socket->Receive(buffer, rec_now);
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
    else if (m_Type == MANAGER_TYPE::SERVER && !clientName.empty())
    {
		//TODO thread safe
	    if (m_ServerConnections->find(clientName) != m_ServerConnections->end()
		    && (m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end()))
        {
		    auto wanted_bytes = m_ServerPacketConditions->at(clientName).want_to_receive;
			auto current_byte = m_ServerPacketConditions->at(clientName).current;
			auto rec_now = wanted_bytes - current_byte;
			auto buffer = new char[rec_now];
            auto received = m_ServerConnections->at(clientName)->Receive(buffer, rec_now);
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
	return false;
}

/**
 * @details Handles non blocking receiving of packet length and packet itself.
 * @param clientName Name of client.
 * @return TRUE if packet received
 */
bool NetworkManager::WaitAllPacket(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::CLIENT || clientName.empty())
    {
        if (!m_ClientPacketConditionPtr->is_initialized)
        {
            m_ClientPacketConditionPtr->Init(sizeof(uint32_t), sizeof(uint32_t)<<3);
            bool res = WaitAllDataFromNet(clientName);
            m_ClientPacketConditionPtr->is_len_received = res;
            if (res)
            {
                uint32_t require_bits = *reinterpret_cast<uint32_t *>(m_ClientPacketConditionPtr->buffer);
                m_ClientPacketConditionPtr->Destroy();
                m_ClientPacketConditionPtr->Init((require_bits+7)>>3, require_bits);
                bool receive_all = WaitAllDataFromNet(clientName);
                if (receive_all)
                {
                    return true;
                }
            }
        }
        else if (!m_ClientPacketConditionPtr->is_len_received)
        {
            bool len_rec = WaitAllDataFromNet(clientName);
            m_ClientPacketConditionPtr->is_len_received = len_rec;
            if (len_rec)
            {
                uint32_t require_bits = *reinterpret_cast<uint32_t *>(m_ClientPacketConditionPtr->buffer);
                m_ClientPacketConditionPtr->Destroy();
                m_ClientPacketConditionPtr->Init((require_bits+7)>>3, require_bits);
                bool receive_all = WaitAllDataFromNet(clientName);
                if (receive_all)
                {
                    return true;
                }
            }
        }
        else if (m_ClientPacketConditionPtr->is_len_received)
        {
            bool res = WaitAllDataFromNet(clientName);
            if (res)
            {
                return true;
            }
        }
    }
    else if (m_Type == MANAGER_TYPE::SERVER)
    {
		bool client_exists = m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end();
		if (!client_exists)
        {
			LOG_DEBUG("NetworkManager::WaitAllPacket Client not exists - ") << clientName;
			return false;
		}
        if (!m_ServerPacketConditions->at(clientName).is_initialized)
        {
            m_ServerPacketConditions->at(clientName).Init(sizeof(uint32_t), sizeof(uint32_t)<<3);
            bool res = WaitAllDataFromNet(clientName);
            m_ServerPacketConditions->at(clientName).is_len_received = res;
            if (res)
            {
                uint32_t require_bits = *reinterpret_cast<uint32_t *>(m_ServerPacketConditions->at(clientName).buffer);
                m_ServerPacketConditions->at(clientName).Destroy();
                m_ServerPacketConditions->at(clientName).Init((require_bits+7)>>3, require_bits);
                bool receive_all = WaitAllDataFromNet(clientName);
                if (receive_all)
                {
                    return true;
                }
            }
        }
		else if (!m_ServerPacketConditions->at(clientName).is_len_received)
        {
		    bool len_rec = WaitAllDataFromNet(clientName);
			m_ServerPacketConditions->at(clientName).is_len_received = len_rec;
			if (len_rec)
            {
                uint32_t require_bits = *reinterpret_cast<uint32_t *>(m_ServerPacketConditions->at(clientName).buffer);
                m_ServerPacketConditions->at(clientName).Destroy();
                m_ServerPacketConditions->at(clientName).Init((require_bits+7)>>3, require_bits);
                bool receive_all = WaitAllDataFromNet(clientName);
                if (receive_all)
                {
                    return true;
				}
			}
		}
		else if (m_ServerPacketConditions->at(clientName).is_len_received)
        {
            bool res = WaitAllDataFromNet(clientName);
			if (res)
            {
                return true;
			}
		}
	}
	return false;
}

/**
 * @details Get buffer of partly received packet by client name(optional in Client).
 * @param clientName Name of client OPTIONAL.
 * @return nullptr if something going wrong.
 */
char* NetworkManager::GetPacket(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::CLIENT || clientName.empty())
    {
        return m_ClientPacketConditionPtr->buffer;
    }
	else if (m_Type == MANAGER_TYPE::SERVER)
    {
		if (m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end())
        {
            return m_ServerPacketConditions->at(clientName).buffer;
        }
	}
	return nullptr;
}

/**
 * @details Get bits of data packet should consist of.
 * @param clientName Name of client OPTIONAL.
 * @return Number of bits, 0 if wrong.
 */
uint16_t NetworkManager::GetRequiredBitsFrom(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::CLIENT || clientName.empty())
    {
        return m_ClientPacketConditionPtr->required_bits;
    }
    else if (m_Type == MANAGER_TYPE::SERVER)
    {
        if (m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end())
        {
            return m_ServerPacketConditions->at(clientName).required_bits;
        }
    }
	return 0;
}

/**
 * @details If packet received, reinterpret all it data, and executes function if contain.
 * @param clientName Name of client OPTIONAL
 * @return TRUE if receive all packet.
 */
bool NetworkManager::ReadIfReceivePacket(const std::string& clientName)
{
	bool res = WaitAllPacket(clientName);
    if (res)
    {
        char* buffer = GetPacket(clientName);
        auto data_len = GetRequiredBitsFrom(clientName);
        InputMemoryBitStream stream(buffer, data_len);
        while (stream.GetRemainingBitCount() > 0)
        {
            LOG_DEBUG("Reading packet buffer, bit len - ") << data_len;
			PACKET packet = PACKET::MAX;
            stream.ReadBits(&packet, GetRequiredBits<PACKET::MAX>::VALUE);
            if (packet == PACKET::FUNCTION)
            {
                HandleFunctionPacket(stream);
            }
        }
	    DestroyPacketBuffer(clientName);
    }
	return res;
}

bool NetworkManager::IsInitilizedPacketBuffer(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::CLIENT || clientName.empty())
    {
        return m_ClientPacketConditionPtr->IsInit();
    }
	else if (m_Type == MANAGER_TYPE::SERVER)
    {
	    if (m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end())
        {
			return m_ServerPacketConditions->at(clientName).IsInit();
		}
	}
	return false;
}

void NetworkManager::DestroyPacketBuffer(const std::string& clientName)
{
    if (m_Type == MANAGER_TYPE::CLIENT || clientName.empty())
    {
        m_ClientPacketConditionPtr->Destroy();
    }
    else if (m_Type == MANAGER_TYPE::SERVER)
    {
        if (m_ServerPacketConditions->find(clientName) != m_ServerPacketConditions->end())
        {
            m_ServerPacketConditions->at(clientName).Destroy();
        }
    }
}

/**
 * @attention SERVER-ONLY
 * @details Wait Packet about client info, then call NetworkManager::HandleHelloPacket.
 * @param socket Client socket.
 * @return TRUE if receive all.
 */
bool NetworkManager::HandleIfReceiveConnectionPacket(const TCPSocketPtr& socket)
{
	if (m_Type == MANAGER_TYPE::SERVER)
    {
        bool res = WaitAllPacket();
        if (res)
        {
            m_InStreamPtr = std::make_unique<InputMemoryBitStream>(GetPacket(), GetRequiredBitsFrom());
            HandleHelloPacket(socket);
            DestroyPacketBuffer();
        }
		return res;
	}
	return false;
}

void ManagerInfo::Write(OutputMemoryBitStream& stream)
{
	stream.Write(name);
}

void ManagerInfo::Read(InputMemoryBitStream& stream)
{
	stream.Read(name);
}
