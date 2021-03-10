//
// Created by nicola on 22/02/2021.
//

#pragma once

#include <atomic>
#include <memory>
#include <thread>

#include "SocketUtil.h"
#include "Stream.h"

struct ManagerInfo
{
    std::string name;

    void Write(class OutputMemoryBitStream& stream);
    void Read(class InputMemoryBitStream& stream);
	//TODO fill it in manager
};

enum SECURITY_LEVEL
{
	LOW,
	COMMON,
	HIGH
};

enum PACKET
{
    HELLO,
    REJECT,
    DATA,
    FUNCTION,
    MAX
};

enum class MANAGER_TYPE
{
    SERVER,
    CLIENT
};

enum class MANAGER_MODE
{
    MANUAL,
    FREQUENCY
};
/**
 * @brief class for RPC server and client manipulations
 */
class NetworkManager
{
public:
    explicit NetworkManager(MANAGER_TYPE type, int port = 22222);

    virtual ~NetworkManager();

    template<typename T>
    void AddDataToPacket(T value)
    {
        if (!bReadyToWritePacket)
        {
		    bReadyToWritePacket = true;
            m_OutStreamPtr = std::make_unique<OutputMemoryBitStream>();
		}
		if (!bReadyToWriteFunction)
        {
            m_OutStreamPtr->WriteBits(PACKET::FUNCTION, GetRequiredBits<PACKET::MAX>::VALUE);
			bReadyToWriteFunction = true;
		}
		if (bReadyToWritePacket && bReadyToWriteFunction)
        {
			m_OutStreamPtr->Write(value);
			LOG_INFO(writing value to packet);
		}
    }

	void EndFunction();

    void HandlePacket(const TCPSocketPtr& socket);

    void HandleHelloPacket(const TCPSocketPtr& socket);

    void HandleFunctionPacket(InputMemoryBitStream& stream);

    void SendHello();

    void SendRejected(const TCPSocketPtr& socket);

	void SendPacket();

    /** @brief Check received data per second */
    void SetNetFrequency(float frequency);

    void SetManagerMode(MANAGER_MODE mode);

    void SetSecurityLevel(SECURITY_LEVEL level) noexcept {m_Level = level;};

	inline void SetConnectionTimeLimit(int newLimit);

	void SetManagerInfo(ManagerInfo&& info);

    [[nodiscard]] MANAGER_MODE GetManagerMode() const;

    [[nodiscard]] MANAGER_TYPE GetManagerType() const noexcept;

	[[nodiscard]] inline int GetConnectionTimeLimit() const;

	[[nodiscard]] bool IsConnected() const;

	void Connect(const std::string& address, int port);

    /** @brief Should be called in while, do nothing if MANUAL mode enabled */
    void Tick(float deltaTime);

    /** @brief In manual mode, executes all received functions */
    void ReceiveData();

	/** @brief SERVER-ONLY, Async function to accept clients, */
	void AcceptConnections();

	/** SERVER-ONLY */
	void Server_Shutdown();

	/** SERVER-ONLY */
	void Server_DisconnectClient(std::string name);

	/** CLIENT-ONLY */
	void Client_Disconnect();

protected:

	// Security functions
	[[nodiscard]] virtual bool ValidateLowLevel(const ManagerInfo& info) const {return !info.name.empty();};
	[[nodiscard]] virtual bool ValidateCommonLevel(const ManagerInfo& info) const {return true;};
	[[nodiscard]] virtual bool ValidateHighLevel(const ManagerInfo& info) const {return true;};

	virtual void Server_HandleClients();

    int bContainSendData:1 = 0;

    int bClientConnected:1 = 0;

    int bClientApproved:1 = 0;

	int bReadyToWriteFunction:1 = 0;

    int bReadyToWritePacket:1 = 0;

	int bInfoExists:1 = 0;

	std::atomic<bool> bPendingShutdown = false;

	float m_PreviousDelta = 0.f;

    float m_NetFrequency = 1.f;

    MANAGER_MODE m_Mode = MANAGER_MODE::FREQUENCY;

    SECURITY_LEVEL m_Level = LOW;

    std::unique_ptr<class InputMemoryBitStream> m_InStreamPtr;

    std::unique_ptr<class OutputMemoryBitStream> m_OutStreamPtr;

    TCPSocketPtr m_Socket;

    ManagerInfo m_Info;

private:
	int m_Port;

	// User DATA
	std::unique_ptr<std::unordered_map<std::string, TCPSocketPtr>> m_ServerConnections;
	std::unique_ptr<std::unordered_map<std::string, ManagerInfo>> m_ServerClientsInfo;

	MANAGER_TYPE m_Type;

	std::mutex m_ConnectionsMutex;
	std::thread m_AcceptingThread;

	int m_ConnectionTimeLimit = 5;
};
