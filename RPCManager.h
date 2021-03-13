//
// Created by nicola on 14/02/2021.
//

#pragma once

#include <string>
#include <unordered_map>

/** @brief Empty macro for rpc parser */
#define RPCfunction()

typedef void (*RPCWrapFunction)(class InputMemoryBitStream&);

class RPCManager
{
public:
    RPCManager() = delete;
    virtual ~RPCManager() = delete;

    inline static void RegisterFunction(RPCWrapFunction func, const std::string& id)
    {
        if (m_WrappedFunctions.find(id) != m_WrappedFunctions.end())
        {
            LOG_FATAL("Function Id exists yet");
			LOG_FATAL("EXITING...");
            std::exit(-1);
        }
        else
        {
            m_WrappedFunctions[id] = func;
            LOG_DEBUG("Function added to rpc manager ") << id;
        }
    }

    inline static void Proccess(const std::string& id, InputMemoryBitStream& inStream)
    {
        if (m_WrappedFunctions.find(id) != m_WrappedFunctions.end())
        {
            LOG_DEBUG("Execute received function ") << id;
            m_WrappedFunctions.at(id)(inStream);
        }
        else
        {
            LOG_DEBUG("RPCManager::Process Function doesnt exists") << id;
        }
    }

protected:
    inline static std::unordered_map<std::string, RPCWrapFunction> m_WrappedFunctions{};
};
