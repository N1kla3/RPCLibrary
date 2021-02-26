//
// Created by nicola on 14/02/2021.
//

#pragma once

#include <string>
#include <unordered_map>

/** @brief Empty macro for rpc parser */
#define RPC(id)

typedef void (*RPCWrapFunction)(class InputMemoryBitStream&);

class RPCManager
{
public:
    RPCManager() = delete;
    virtual ~RPCManager() = delete;

    inline static void RegisterFunction(RPCWrapFunction func, uint32_t id)
    {
        if (m_WrappedFunctions.at(id) != nullptr)
        {
            LOG_FATAL(id exists);
            std::exit(-1);
        }
        else
        {
            m_WrappedFunctions[id] = func;
            LOG_DEBUG(function added to rpc manager);
        }
    }

    inline static void Proccess(uint32_t id, InputMemoryBitStream& inStream)
    {
        if (m_WrappedFunctions.find(id) != m_WrappedFunctions.end())
        {
            m_WrappedFunctions.at(id)(inStream);
            LOG_DEBUG(execute received function);
        }
        else
        {
            LOG_FATAL(function doesnt exists);
        }
    }

protected:
    inline static std::unordered_map<uint32_t, RPCWrapFunction> m_WrappedFunctions{};
};
