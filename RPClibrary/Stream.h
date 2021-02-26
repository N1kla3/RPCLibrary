//
// Created by nicola on 13/02/2021.
//

#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

inline uint32_t ConvertToFixed(float inNumber, float inMin, float inPrecision)
{
    return static_cast<int>((inNumber - inMin) / inPrecision);
}

inline float ConvertFromFixed(uint32_t inNumber, float inMin, float inPrecision)
{
    return static_cast<float>(inNumber) * inPrecision + inMin;
}

namespace
{
    template<typename T>
    concept primitive = std::is_arithmetic<T>::value || std::is_enum<T>::value;
}

class OutputMemoryBitStream
{

public:
    OutputMemoryBitStream() : m_BitHead(0), m_Buffer(nullptr) { ReallocBuffer(1500 * 8); }

    ~OutputMemoryBitStream() { std::free(m_Buffer); }

    void WriteBits(uint8_t inData, uint32_t inBitCount);

    void WriteBits(const void* inData, uint32_t inBitCount);

    [[nodiscard]] const char* GetBufferPtr() const { return m_Buffer; }

    [[nodiscard]] uint32_t GetBitLength() const { return m_BitHead; }

    [[nodiscard]] uint32_t GetByteLength() const { return (m_BitHead + 7) >> 3; }

    void WriteBytes(const void* inData, uint32_t inByteCount) { WriteBits(inData, inByteCount << 3); }

    template<typename T>
    requires primitive<T>
    void Write(T inData, uint32_t inBitCount = sizeof(T) * 8)
    {
        WriteBits(&inData, inBitCount);
    }

    template<>
    void Write<bool>(bool inData, uint32_t inBitCount)
    {
        WriteBits(&inData, 1);
    }

    void Write(const std::string& inString)
    {
        uint32_t elementCount = static_cast<uint32_t>(inString.size());
        Write(elementCount);
        for (const auto& element : inString) { Write(element); }
    }

    template<typename tKey, typename tValue>
    requires primitive<tKey>&& primitive<tValue>
    void Write(const std::unordered_map<tKey, tValue>& map)
    {
        Write(map.size());
        for (auto [key, value] : map)
        {
            Write(key);
            Write(value);
        }
    }

    template<typename T>
    requires primitive<T>
    void Write(const std::vector<T>& vec)
    {
        Write(vec.size());
        for (auto el : vec)
        {
            Write(el);
        }
    }

protected:
    void ReallocBuffer(uint32_t inNewBitCapacity);

    char* m_Buffer;
    uint32_t m_BitHead;
    uint32_t m_BitCapacity;
};

class InputMemoryBitStream
{

public:
    InputMemoryBitStream(char* inBuffer, uint32_t inBitCount)
        : m_Buffer(inBuffer), m_BitCapacity(inBitCount), m_BitHead(0), m_IsBufferOwner(false)
    {}

    InputMemoryBitStream(const InputMemoryBitStream& inOther)
        : m_BitCapacity(inOther.m_BitCapacity), m_BitHead(inOther.m_BitHead), m_IsBufferOwner(true)
    {
        int byteCount = m_BitCapacity / 8;
        m_Buffer = static_cast<char*>(malloc(byteCount));
        std::memcpy(m_Buffer, inOther.m_Buffer, byteCount);
    }

    ~InputMemoryBitStream()
    {
        if (m_IsBufferOwner) { free(m_Buffer); }
    }

    [[nodiscard]] const char* GetBufferPtr() const { return m_Buffer; }

    [[nodiscard]] uint32_t GetRemainingBitCount() const { return m_BitCapacity - m_BitHead; }

    void ReadBits(uint8_t& outData, uint32_t inBitCount);

    void ReadBits(void* outData, uint32_t inBitCount);

    void ReadBytes(void* outData, uint32_t inByteCount) { ReadBits(outData, inByteCount << 3); }

    template<typename T>
    requires primitive<T>
    void Read(T& inData, uint32_t inBitCount = sizeof(T) * 8)
    {
        ReadBits(&inData, inBitCount);
    }

    template<>
    void Read<bool>(bool& inData, uint32_t inBitCount)
    {
        ReadBits(&inData, 1);
    }

    void ResetToCapacity(uint32_t inByteCapacity)
    {
        m_BitCapacity = inByteCapacity << 3;
        m_BitHead = 0;
    }

    void Read(std::string& inString)
    {
        uint32_t elementCount;
        Read(elementCount);
        inString.resize(elementCount);
        for (auto& element : inString) { Read(element); }
    }

    template<typename tKey, typename tValue>
    requires primitive<tKey>&& primitive<tValue>
    void Read(std::unordered_map<tKey, tValue>& map)
    {
        size_t size;
        Read(size);
        map.clear();
        for (auto i = 0; i < size; i++)
        {
            tKey key;
            tValue value;
            Read<tKey>(key);
            Read<tValue>(value);
            map[key] = value;
        }
    }

    template<typename T>
    requires primitive<T>
    void Read(std::vector<T>& vec)
    {
        size_t size;
        Read(size);
        vec.resize(size);
        for (auto i = 0; i < size; i++)
        {
            T value;
            Read(value);
            vec[i] = value;
        }
    }

protected:
    char* m_Buffer;
    uint32_t m_BitHead;
    uint32_t m_BitCapacity;
    bool m_IsBufferOwner;
};
