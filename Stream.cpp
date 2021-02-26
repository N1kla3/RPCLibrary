//
// Created by nicola on 13/02/2021.
//
#include "Stream.h"

void OutputMemoryBitStream::WriteBits(uint8_t inData, uint32_t inBitCount)
{
    uint32_t nextBitHead = m_BitHead + static_cast< uint32_t >( inBitCount );

    if (nextBitHead > m_BitCapacity) {
        ReallocBuffer(std::max(m_BitCapacity * 2, nextBitHead));
    }

    uint32_t byteOffset = m_BitHead >> 3;
    uint32_t bitOffset = m_BitHead & 0x7;

    uint8_t currentMask = ~(0xff << bitOffset);
    m_Buffer[byteOffset] = (m_Buffer[byteOffset] & currentMask) | (inData << bitOffset);

    uint32_t bitsFreeThisByte = 8 - bitOffset;

    if (bitsFreeThisByte < inBitCount) {
        m_Buffer[byteOffset + 1] = inData >> bitsFreeThisByte;
    }

    m_BitHead = nextBitHead;
}

void OutputMemoryBitStream::WriteBits(const void* inData, uint32_t inBitCount)
{
    const char *srcByte = static_cast<const char *>( inData );
    while (inBitCount > 8) {
        WriteBits(*srcByte, 8);
        ++srcByte;
        inBitCount -= 8;
    }
    if (inBitCount > 0) {
        WriteBits(*srcByte, inBitCount);
    }
}

void OutputMemoryBitStream::ReallocBuffer(uint32_t inNewBitLength)
{
    if (m_Buffer == nullptr) {
        m_Buffer = static_cast<char *>( std::malloc(inNewBitLength >> 3));
        memset(m_Buffer, 0, inNewBitLength >> 3);
    } else {
        char *tempBuffer = static_cast<char *>( std::malloc(inNewBitLength >> 3));
        memset(tempBuffer, 0, inNewBitLength >> 3);
        memcpy(tempBuffer, m_Buffer, m_BitCapacity >> 3);
        std::free(m_Buffer);
        m_Buffer = tempBuffer;
    }

    m_BitCapacity = inNewBitLength;
}

void InputMemoryBitStream::ReadBits(uint8_t& outData, uint32_t inBitCount)
{
    uint32_t byteOffset = m_BitHead >> 3;
    uint32_t bitOffset = m_BitHead & 0x7;

    outData = static_cast< uint8_t >( m_Buffer[byteOffset] ) >> bitOffset;

    uint32_t bitsFreeThisByte = 8 - bitOffset;
    if (bitsFreeThisByte < inBitCount) {
        outData |= static_cast< uint8_t >( m_Buffer[byteOffset + 1] ) << bitsFreeThisByte;
    }

    outData &= (~(0x00ff << inBitCount));

    m_BitHead += inBitCount;
}

void InputMemoryBitStream::ReadBits(void* outData, uint32_t inBitCount)
{
    uint8_t *destByte = reinterpret_cast< uint8_t * >( outData );
    while (inBitCount > 8) {
        ReadBits(*destByte, 8);
        ++destByte;
        inBitCount -= 8;
    }
    if (inBitCount > 0) {
        ReadBits(*destByte, inBitCount);
    }
}