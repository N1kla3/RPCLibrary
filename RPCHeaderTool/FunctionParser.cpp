//
// Created by kolya on 3/2/21.
//

#include "FunctionParser.h"
#include <sstream>

bool FunctionParser::ParseDeclaration(const std::string& line)
{
	if (line.empty()) return false;
	for (auto iter = line.cbegin(); iter != line.cend(); iter++)
    {
        if (*iter == ' ')
        {
			ParseDefinition(std::string(iter, line.cend()));
		}
	}
	GenerateReadDeclaration();
	GenerateReadDefinition();
	GenerateWriteDeclaration();
	GenerateWriteDefinition();
	GenerateRegistrations();
	return true;
}

std::string FunctionParser::GetReadDeclarations() const
{
    return m_ReadDeclarations;
}

std::string FunctionParser::GetWriteDeclarations() const
{
    return m_WriteDeclarations;
}

std::string FunctionParser::GetReadDefinitions() const
{
    return m_ReadDefinitions;
}

std::string FunctionParser::GetWriteDefinitions() const
{
    return m_WriteDefinitions;
}

std::string FunctionParser::GetRegistrations() const
{
    return m_Registrations;
}

void FunctionParser::ParseDefinition(const std::string& string)
{
	// TODO what about reutrn value
	auto iter = string.cbegin();
	for (; iter != string.cend() || *iter != ' '; iter++);
	for (auto scope = iter; scope != string.cend(); scope++)
	{
		if (*scope == '(')
		{
			name = std::move(std::string(iter, scope));
			iter = scope;
			break;
		}
	}
	for (auto scope = iter; iter != string.cend(); scope++)
    {
        if (*scope == ')')
        {
			ParseArguments(std::string(iter, scope));
		}
	}
}

void FunctionParser::ParseArguments(const std::string& str)
{
    if (str.size() == 1) return;
	auto iter = str.cbegin()+1;
	for (auto right = iter; right != str.cend(); right++)
    {
		if (*right == ',')
        {
			ParseArg(std::string(iter, right));
			iter = right + 1;
		}
	}
	ParseArg(std::string(iter, str.cend()));
}

void FunctionParser::ParseArg(const std::string& str)
{
    for (auto iter = str.crbegin(); iter != str.crend(); iter++)
    {
		if (*iter == ' ')
        {
			//TODO need to think about it
			m_ArgsTypes.emplace_back(str.cbegin(), iter.base());
            m_Args.emplace_back(iter.base(), str.cend());
		}
	}
}

void FunctionParser::GenerateReadDeclaration() const
{
    std::ostringstream stream(m_ReadDeclarations);
	stream << "void read_" << name << "(InputMemoryBitStream stream);";
}

void FunctionParser::GenerateWriteDeclaration() const
{
	std::ostringstream stream(m_WriteDeclarations);
	stream << "void write_" << name << "(NetworkManager manager,";
    for (auto index = 0; index < m_Args.size() || index < m_ArgsTypes.size(); index++)
    {
		stream << m_ArgsTypes[index] << " " << m_Args[index];
		if (index != m_ArgsTypes.size()-1)
        {
			stream << ",";
		}
	}
	stream << ");";
}

void FunctionParser::GenerateReadDefinition() const
{
    std::ostringstream stream(m_ReadDeclarations);
    stream << std::string(m_ReadDeclarations.cbegin(), m_ReadDeclarations.cend()-1) << "{";

    for (auto index = 0; index < m_Args.size() || index < m_ArgsTypes.size(); index++)
    {
        stream << m_ArgsTypes[index] << " " << m_Args[index] << "{};";
        stream << "stream.Read(" << m_Args[index] << ");\n";
    }
	stream << name << "(";
	for (auto iter = m_Args.cbegin(); iter != m_Args.cend(); iter++)
    {
		stream << *iter;
		if (iter != m_Args.cend()-1)
        {
		    stream << ",";
		}
	}
	stream << ");}";
}

void FunctionParser::GenerateWriteDefinition() const
{
    std::ostringstream stream(m_WriteDeclarations);
    stream << std::string(m_WriteDeclarations.cbegin(), m_WriteDeclarations.cend()-1) << "{";
	for (const auto & m_Arg : m_Args)
    {
		stream << "manager.AddDataToPacket(" << m_Arg << ")\n";
	}
	stream << name << "(";
    for (auto iter = m_Args.cbegin(); iter != m_Args.cend(); iter++)
    {
        stream << *iter;
        if (iter != m_Args.cend()-1)
        {
            stream << ",";
        }
    }
    stream << ");}";
}

void FunctionParser::GenerateRegistrations() const
{
    std::ostringstream stream(m_Registrations);
	stream << "RPCManager::RegisterFunction(read_" << name << "," << "\"" << name << "\"" << ");";
}
