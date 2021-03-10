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
			break;
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
	auto iter = string.cbegin();
	for (; iter != string.cend(); iter++)
    {
		if (*iter != ' ') break;
	}
	for (auto scope = iter; scope != string.cend(); scope++)
	{
		if (*scope == '(')
		{
			name = std::move(std::string(iter, scope));
			iter = scope;
			break;
		}
	}
	for (auto scope = iter; scope != string.cend(); scope++)
    {
        if (*scope == ')')
        {
			ParseArguments(std::string(iter, scope+1));
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
			iter = right+1;
		}
	}
	ParseArg(std::string(iter, str.cend()-1));
}

void FunctionParser::ParseArg(const std::string& str)
{
    for (auto iter = str.crbegin(); iter != str.crend(); iter++)
    {
		if (*iter == ' ')
        {
			m_ArgsTypes.emplace_back(str.cbegin(), iter.base());
            m_Args.emplace_back(iter.base(), str.cend());
			break;
		}
	}
}

void FunctionParser::GenerateReadDeclaration()
{
    std::ostringstream stream;
	stream << "void read_" << name << "(InputMemoryBitStream& stream);";
	m_ReadDeclarations = stream.str();
}

void FunctionParser::GenerateWriteDeclaration()
{
	std::ostringstream stream;
	stream << "void write_" << name << "(class NetworkManager& manager,";
    for (auto index = 0; index < m_Args.size() || index < m_ArgsTypes.size(); index++)
    {
		stream << m_ArgsTypes[index] << " " << m_Args[index];
		if (index != m_ArgsTypes.size()-1)
        {
			stream << ",";
		}
	}
	stream << ");";
	m_WriteDeclarations = stream.str();
}

void FunctionParser::GenerateReadDefinition()
{
    std::ostringstream stream;
    stream << std::string(m_ReadDeclarations.cbegin(), m_ReadDeclarations.cend()-1) << "{";

    for (auto index = 0; index < m_Args.size() || index < m_ArgsTypes.size(); index++)
    {
        stream << RemoveModifiers(m_ArgsTypes[index]) << " " << m_Args[index] << "{};";
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
	m_ReadDefinitions = stream.str();
}

void FunctionParser::GenerateWriteDefinition()
{
    std::ostringstream stream;
    stream << std::string(m_WriteDeclarations.cbegin(), m_WriteDeclarations.cend()-1) << "{";
	stream << "manager.AddDataToPacket(\"" << name << "\");";
	for (const auto & m_Arg : m_Args)
    {
		stream << "manager.AddDataToPacket(" << m_Arg << ");\n";
	}

    stream << "manager.EndFunction();}";
	m_WriteDefinitions = stream.str();
}

void FunctionParser::GenerateRegistrations()
{
    std::ostringstream stream;
	stream << "RPCManager::RegisterFunction(read_" << name << "," << "\"" << name << "\"" << ");";
	m_Registrations = stream.str();
}

/** paste argument type here */
std::string&& FunctionParser::RemoveConst(std::string&& argument)
{
	auto begin = argument.find("const");
	if (begin != std::string::npos)
    {
		argument.erase(begin, begin+5);
	}
	return std::move(argument);
}

std::string&& FunctionParser::RemoveRef(std::string&& argument)
{
	auto found = argument.find('&');
	while (found != std::string::npos)
    {
		argument.erase(found);
		found = argument.find('&');
	}
	return std::move(argument);
}

std::string FunctionParser::RemoveModifiers(std::string str)
{
	return RemoveConst(RemoveRef(std::move(str)));
}
