//
// Created by kolya on 3/2/21.
//

#include "FunctionParser.h"

bool FunctionParser::ParseDeclaration(const std::string& line)
{
	for (auto iter = line.cbegin(); iter != line.cend(); iter++)
    {
        if (*iter == ' ')
        {
			ParseDefinition(std::string(iter, line.cend()));
		}
	}
	return false;
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

}

std::string FunctionParser::GenerateReadDeclaration() const
{
	return std::string();
}

std::string FunctionParser::GenerateWriteDeclaration() const
{
	return std::string();
}

std::string FunctionParser::GenerateReadDefinition() const
{
	return std::string();
}

std::string FunctionParser::GenerateWriteDefinition() const
{
	return std::string();
}

std::string FunctionParser::GenerateRegistrations() const
{
	return std::string();
}
