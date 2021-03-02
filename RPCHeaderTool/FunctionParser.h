//
// Created by kolya on 3/2/21.
//
#pragma once

#include <string>
#include <vector>

class FunctionParser
{
public:
	FunctionParser() = default;
	bool ParseDeclaration(const std::string& line);

	std::string GetReadDeclarations() const;
	std::string GetWriteDeclarations() const;
	std::string GetReadDefinitions() const;
	std::string GetWriteDefinitions() const;
	std::string GetRegistrations() const;

private:
	void ParseDefinition();

	std::string name;
	std::vector<std::string> m_Args{};
	std::vector<std::string> m_ArgsTypes{};

	std::string m_ReadDeclarations;
	std::string m_WriteDeclarations;
	std::string m_ReadDefinitions;
	std::string m_WriteDefinitions;

	std::string m_registrations;
};


