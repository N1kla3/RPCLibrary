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

	[[nodiscard]] std::string GetReadDeclarations() const;
	[[nodiscard]] std::string GetWriteDeclarations() const;
	[[nodiscard]] std::string GetReadDefinitions() const;
	[[nodiscard]] std::string GetWriteDefinitions() const;
	[[nodiscard]] std::string GetRegistrations() const;

private:
	void ParseDefinition(const std::string& string);
	void ParseArguments(const std::string& str);
	void ParseArg(const std::string& str);

	// Generation utility functions
	void GenerateReadDeclaration() const;
	void GenerateWriteDeclaration() const;
	void GenerateReadDefinition() const;
	void GenerateWriteDefinition() const;
	void GenerateRegistrations() const;

	std::string name;
	std::vector<std::string> m_Args{};
	std::vector<std::string> m_ArgsTypes{};

	std::string m_ReadDeclarations;
	std::string m_WriteDeclarations;
	std::string m_ReadDefinitions;
	std::string m_WriteDefinitions;

	std::string m_Registrations;
};


