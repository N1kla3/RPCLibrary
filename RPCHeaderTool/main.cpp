//
// Created by nicola on 26/02/2021.

#include <filesystem>
#include <fstream>
#include <iostream>

using std::string;

void GenerateHeader(const string& pathToProjectSource, const string& whereToGenerate);
void parseToHeader(const string& inFile, const string& pathToGeneratedFile);
void parseToCpp(const string& inFile, const string& pathToGeneratedFile);

// first param - path to files for parsing
// second param - path to output folder
int main(int arg, char** argc)
{
	if (arg != 3)
	{
		return -1;
	}
	string path_to_source = static_cast<string>(argc[1]);
	string path_to_generate_folder = static_cast<string>(argc[2]);
	GenerateHeader(path_to_source, path_to_generate_folder);
	GenerateCpp(path_to_source, path_to_generate_folder);
	return 0;
}

void GenerateHeader(const string& pathToProjectSource, const string& whereToGenerate)
{
	auto header_path = whereToGenerate + "/gen.network.h";
	auto cpp_path = whereToGenerate + "/gen.network.cpp";

	std::ofstream header(header_path);
	if (header.is_open())
	{
		header << "//Generated file !!!\n";
		header << "#pragma once\n";
		header.close();
	}
	else std::cout << "cant open file\n";

	std::ofstream cpp(cpp_path);
	if (cpp.is_open())
	{
		cpp << "#include\"gen.network.h\"\n";
		cpp << "#include\"RPCManager\"\n";
		cpp << "#include\"NetworkManager\"\n";
		cpp.close();
	}
	else std::cout << "cant open file\n";

	for (const auto& file : std::filesystem::directory_iterator(pathToProjectSource))
	{
		std::string path_file = file.path().string();
		if (*(path_file.cend() - 1) == 'h')
		{
			parseToHeader(path_file, header_path);
			parseToCpp(path_file, cpp_path);
		}
	}
}

void parseToHeader(const string& inFile, const string& pathToGeneratedFile)
{
	std::ifstream header(inFile);
	if (header.is_open())
    {
		header.close();
	}
}

void parseToCpp(const string& inFile, const string& pathToGeneratedFile)
{
}
