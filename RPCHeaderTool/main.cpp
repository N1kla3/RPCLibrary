//
// Created by nicola on 26/02/2021.

#include <fstream>
#include <iostream>
#include <filesystem>

using std::string;

void GenerateHeader(const string& pathToProjectSource, const string& whereToGenerate);
void GenerateCpp(const string& pathToProjectSource, const string& whereToGenerate);
void parseToHeader(const string& inFile, const string& pathTogeneratedFile);
void parseToCpp(const string& inFile, const string& pathTogeneratedFile);

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
		header << "#include\"RPCManager\"\n";
		header << "#include\"NetworkManager\"\n";
		header.close();
		for (const auto& file : std::filesystem::directory_iterator(pathToProjectSource))
        {
            std::string path_file = file.path().string();
			if (*(path_file.cend()-1) == 'h')
            {
				std::cout << path_file;
			}
		}
	}
	else std::cout << "cant open file";
}

void GenerateCpp(const string& pathToProjectSource, const string& whereToGenerate)
{

}
