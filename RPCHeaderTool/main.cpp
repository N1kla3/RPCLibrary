//
// Created by nicola on 26/02/2021.

#include "FunctionParser.h"
#include <filesystem>
#include <fstream>
#include <iostream>

using std::string;

void GenerateHeader(const string& pathToProjectSource, const string& whereToGenerate);
void parseToHeader(const string& inFile, const string& headerPath, const string& cppPath);

std::string generations{};

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
	return 0;
}

void GenerateHeader(const string& pathToProjectSource, const string& whereToGenerate)
{
	auto header_path = whereToGenerate + "/rpc.generated.h";
	auto cpp_path = whereToGenerate + "/rpc.generated.cpp";

	std::ofstream header(header_path);
	if (header.is_open())
	{
		header << "//Generated file !!!\n";
		header << "#pragma once\n";
		header << "void InitRPC();";
		header.close();
	}
	else std::cout << "cant open file\n";

	std::ofstream cpp(cpp_path);
	if (cpp.is_open())
	{
		cpp << "#include\"rpc.generated.h\"\n";
		cpp << "#include\"RPCManager.h\"\n";
		cpp << "#include\"NetworkManager.h\"\n";
		cpp.close();
	}
	else std::cout << "cant open file\n";

    for (const auto& file : std::filesystem::directory_iterator(pathToProjectSource))
    {
		std::ostringstream includes;
        std::string file_name = file.path().filename().string();
        if (*(file_name.cend() - 1) == 'h')
        {
			includes << "#include" << "\"" << "../" << file_name << "\"\n";
        }
		cpp.open(cpp_path, std::ios_base::app);
		if (cpp.is_open())
        {
			cpp << includes.str();
			cpp.close();
		}
    }
	for (const auto& file : std::filesystem::directory_iterator(pathToProjectSource))
	{
		std::string path_file = file.path().string();
		if (*(path_file.cend() - 1) == 'h')
		{
			parseToHeader(path_file, header_path, cpp_path);
		}
	}
    cpp.open(cpp_path, std::ios_base::app);
	if (cpp.is_open())
    {
		cpp << "void InitRPC(){\n";
		cpp << generations;
		cpp << "}\n";
		cpp.close();
	}
}

void parseToHeader(const string& inFile, const string& headerPath, const string& cppPath)
{
	std::ifstream header(inFile);
	if (header.is_open())
    {
		string str;
		while (std::getline(header, str))
        {
            std::istringstream string_line(str);
			string res;
			string_line >> res;
			if (res == "RPCfunction()")
            {
				FunctionParser parser;
                std::getline(header, str);
				parser.ParseDeclaration(str);

                std::ofstream gen_header(headerPath, std::ios_base::app);
                if (gen_header.is_open())
                {
                    gen_header << parser.GetReadDeclarations();
                    gen_header << parser.GetWriteDeclarations();
                    gen_header.close();
                }

                std::ofstream gen_cpp(cppPath, std::ios_base::app);
                if (gen_cpp.is_open())
                {
                    gen_cpp << parser.GetReadDefinitions();
                    gen_cpp << parser.GetWriteDefinitions();

                    generations.append(parser.GetRegistrations());
                }
			}
		}
        header.close();
    }
}

