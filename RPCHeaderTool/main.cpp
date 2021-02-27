//
// Created by nicola on 26/02/2021.

#include <fstream>
#include <iostream>

using std::string;

void GenerateHeader(const string& pathToProjectSource, const string& whereToGenerate);
void GenerateCpp(const string& pathToProjectSource, const string& whereToGenerate);

// first param - path to files for parsing
// second param - path to output folder
int main(int arg, char** argc)
{
	if (arg != 3)
	{
		return -1;
	}
	string path_to_source = static_cast<string>(argc[0]);
	string path_to_generate_folder = static_cast<string>(argc[1]);
	GenerateHeader(path_to_source, path_to_generate_folder);
	GenerateCpp(path_to_source, path_to_generate_folder);
	return 0;
}

void GenerateHeader(const string& pathToProjectSource, const string& whereToGenerate)
{

}

void GenerateCpp(const string& pathToProjectSource, const string& whereToGenerate)
{

}
