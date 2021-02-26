//
// Created by nicola on 26/02/2021.

#include <fstream>

using std::string;

int main(int arg, char** argc)
{
	if (arg != 2)
	{
		return -1;
	}
	string path_to_folder = static_cast<string>(*argc);
	auto header_path = path_to_folder.append("/generated.h");
	std::ofstream header(header_path);
	header.close();
	auto cpp_path = path_to_folder.append("/generated.cpp");
	std::ofstream cpp(cpp_path);
	cpp.close();
	return 0;
}
