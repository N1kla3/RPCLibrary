cmake_minimum_required(VERSION 3.17)
project(RPCHeaderTool)
set(CMAKE_CXX_STANDARD 20)

add_executable(RPCHeaderTool main.cpp FunctionParser.cpp FunctionParser.h)