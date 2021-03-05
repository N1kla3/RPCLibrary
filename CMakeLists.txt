cmake_minimum_required(VERSION 3.17)
project(RPClibrary)
set(CMAKE_CXX_STANDARD 20)

SET(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS log log_setup REQUIRED)

include_directories(${Boost_INCLUDE_DIR})
add_subdirectory(RPCHeaderTool)


set(SOURCE
        RPC.cpp
        Stream.cpp
        Stream.h
        RPCManager.cpp
        RPCManager.h
        Socket.cpp
        Socket.h
        SocketFactory.cpp
        SocketFactory.h
        TCPSocket.cpp
        TCPSocket.h
        SocketUtil.cpp
        SocketUtil.h
        NetworkManager.cpp
        NetworkManager.h)

macro(HeaderTool)

    add_custom_command(OUTPUT ${PROJECT_SOURCE_DIR}/RPCLibrary/rpc.generated.h ${PROJECT_SOURCE_DIR}/RPCLibrary/rpc.generated.cpp
            COMMAND RPCHeaderTool ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/RPCLibrary
            DEPENDS ${ARGV} RPCHeaderTool
            COMMENT "generating files"
            )

endmacro(HeaderTool)

add_library(RPClibrary ${SOURCE})
target_precompile_headers(RPClibrary PUBLIC RPC.h)

target_link_libraries(RPClibrary Boost::log Boost::log_setup)