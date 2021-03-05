cmake_minimum_required(VERSION 3.17)
project(RPClibrary)
set(CMAKE_CXX_STANDARD 20)

SET(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS log log_setup REQUIRED)

include_directories(${Boost_INCLUDE_DIR})
add_subdirectory(RPCHeaderTool)

set(GENERATED_HEADER ${PROJECT_SOURCE_DIR}/rpc.generated.h)
set(GENERATED_CPP ${PROJECT_SOURCE_DIR}/rpc.generated.cpp)


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

macro(HeaderTool ParseDirectory LibDirectory Headers)
    add_custom_target(OUTPUT ${GENERATED_HEADER} ${GENERATED_CPP}
            COMMAND RPCHeaderTool ${ParseDirectory} ${LibDirectory}
            DEPEND ${Headers})
endmacro()

add_library(RPClibrary ${SOURCE} ${GENERATED_HEADER} ${GENERATED_CPP})
target_precompile_headers(RPClibrary PUBLIC RPC.h)

target_link_libraries(RPClibrary Boost::log Boost::log_setup)