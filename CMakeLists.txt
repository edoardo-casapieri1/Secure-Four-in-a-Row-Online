cmake_minimum_required(VERSION 3.16)
project(cybersec_project)

add_library(CLIENT_SOURCES Client/client.cpp Game/game.cpp)
add_library(SERVER_SOURCES Server/server.cpp)

add_executable(client Client/client.cpp)
add_executable(server Server/server.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(client CLIENT_SOURCES OpenSSL::SSL)
target_link_libraries(server SERVER_SOURCES OpenSSL::SSL)

set(CMAKE_CXX_STANDARD 14)
