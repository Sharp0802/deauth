cmake_minimum_required(VERSION 3.28)
project(deauth C)

set(CMAKE_C_STANDARD 90)

add_executable(deauth main.c)
target_link_libraries(deauth PRIVATE pcap)
