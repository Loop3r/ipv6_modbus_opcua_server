cmake_minimum_required(VERSION 3.5)
project(ipv6_modbus_opcua_server)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES ipv6_modbus_opcua_server.c socket.c socket.h modbus_data.h open62541.c open62541.h)
add_executable(ipv6_modbus_opcua_server ${SOURCE_FILES})

target_link_libraries(ipv6_modbus_opcua_server modbus pthread)