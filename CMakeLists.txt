cmake_minimum_required(VERSION 3.12)
project(sniffsniff)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS ON) # popen()/pclose() are not C++ standards
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "") # export compile commands (for clangd)

find_package(PcapPlusPlus REQUIRED)

add_executable("${PROJECT_NAME}" main.cpp)
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
