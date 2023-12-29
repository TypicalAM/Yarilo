cmake_minimum_required(VERSION 3.12)
project(sniffsniff)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS ON) # popen()/pclose() are not C++ standards

find_package(libtins REQUIRED)
find_package(Boost 1.70.0 REQUIRED log_setup log)

add_executable("${PROJECT_NAME}" src/main.cpp)
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries("${PROJECT_NAME}" ${LIBTINS_LIBRARIES} pthread Boost::log_setup Boost::log)
