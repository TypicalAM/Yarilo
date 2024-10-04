cmake_minimum_required(VERSION 3.12)
project(yarilo)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

option(YARILO_WITH_MAYHEM "Enable pin configuration and handling" OFF)
option(YARILO_BUILD_DOCS "Build documentation" OFF)

find_package(Threads REQUIRED)
find_package(libtins REQUIRED)
find_package(spdlog REQUIRED)
find_package(LibNL REQUIRED)
find_package(Doxygen)

if (YARILO_BUILD_DOCS)
  if (DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    message(STATUS "Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target(doc_doxygen ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
  else (DOXYGEN_FOUND)
    message(STATUS "Doxygen needs to be installed to generate the doxygen documentation.")
  endif (DOXYGEN_FOUND)
endif (YARILO_BUILD_DOCS)

# This branch assumes that gRPC and all its dependencies are already installed
# on this system, so they can be located by find_package().

# Find Protobuf installation
# Looks for protobuf-config.cmake file installed by Protobuf's cmake installation.
option(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${Protobuf_VERSION}")

set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
if(CMAKE_CROSSCOMPILING)
  find_program(_PROTOBUF_PROTOC protoc)
else()
  set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
endif()

# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(_GRPC_GRPCPP gRPC::grpc++)
if(CMAKE_CROSSCOMPILING)
  find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
else()
  set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
endif()

get_filename_component(hw_proto "../protos/service.proto" ABSOLUTE)
get_filename_component(hw_proto_path "${hw_proto}" PATH)

set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/proto/service.pb.cc")
set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/proto/service.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/proto/service.grpc.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/proto/service.grpc.pb.h")

add_custom_command(
      OUTPUT "${hw_proto_srcs}" "${hw_proto_hdrs}" "${hw_grpc_srcs}" "${hw_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}/proto"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}/proto"
        -I "${hw_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${hw_proto}"
      DEPENDS "${hw_proto}")

include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
  ${LibNL_INCLUDE_DIR}
 )

add_library(hw_grpc_proto
  ${hw_grpc_srcs}
  ${hw_grpc_hdrs}
  ${hw_proto_srcs}
  ${hw_proto_hdrs})

target_link_libraries(hw_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

# find_program(CMAKE_CXX_CPPCHECK NAMES cppcheck)
# if (CMAKE_CXX_CPPCHECK)
#     list(
#         APPEND CMAKE_CXX_CPPCHECK 
#             "--enable=warning"
#             "--inconclusive"
#             "--force" 
#             "--check-level=exhaustive"
#             "--inline-suppr"
#     )
# endif()

if(YARILO_WITH_MAYHEM)
    add_compile_definitions(MAYHEM)
    message(STATUS "Mayhem support enabled")
endif()

set(SOURCES 
  src/main.cpp
  src/net_card_manager.cpp
  src/sniffer.cpp
  src/access_point.cpp
  src/service.cpp
  src/decrypter.cpp
  src/group_decrypter.cpp
  src/recording.cpp
  src/formatter.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-g -Wall -Wextra -Wshadow -Wpedantic -Wconversion -Wsign-conversion -Wundef -Wnon-virtual-dtor -Woverloaded-virtual -w -Werror")
target_link_libraries(${PROJECT_NAME}
    hw_grpc_proto
    absl::flags
    absl::flags_parse
    spdlog::spdlog
    pthread
    ${LibNL_LIBRARIES}
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF}
    ${LIBTINS_LIBRARIES}
)
