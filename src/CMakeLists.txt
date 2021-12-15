cmake_minimum_required(VERSION 3.10)

# set the project name
project(dcr-server)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Protobuf REQUIRED)

set(protobuf_files
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/capsule.proto
)

set(source_files
    main.cc
    config.h
    crypto_util.hpp crypto_util.cc
    util/logging.hpp util/logging.cc
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${protobuf_files})
add_executable(${PROJECT_NAME} ${source_files} ${PROTO_SRCS} ${PROTO_HDRS})

target_link_libraries(${PROJECT_NAME}
  protobuf::libprotobuf
)