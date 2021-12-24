cmake_minimum_required(VERSION 3.10)

# set the project name
project(dcr-server)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Protobuf
find_package(Protobuf REQUIRED)
find_package(cppzmq REQUIRED)

set(source_files
    main.cc
    config.h
    crypto_util.hpp crypto_util.cc
    util/logging.hpp util/logging.cc
    storage.hpp storage.cc
    dc_server.hpp dc_server.cc
    comm.hpp comm.cc
)

# Protobuf
set(protobuf_files
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/capsule.proto
)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${protobuf_files})
add_executable(${PROJECT_NAME} ${source_files} ${PROTO_SRCS} ${PROTO_HDRS})

# RocksDB
add_subdirectory(${CMAKE_SOURCE_DIR}/../third_party/rocksdb third_party/rocksdb)
include_directories(${CMAKE_SOURCE_DIR}/../third_party/rocksdb/include)

target_link_libraries(${PROJECT_NAME} PUBLIC
  protobuf::libprotobuf
  rocksdb
  cppzmq
)