cmake_minimum_required(VERSION 3.10)

# set the project name
project(dcr-server)

# specify the C++ standard
set(GCC_OPTIMIZATION_FLAGS "-O3")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_OPTIMIZATION_FLAGS}")

# Protobuf
find_package(Protobuf REQUIRED)
# find_package(cppzmq REQUIRED)

## load in pkg-config support
find_package(PkgConfig)
## use pkg-config to get hints for 0mq locations
pkg_check_modules(PC_ZeroMQ QUIET zmq)

# Openssl
find_package(OpenSSL REQUIRED)

## use the hint from above to find where 'zmq.hpp' is located
find_path(ZeroMQ_INCLUDE_DIR
        NAMES zmq.hpp
        PATHS ${PC_ZeroMQ_INCLUDE_DIRS}
        )

## use the hint from about to find the location of libzmq
find_library(ZeroMQ_LIBRARY
        NAMES zmq
        PATHS ${PC_ZeroMQ_LIBRARY_DIRS}
        )

set(source_files
    main.cc
    config.h
    crypto.hpp crypto.cc
    crypto_util.hpp crypto_util.cc
    util/logging.hpp util/logging.cc util/utils.hpp
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
target_include_directories(${PROJECT_NAME} PUBLIC ${ZeroMQ_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} PUBLIC
  protobuf::libprotobuf
  rocksdb
  ${ZeroMQ_LIBRARY}
  OpenSSL::SSL OpenSSL::Crypto
)
