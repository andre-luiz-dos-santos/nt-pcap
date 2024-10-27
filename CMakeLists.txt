cmake_minimum_required(VERSION 3.10)
project(NetworkTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP libpcap)
pkg_check_modules(ZSTD libzstd)
find_package(OpenSSL REQUIRED)

if(NOT PCAP_FOUND)
    set(PCAP_LIBRARIES "-lpcap")
endif()

if(NOT ZSTD_FOUND)
    set(ZSTD_LIBRARIES "-lzstd")
endif()

add_executable(nt)
target_compile_options(nt PRIVATE
    -g
    -O2
    -Wall
    -Wextra
    -Wno-deprecated-declarations
)
target_sources(nt PRIVATE
    src/checksum.cpp
    src/main.cpp
    src/metrics.cpp
    src/net.cpp
    src/receive.cpp
    src/secret.cpp
    src/sender.cpp
    src/time.cpp
    src/usergroup.cpp
    src/zstd.cpp
)
target_include_directories(nt PRIVATE
    ${PCAP_INCLUDE_DIRS}
    ${ZSTD_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(nt PRIVATE
    -lpthread
    -lstdc++fs
    ${PCAP_LIBRARIES}
    ${ZSTD_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)