cmake_minimum_required(VERSION 3.24)
project(libcrypto
        VERSION 0.1.0
        DESCRIPTION "Cryptography utilities for C/C++"
        HOMEPAGE_URL "https://github.com/M3DZIK/libcrypto-c"
        LANGUAGES C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(include)
install(FILES include/libcrypto.h DESTINATION include)

add_subdirectory(src)

include(CTest)
add_subdirectory(test)
