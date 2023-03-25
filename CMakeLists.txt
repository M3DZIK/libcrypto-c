cmake_minimum_required(VERSION 3.24)
project(libcrypto)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(libcrypto src/pbkdf2.c src/aes_cbc.c src/salt.c)

add_subdirectory(test)
