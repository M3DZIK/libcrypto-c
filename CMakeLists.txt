cmake_minimum_required(VERSION 3.24)
project(libcrypto
        VERSION 0.1.0
        DESCRIPTION "Cryptography utilities for C/C++"
        HOMEPAGE_URL "https://github.com/M3DZIK/libcrypto-c"
        LANGUAGES C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(libcrypto src/pbkdf2.c src/aes_cbc.c src/salt.c)

add_subdirectory(test)
