cmake_minimum_required(VERSION 3.24)
project(libcrypto_tests)

set(CMAKE_C_STANDARD 17)

add_executable(TestPbkdf2 pbkdf2_test.c)
target_link_libraries(TestPbkdf2 libcrypto OpenSSL::SSL)
add_executable(TestAesCbc aes_cbc_test.c)
target_link_libraries(TestAesCbc libcrypto OpenSSL::SSL)

add_test(NAME TestPbkdf2
        COMMAND TestPbkdf2)
add_test(NAME TestAesCbc
        COMMAND TestAesCbc)
