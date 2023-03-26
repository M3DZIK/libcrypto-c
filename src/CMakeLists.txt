add_library(libcrypto pbkdf2.c aes_cbc.c salt.c)

install(TARGETS libcrypto
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)
