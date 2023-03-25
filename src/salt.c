#include "../include/libcrypto.h"

#include <stdio.h>
#include <openssl/rand.h>

unsigned char *generate_salt(int salt_len)
{
    unsigned char *salt = (unsigned char*) malloc(salt_len);
    if (!salt) {
        fprintf(stderr, "Error allocating memory for salt.\n");
        return NULL;
    }

    if (RAND_bytes(salt, salt_len) != 1) {
        fprintf(stderr, "Error generating random bytes for salt.\n");
        free(salt);
        return NULL;
    }

    return salt;
}
