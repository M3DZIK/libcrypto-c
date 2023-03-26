#include "libcrypto.h"

#include <stdio.h>

unsigned char *generate_salt(int salt_len)
{
    // allocate memory for salt
    unsigned char *salt = (unsigned char*) malloc(salt_len);
    if (!salt) {
        fprintf(stderr, "Error allocating memory for salt.\n");
        return NULL;
    }

    // fill salt with random bytes
    if (RAND_bytes(salt, salt_len) != 1) {
        free(salt);

        fprintf(stderr, "Error generating random bytes for salt.\n");
        return NULL;
    }

    return salt;
}
