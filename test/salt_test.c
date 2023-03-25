#include "../include/libcrypto.h"

#include <string.h>
#include <stdio.h>

#define SALT_LEN 16

int main()
{
    unsigned char *salt = generate_salt(SALT_LEN);

    if (!salt) {
        fprintf(stderr, "Error generating salt.\n");
        return 1;
    }

    // check that salt is 16 bytes long
    if (strlen((char*) salt) != SALT_LEN) {
        fprintf(stderr, "Salt is not 16 bytes long.\n");
        return 1;
    }
}
