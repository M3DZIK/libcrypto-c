#include "libcrypto.h"

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

    // check if salt length is correct
    if (strlen((char*) salt) != SALT_LEN) {
        fprintf(stderr, "Salt is not %i bytes long.\n", SALT_LEN);
        return 1;
    }
}
