#include "../include/libcrypto.h"

#include <stdio.h>
#include <string.h>

int main()
{
    char *password = "hello world";

    unsigned char *salt = (unsigned char *) "salt";

    char *hash = pbkdf2_hash_sha256(password, salt, 1000);

    char *expected = "27426946a796b9a62bc53fba7157961905e4bdd0af2203d6eaf6dd4b64942def";

    if (strcmp(hash, expected) != 0) {
        printf("hash mismatch\n");
        printf("Expected: %s\n", expected);
        printf("Actual: %s\n", hash);
        return 1;
    }

    return 0;
}
