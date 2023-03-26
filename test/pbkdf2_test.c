#include "libcrypto.h"

#include <stdio.h>
#include <string.h>

#define PASSWORD "hello world"
#define SALT (unsigned char*) "salt"
#define EXPECTED_SHA256 "27426946a796b9a62bc53fba7157961905e4bdd0af2203d6eaf6dd4b64942def"
#define EXPECTED_SHA512 "883f5fb301ff684a2e92fdfc1754241bb2dd3eb6af53e5bd7e6c9eb2df7ccb7783f40872b5d3dd5c2915a519f008a92c4c2093e8a589e59962cf1e33c8706ca9"

int main()
{
    char *hash_sha256 = pbkdf2_hash_sha256(PASSWORD, SALT, 1000);
    if (strcmp(hash_sha256, EXPECTED_SHA256) != 0) {
        fprintf(stderr, "hash mismatch\n");
        fprintf(stderr, "Expected: %s\n", EXPECTED_SHA256);
        fprintf(stderr, "Actual: %s\n", hash_sha256);
        return 1;
    }

    free(hash_sha256);

    char *hash_sha512 = pbkdf2_hash_sha512(PASSWORD, SALT, 1000);
    if (strcmp(hash_sha512, EXPECTED_SHA512) != 0) {
        fprintf(stderr, "hash mismatch\n");
        fprintf(stderr, "Expected: %s\n", EXPECTED_SHA512);
        fprintf(stderr, "Actual: %s\n", hash_sha512);
        return 1;
    }

    free(hash_sha512);

    return 0;
}
