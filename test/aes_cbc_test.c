#include "libcrypto.h"

#include <stdio.h>
#include <string.h>

#define CLEAR_TEXT "hello world"
#define PASSWORD "secret passphrase"
#define SALT (unsigned char*) "salt"
#define EXAMPLE_CIPHERTEXT "ceb5156163e045c920cea4748ae302c7e210b4d521925bc342c71145aef3952d"

int main()
{
    char *hash = pbkdf2_hash_sha256(PASSWORD, SALT, 1000);

    char *encrypted = aes_cbc_encrypt(CLEAR_TEXT, hash);
    char *decrypted = aes_cbc_decrypt(encrypted, hash);
    if (strcmp(decrypted, CLEAR_TEXT) != 0) {
        fprintf(stderr, "text after encryption and decryption does not match clear text\n");
        fprintf(stderr, "Expected: %s\n", CLEAR_TEXT);
        fprintf(stderr, "Actual: %s\n", decrypted);
        return 1;
    }

    free(encrypted);
    free(decrypted);

    char *decrypted_two = aes_cbc_decrypt(EXAMPLE_CIPHERTEXT, hash);
    if (strcmp(decrypted_two, CLEAR_TEXT) != 0) {
        fprintf(stderr, "Decrypted text does not match clear text\n");
        fprintf(stderr, "Expected: %s\n", CLEAR_TEXT);
        fprintf(stderr, "Actual: %s\n", decrypted_two);
        return 1;
    }

    free(decrypted_two);
    free(hash);

    return 0;
}
