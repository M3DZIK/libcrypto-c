#include "../include/libcrypto.h"

#include <stdio.h>

int main(int argc, const char** argv)
{
    char *clear_text = "hello world";
    char *password = "secret passphrase";
    unsigned char *salt = (unsigned char *) "salt";

    char *hash = pbkdf2_hash_sha256(password, salt, 1000);

    char *encrypted = aes_cbc_encrypt(clear_text, hash);

    printf("Encrypted: %s\n", encrypted);

    char *decrypted = aes_cbc_decrypt(encrypted, hash);

    printf("Decrypted: %s\n", decrypted);

    char *decrypted_two = aes_cbc_decrypt("ceb5156163e045c920cea4748ae302c7e210b4d521925bc342c71145aef3952d", hash);

    printf("Decrypted: %s\n", decrypted_two);

    return 0;
}
