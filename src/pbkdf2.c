#include "../include/libcrypto.h"

#include "string.h"
#include <openssl/evp.h>

char *hash_to_hex(const char *key, int key_len)
{
    // allocate memory for the hex key
    char *hex_key = (char*) malloc(sizeof(char) * (key_len * 2 + 1));
    if (!hex_key) {
        fprintf(stderr, "Error allocating memory for hex key.\n");
        return NULL;
    }

    // converting the key to hex
    unsigned char *digest = (unsigned char*) key;
    for (int i = 0; i < key_len; i++) {
        sprintf(hex_key + i * 2, "%02x", digest[i]);
    }

    return hex_key;
}

char *pbkdf2_hash_sha256(const char *password, const unsigned char *salt, int iterations)
{
    int key_len = 32;
    int salt_len = (int) strlen((const char*) salt);

    // allocate memory for the key
    unsigned char *key = (unsigned char*) malloc(key_len);
    if (!key) {
        fprintf(stderr, "Error allocating memory for key.\n");
        return NULL;
    }

    // compute hash
    PKCS5_PBKDF2_HMAC(password, (int) strlen(password), salt, salt_len, iterations, EVP_sha256(), key_len, key);

    // converting the key to hex
    char *hex_key = hash_to_hex((const char*)key, key_len);
    if (!hex_key) {
        free(key);

        fprintf(stderr, "Error converting key to hex.\n");
        return NULL;
    }

    return hex_key;
}

char *pbkdf2_hash_sha512(const char *password, const unsigned char *salt, int iterations)
{
    int key_len = 64;
    int salt_len = (int) strlen((const char*)salt);

    // allocate memory for the key
    unsigned char *key = (unsigned char*) malloc(key_len);
    if (!key) {
        fprintf(stderr, "Error allocating memory for key.\n");
        return NULL;
    }

    // compute hash
    PKCS5_PBKDF2_HMAC(password, (int) strlen(password), salt, salt_len, iterations, EVP_sha512(), key_len, key);

    // converting the key to hex
    char *hex_key = hash_to_hex((const char*)key, key_len);
    if (!hex_key) {
        free(key);

        fprintf(stderr, "Error converting key to hex.\n");
        return NULL;
    }

    return hex_key;
}
