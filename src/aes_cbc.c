#include "libcrypto.h"

#include <stdio.h>
#include <string.h>

/**
 * Convert hexadecimal string to bytes.
 * @param key hexadecimal string
 * @return bytes
 */
unsigned char *process_key(const char *key)
{
    unsigned char* secret_key = (unsigned char*) malloc(strlen(key) / 2);

    int secret_key_length = (int) strlen(key) / 2;

    for (int i = 0; i < secret_key_length; i++) {
        char byte_string[3] = { key[i * 2], key[i * 2 + 1], '\0' };
        secret_key[i] = (unsigned char)strtoul(byte_string, NULL, 16);
    }

    return secret_key;
}

char *aes_cbc_encrypt(const char *cleartext, const char *key)
{
    // convert hexadecimal key and ciphertext to bytes
    unsigned char* secret_key = process_key(key);

    // generate initialization vector
    unsigned char *iv = generate_salt(AES_BLOCK_SIZE);

    // create cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(secret_key);
        free(iv);

        fprintf(stderr, "Error creating cipher context.\n");
        return NULL;
    }

    // initialize cipher context
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*) secret_key, iv) != 1) {
        fprintf(stderr, "Error initializing cipher context.\n");
        goto cleanup;
    }

    // allocate memory for ciphertext
    int ciphertext_len = (int) strlen(cleartext) + AES_BLOCK_SIZE;
    unsigned char *ciphertext = (unsigned char*) malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Error allocating memory for ciphertext.\n");
        goto cleanup;
    }

    // encrypt plaintext
    int update_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &update_len, (unsigned char*) cleartext, (int) strlen(cleartext)) != 1) {
        fprintf(stderr, "Error encrypting plaintext.\n");
        goto cleanup;
    }
    ciphertext_len = update_len;

    // finalize encryption
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len) != 1) {
        fprintf(stderr, "Error finalizing encryption.\n");
        goto cleanup;
    }
    ciphertext_len += final_len;

    // return iv + ciphertext as a single hex string
    char *hex = (char*) malloc(ciphertext_len * 2 + AES_BLOCK_SIZE * 2 + 1);
    if (!hex) {
        fprintf(stderr, "Error allocating memory for hex string.\n");
        goto cleanup;
    }

    // append iv to ciphertext
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        sprintf(hex + i * 2, "%02x", iv[i]);
    }

    // append ciphertext
    for (int i = 0; i < ciphertext_len; i++) {
        sprintf(hex + AES_BLOCK_SIZE * 2 + i * 2, "%02x", ciphertext[i]);
    }

    // free cipher context
    EVP_CIPHER_CTX_free(ctx);

    // free memory
    free(ciphertext);
    free(secret_key);
    free(iv);

    return hex;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    free(secret_key);
    free(iv);
    free(ciphertext);

    return NULL;
}

char *aes_cbc_decrypt(const char *cipher_text, const char *key)
{
    // convert hexadecimal key and ciphertext to bytes
    unsigned char* secret_key = process_key(key);

    // convert hexadecimal ciphertext to bytes
    int cipher_text_length = (int) strlen(cipher_text) / 2;
    unsigned char *cipher_text_bytes = (unsigned char*) malloc(cipher_text_length);
    for (int i = 0; i < cipher_text_length; i++) {
        char byte_string[3] = { cipher_text[i * 2], cipher_text[i * 2 + 1], '\0' };
        cipher_text_bytes[i] = (unsigned char)strtoul(byte_string, NULL, 16);
    }

    // extract initialization vector
    unsigned char *iv = (unsigned char*) malloc(AES_BLOCK_SIZE);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv[i] = cipher_text[i];
    }

    // create an EVP cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating EVP context");

        free(secret_key);
        free(cipher_text_bytes);

        return NULL;
    }

    // initialize the cipher context with the key and IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret_key, cipher_text_bytes) != 1) {
        fprintf(stderr, "Error initializing decryption");

        EVP_CIPHER_CTX_free(ctx);
        free(secret_key);
        free(cipher_text_bytes);

        return NULL;
    }

    // allocate memory for the decrypted text
    size_t decrypted_text_len = cipher_text_length - EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char *decrypted_text_bytes = (unsigned char*) malloc(decrypted_text_len);

    // perform decryption in a single call
    int decrypted_length = 0;
    if (EVP_DecryptUpdate(ctx, decrypted_text_bytes, &decrypted_length, cipher_text_bytes + EVP_CIPHER_block_size(EVP_aes_256_cbc()), (int) decrypted_text_len) != 1) {
        fprintf(stderr, "Error performing decryption");
        goto cleanup;
    }

    // finalize the decryption
    int final_length = 0;
    if (EVP_DecryptFinal_ex(ctx, decrypted_text_bytes + decrypted_length, &final_length) != 1) {
        fprintf(stderr, "Error finalizing decryption");
        goto cleanup;
    }
    decrypted_length += final_length;

    // convert decrypted bytes to string
    char *decryptedText = (char*) malloc(decrypted_length + 1);
    memcpy(decryptedText, decrypted_text_bytes, decrypted_length);
    decryptedText[decrypted_length] = '\0';

    // free cipher context
    EVP_CIPHER_CTX_free(ctx);

    // free memory
    free(secret_key);
    free(cipher_text_bytes);
    free(decrypted_text_bytes);

    return decryptedText;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    free(secret_key);
    free(cipher_text_bytes);
    free(decrypted_text_bytes);

    return NULL;
}
