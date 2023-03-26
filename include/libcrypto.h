#ifndef LIBCRYPTO_H
#define LIBCRYPTO_H

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * Generate a random salt
 * @param salt_len Length of the salt
 * @return unsigned char* Pointer to the salt
 */
unsigned char *generate_salt(int salt_len);

/**
 * Compute the PBKDF2-SHA256 hash of a password
 * @param password Password to hash
 * @param salt Salt to use
 * @param iterations Number of iterations
 * @return char* Pointer to the hash
 */
char *pbkdf2_hash_sha256(const char *password, const unsigned char *salt, int iterations);

/**
 * Compute the PBKDF2-SHA512 hash of a password
 * @param password Password to hash
 * @param salt Salt to use
 * @param iterations Number of iterations
 * @return char* Pointer to the hash
 */
char *pbkdf2_hash_sha512(const char *password, const unsigned char *salt, int iterations);

/**
 * Encrypt a cleartext using AES-256-CBC
 * @param cleartext Cleartext to encrypt
 * @param key Key to use
 * @return char* Pointer to the ciphertext
 */
char *aes_cbc_encrypt(const char *cleartext, const char *key);

/**
 * Decrypt a ciphertext using AES-256-CBC
 * @param ciphertext Ciphertext to decrypt
 * @param key Key to use
 * @return char* Pointer to the cleartext
 */
char *aes_cbc_decrypt(const char *ciphertext, const char *key);

#endif //LIBCRYPTO_H
