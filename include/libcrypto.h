#ifndef LIBCRYPTO_H
#define LIBCRYPTO_H

// Salt
unsigned char *generate_salt(int salt_len);

// PBKDF2
char *pbkdf2_hash_sha256(const char *password, const unsigned char *salt, int iterations);
char *pbkdf2_hash_sha512(const char *password, const unsigned char *salt, int iterations);

// AES CBC
char *aes_cbc_encrypt(const char *cleartext, const char *key);
char *aes_cbc_decrypt(const char *ciphertext, const char *key);

#endif //LIBCRYPTO_H
