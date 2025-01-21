#ifndef ECC_H
#define ECC_H

// sign a message
size_t sign_message(const char *message, mbedtls_ecdsa_context key, unsigned char *signature);

// verify a signature
int verify_signature(const char *message, const unsigned char *signature, mbedtls_ecdsa_context key, size_t sig_len);

void pub_key_to_string(mbedtls_ecdsa_context key, char *ret_key);

void pk_key_to_string(mbedtls_ecdsa_context key, char *ret_key);

#endif
