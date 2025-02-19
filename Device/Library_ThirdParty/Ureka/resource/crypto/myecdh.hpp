#ifndef ECDH_HPP
#define ECDH_HPP
#include <string>
#include "ecdsa.h"

using namespace std;

string byte_to_hex(unsigned char *bytes, int len);

string hex_to_byte(string hex_str);

// mbedtls_ecdsa_context turn_string_to_key(string pk, string pub);

string generate_random_str(int bytes_num);

// string generate_sha256_hash_bytes(string message);

string generate_ecdh_key(string priv_key, string pub_key, string salt, string info);

string gcm_gen_iv();

string *gcm_encrypt(string plaintext, string associated_plaintext, string session_key, string iv);

string gcm_decrypt(string ciphertext, string associated_plaintext, string gcm_authentication_tag, string session_key, string iv);

#endif