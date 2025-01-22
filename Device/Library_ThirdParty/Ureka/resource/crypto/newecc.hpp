#ifndef NEWECC_H
#define NEWECC_H

#include <string>

using namespace std;

string *generate_key_pair();

// sign a message
size_t sign_message(const char *message, string key, unsigned char *signature);

// verify a signature
int verify_signature(const char *message, const unsigned char *signature, string key, size_t sig_len);

#endif