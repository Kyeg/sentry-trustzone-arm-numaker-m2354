#include "newecc.hpp"

using namespace std;

string *generate_key_pair()
{
    //string keys[2] = {"hello", "world"};
    return 0;
}

size_t sign_message(const char *message, string key, unsigned char *signature)
{
    string signature_temp = "hello";
    memcpy(signature, signature_temp.c_str(), signature_temp.size());
    return signature_temp.size();
}

int verify_signature(const char *message, const unsigned char *signature, string key, size_t sig_len)
{
    return 1;
}
