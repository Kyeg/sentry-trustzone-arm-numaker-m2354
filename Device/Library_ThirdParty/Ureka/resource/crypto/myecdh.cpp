#include <stdio.h>
#include <string>
#include <cstdlib>
#include <cstring>
#include "sha256.h"
#include "ecdh.h"
#include "hkdf.h"
#include "gcm.h"
#include "pk.h"
#include "ecp.h"
#include "error.h"
#include "ctr_drbg.h"
#include "entropy.h"
#include "myecdh.hpp"

using namespace std;

string byte_to_hex(unsigned char *bytes, int len)
{
    string hex_str = "";
    for (int i = 0; i < len; i++)
    {
        char hex_byte[3];
        sprintf(hex_byte, "%02x", bytes[i]);
        hex_str += hex_byte;
    }
    return hex_str;
}

string hex_to_byte(string hex_str)
{
    string byte_str = "";
    for (int i = 0; i < hex_str.size(); i += 2)
    {
        char byte = (char)strtol(hex_str.substr(i, 2).c_str(), NULL, 16);
        byte_str += byte;
    }
    return byte_str;
}

/*string pk_key_to_string(mbedtls_ecdsa_context key)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    char buf[1000];
    int ret = 1;

    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
    {
        // cout << "mbedtls_pk_setup failed with error code " << ret << endl;
        printf("mbedtls_pk_setup failed with error code %d\n", ret);
        return "";
    }

    pk.pk_ctx = &key;

    if ((ret = mbedtls_pk_write_key_pem(&pk, (unsigned char *)buf, 1000)) != 0)
    {
        // cout << "mbedtls_pk_write_key_pem failed with error code " << ret << endl;
        printf("mbedtls_pk_write_key_pem failed with error code %d\n", ret);
        return "";
    }

    // mbedtls_pk_free(&pk);

    return string(buf);
}

string pub_key_to_string(mbedtls_ecdsa_context key)
{
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    char buf[1000];

    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
    {
        // cout << "mbedtls_pk_setup failed with error code " << ret << endl;
        printf("mbedtls_pk_setup failed with error code %d\n", ret);
        return "";
    }

    pk.pk_ctx = &key;

    if ((ret = mbedtls_pk_write_pubkey_pem(&pk, (unsigned char *)buf, 1000)) != 0)
    {
        // cout << "mbedtls_pk_write_pubkey_pem failed with error code " << ret << endl;
        printf("mbedtls_pk_write_pubkey_pem failed with error code %d\n", ret);
        return "";
    }

    // mbedtls_pk_free(&pk);

    return string(buf);
}*/

// mbedtls_ecdsa_context turn_string_to_key(char *pk, char *pub)
// {
//     mbedtls_ecdsa_context key;
//     mbedtls_ecdsa_init(&key);
//     mbedtls_pk_context pk_ctx, pub_ctx;
//     mbedtls_pk_init(&pk_ctx);
//     mbedtls_pk_init(&pub_ctx);

//     int ret = 1;

//     if (pk != "")
//     {
//         if ((ret = mbedtls_pk_parse_key(&pk_ctx, (const unsigned char *)pk, strlen(pk) + 1, NULL, 0)) != 0)
//         {
//             // cout << "mbedtls_pk_parse_key failed with error code " << ret << endl;
//             printf("mbedtls_pk_parse_key failed with error code %d\n", ret);
//             return key;
//         }

//         if ((ret = mbedtls_ecp_group_copy(&key.grp, &mbedtls_pk_ec(pk_ctx)->grp)) != 0)
//         {
//             // cout << "mbedtls_ecp_group_copy failed with error code " << ret << endl;
//             printf("mbedtls_ecp_group_copy failed with error code %d\n", ret);
//             return key;
//         }

//         if ((ret = mbedtls_mpi_copy(&key.d, &mbedtls_pk_ec(pk_ctx)->d)) != 0)
//         {
//             // cout << "mbedtls_mpi_copy failed with error code " << ret << endl;
//             printf("mbedtls_mpi_copy failed with error code %d\n", ret);
//             return key;
//         }
//     }

//     if (pub != "")
//     {
//         if ((ret = mbedtls_pk_parse_public_key(&pub_ctx, (const unsigned char *)pub, strlen(pub) + 1)) ! = 0)
//         {
//             // cout << "mbedtls_pk_parse_public_key failed with error code " << ret << endl;
//             printf("mbedtls_pk_parse_public_key failed with error code %d\n", ret);
//             return key;
//         }

//         if ((ret = mbedtls_ecp_copy(&key.Q, &mbedtls_pk_ec(pub_ctx)->Q)) != 0)
//         {
//             // cout << "mbedtls_ecp_copy failed with error code " << ret << endl;
//             printf("mbedtls_ecp_copy failed with error code %d\n", ret);
//             return key;
//         }

//         if ((ret = mbedtls_ecp_group_copy(&key.grp, &mbedtls_pk_ec(pub_ctx)->grp)) != 0)
//         {
//             // cout << "mbedtls_ecp_group_copy failed with error code " << ret << endl;
//             printf("mbedtls_ecp_group_copy failed with error code %d\n", ret);
//             return key;
//         }
//     }

//     mbedtls_pk_free(&pk_ctx);
//     mbedtls_pk_free(&pub_ctx);

//     return key;
// }

string generate_random_str(int bytes_num)
{
    unsigned char *random_bytes = new unsigned char[bytes_num / 2];
    for (int i = 0; i < bytes_num / 2; i++)
    {
        random_bytes[i] = rand() % 256;
    }
    string ret_str = byte_to_hex(random_bytes, bytes_num / 2);
    // check the size
    // cout << "random string: " << ret_str.size() << " and the size of byte is" << bytes_num << endl;
    printf("random string: %d and the size of byte is %d\n", ret_str.size(), bytes_num);
    return ret_str;
}

string generate_ecdh_key(string priv_key, string pub_key, string salt, string info)
{
    char *derived_key = new char[32];

    unsigned char shared_secret[MBEDTLS_ECP_MAX_BYTES];
    size_t shared_secret_len = 0;

    mbedtls_ecdh_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdh_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)salt.c_str(), salt.size()) != 0)
    {
        // cout << "Failed to seed ctr_drbg" << endl;
        printf("Failed to seed ctr_drbg\n");
        return "";
    }

    mbedtls_pk_context pk_ctx, pbk_ctx;
    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_init(&pbk_ctx);

    if (mbedtls_pk_parse_key(&pk_ctx, (const unsigned char *)priv_key.c_str(), priv_key.size() + 1, NULL, 0) != 0)
    {
        // cout << "Failed to parse private key" << endl;
        printf("Failed to parse private key\n");
        return "";
    }

    if (mbedtls_pk_parse_public_key(&pbk_ctx, (const unsigned char *)pub_key.c_str(), pub_key.size() + 1) != 0)
    {
        // cout << "Failed to parse public key" << endl;
        printf("Failed to parse public key\n");
        return "";
    }

    mbedtls_ecp_keypair *pk_pair = mbedtls_pk_ec(pk_ctx);
    mbedtls_ecp_keypair *pbk_pair = mbedtls_pk_ec(pbk_ctx);

    int ret = 1;

    if ((ret = mbedtls_ecdh_get_params(&ctx, pk_pair, MBEDTLS_ECDH_OURS)) != 0)
    {
        // cout << "Failed to get params " << ret << endl;
        printf("Failed to get params %d\n", ret);
        return "";
    }

    if ((ret = mbedtls_ecdh_get_params(&ctx, pbk_pair, MBEDTLS_ECDH_THEIRS)) != 0)
    {
        // cout << "Failed to get params" << ret << endl;
        printf("Failed to get params %d\n", ret);
        return "";
    }

    if (mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &ctx.Qp, &ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        // cout << "Failed to compute shared secret" << endl;
        printf("Failed to compute shared secret\n");
        return "";
    }

    shared_secret_len = mbedtls_mpi_size(&ctx.z);
    if (mbedtls_mpi_write_binary(&ctx.z, shared_secret, shared_secret_len) != 0)
    {
        // cout << "Failed to write shared secret" << endl;
        printf("Failed to write shared secret\n");
        return "";
    }

    // HKDF
    if (mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                     (const unsigned char *)shared_secret, shared_secret_len,
                     (const unsigned char *)salt.c_str(), salt.size(),
                     (const unsigned char *)info.c_str(), info.size(),
                     (unsigned char *)derived_key, 32) != 0)
    {
        // cout << "Failed to derive key" << endl;
        printf("Failed to derive key\n");
        return "";
    }

    // clean up
    mbedtls_ecdh_free(&ctx);
    mbedtls_pk_free(&pk_ctx);
    mbedtls_pk_free(&pbk_ctx);

    return string(derived_key, 32);
}

string gcm_gen_iv()
{
    return generate_random_str(12);
}

string *gcm_encrypt(string plaintext, string associated_plaintext, string session_key, string iv)
{
    // perform gcm encryption
    unsigned char *ciphertext = new unsigned char[plaintext.size()];
    unsigned char *tag = new unsigned char[16];

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (const unsigned char *)session_key.c_str(), 256) != 0)
    {
        // cout << "Failed to set key(gcm_encrypt)" << endl;
        printf("Failed to set key(gcm_encrypt)\n");
        return NULL;
    }

    if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(), (const unsigned char *)iv.c_str(), iv.size(), (const unsigned char *)associated_plaintext.c_str(), associated_plaintext.size(), (const unsigned char *)plaintext.c_str(), ciphertext, 16, tag) != 0)
    {
        // cout << "Failed to encrypt(gcm_encrypt)" << endl;
        printf("Failed to encrypt(gcm_encrypt)\n");
        return NULL;
    }

    string *ret = new string[2];
    ret[0] = byte_to_hex(ciphertext, plaintext.size());
    ret[1] = byte_to_hex(tag, 16);

    return ret;
}

string gcm_decrypt(string ciphertext, string associated_plaintext, string gcm_authentication_tag, string session_key, string iv)
{
    // perform gcm decryption
    unsigned char *plaintext = new unsigned char[ciphertext.size()];

    string turned_cipher = hex_to_byte(ciphertext);
    string turned_tag = hex_to_byte(gcm_authentication_tag);

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, (const unsigned char *)session_key.c_str(), 256) != 0)
    {
        throw std::runtime_error("-> FAILURE: VERIFY_IV_AND_HMAC");
    }

    if (mbedtls_gcm_auth_decrypt(&ctx, turned_cipher.size(), (const unsigned char *)iv.c_str(), iv.size(), (const unsigned char *)associated_plaintext.c_str(), associated_plaintext.size(), (const unsigned char *)turned_tag.c_str(), 16, (const unsigned char *)turned_cipher.c_str(), plaintext) != 0)
    {
        throw std::runtime_error("-> FAILURE: VERIFY_IV_AND_HMAC");
    }

    return string((char *)plaintext, turned_cipher.size());
}