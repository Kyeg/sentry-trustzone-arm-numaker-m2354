#include "ecc.hpp"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "ecdh.hpp"
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <gtest/gtest.h>

using namespace std;

// ecc.cpp test=======================================================

// 測試 key pair 生成
TEST(ECC_Test, GenerateKeyPair)
{
    mbedtls_ecdsa_context key = generate_key_pair();
    EXPECT_EQ(key.grp.nbits, 256); // 驗證 key 的大小是否為 256 位元
    mbedtls_ecdsa_free(&key);      // 釋放記憶體
}

// 測試訊息簽名
TEST(ECC_Test, SignMessage)
{
    mbedtls_ecdsa_context key = generate_key_pair();
    const char *message = "hello";
    size_t sig_len;

    unsigned char *signature = sign_message(message, key, sig_len);
    EXPECT_GT(sig_len, 0); // 驗證簽名長度應大於 0

    free(signature); // 釋放記憶體
}

// 測試簽名驗證
TEST(ECC_Test, VerifySignature)
{
    mbedtls_ecdsa_context key = generate_key_pair();
    const char *message = "hello";
    size_t sig_len;

    // 簽名訊息
    unsigned char *signature = sign_message(message, key, sig_len);

    // 驗證簽名
    int verification_result = verify_signature(message, signature, key, sig_len);
    EXPECT_EQ(verification_result, 1); // 驗證簽名應該成功

    free(signature); // 釋放記憶體
}

//===================================================================

// ecdh.cpp test======================================================

TEST(ECDHTest, PkKeyToStringTest)
{
    mbedtls_ecdsa_context key = generate_key_pair(); // 使用 generate_key_pair 生成密鑰
    std::string pk_str = pk_key_to_string(key);

    EXPECT_FALSE(pk_str.empty()); // 測試私鑰轉換後的字串不應為空
    mbedtls_ecdsa_free(&key);
}

TEST(ECDHTest, PubKeyToStringTest)
{
    mbedtls_ecdsa_context key = generate_key_pair(); // 使用 generate_key_pair 生成密鑰
    std::string pub_str = pub_key_to_string(key);

    EXPECT_FALSE(pub_str.empty()); // 測試公鑰轉換後的字串不應為空
    mbedtls_ecdsa_free(&key);
}

TEST(ECDHTest, TurnStringToKeyTest)
{
    mbedtls_ecdsa_context key = generate_key_pair();
    std::string pk_str = pk_key_to_string(key);
    std::string pub_str = pub_key_to_string(key);

    mbedtls_ecdsa_context key_restored = turn_string_to_key(pk_str, pub_str);

    // 測試恢復的密鑰與原始密鑰相同
    EXPECT_EQ(mbedtls_mpi_cmp_mpi(&key.d, &key_restored.d), 0);
    EXPECT_EQ(mbedtls_ecp_point_cmp(&key.Q, &key_restored.Q), 0);

    mbedtls_ecdsa_free(&key);
    mbedtls_ecdsa_free(&key_restored);
}

TEST(ECDHTest, GenerateRandomStrTest)
{
    std::string random_str = generate_random_str(16); // 生成 16 字節隨機字符串
    EXPECT_EQ(random_str.size(), 16);                 // 測試隨機字符串長度是否正確
}

TEST(ECDHTest, GenerateSha256HashBytesTest)
{
    std::string hash = generate_sha256_hash_bytes("hello");
    string expected_hash = hex_to_byte(hash);
    EXPECT_EQ(hash.size(), 64); // SHA-256 輸出應為 32 字節
}

TEST(ECDHTest, GenerateEcdhKeyTest)
{
    mbedtls_ecdsa_context key = generate_key_pair();
    std::string priv_key = pk_key_to_string(key);
    std::string pub_key = pub_key_to_string(key);

    std::string ecdh_key = generate_ecdh_key(priv_key, pub_key, "salt", "info");
    EXPECT_FALSE(ecdh_key.empty()); // 測試 ECDH 密鑰生成不應為空

    mbedtls_ecdsa_free(&key);
}

TEST(ECDHTest, GcmGenIvTest)
{
    std::string iv = gcm_gen_iv();
    EXPECT_EQ(iv.size(), 12); // 測試 IV 長度為 12 字節 (通常 GCM 使用 96-bit IV)
}

TEST(ECDHTest, GcmEncryptTest)
{
    std::string plaintext = "This is a secret.";
    std::string associated_plaintext = "header";
    std::string session_key = generate_random_str(32); // 32 字節密鑰
    std::string iv = gcm_gen_iv();

    std::string *encrypted_data = gcm_encrypt(plaintext, associated_plaintext, session_key, iv);

    EXPECT_EQ(encrypted_data[0].size(), plaintext.size()); // 測試密文長度
    EXPECT_EQ(encrypted_data[1].size(), 16);               // 測試 GCM 認證標籤長度 (通常為 16 字節)

    delete[] encrypted_data;
}

TEST(ECDHTest, GcmDecryptTest)
{
    std::string plaintext = "This is a secret.";
    std::string associated_plaintext = "header";
    std::string session_key = generate_random_str(32);
    std::string iv = gcm_gen_iv();

    std::string *encrypted_data = gcm_encrypt(plaintext, associated_plaintext, session_key, iv);
    std::string decrypted_text = gcm_decrypt(encrypted_data[0], associated_plaintext, encrypted_data[1], session_key, iv);

    EXPECT_EQ(decrypted_text, plaintext); // 測試解密後的文本應與原始文本相同

    delete[] encrypted_data;
}

// ===================================================================

TEST(ECDHTest, VerifyWithPublicKeyTest)
{
    mbedtls_ecdsa_context key = generate_key_pair();

    string pk = pk_key_to_string(key);
    string pub = pub_key_to_string(key);

    cout << "Private key: " << pk << endl;
    cout << "Public key: " << pub << endl;

    mbedtls_ecdsa_context key2 = turn_string_to_key("", pub);

    size_t global_sig_len;
    unsigned char *signature = sign_message("hello", key, global_sig_len);
    int ret = verify_signature("hello", signature, key2, global_sig_len);

    EXPECT_EQ(ret, 1); // 驗證簽名應該成功
}

int main()
{
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();

    // mbedtls_ecdsa_context key = generate_key_pair();

    // string pk = pk_key_to_string(key);
    // string pub = pub_key_to_string(key);

    // cout << "Private key: " << pk << endl;
    // cout << "Public key: " << pub << endl;

    // mbedtls_ecdsa_context key2 = turn_string_to_key("", pub);

    // size_t global_sig_len;
    // unsigned char *signature = sign_message("hello", key, global_sig_len);
    // int ret = verify_signature("hello", signature, key2, global_sig_len);
    // free(signature);
    // cout << "Signature verification: " << ret << endl;

    // mbedtls_ecdsa_context client_key = generate_key_pair();

    // // use ecdh to generate shared secret
    // // verify shared secret
    // mbedtls_ecdsa_context server_key = generate_key_pair();
    // string shared_secret = generate_ecdh_key(pk_key_to_string(client_key), pub_key_to_string(server_key), "salt", "info");
    // cout << "Shared secret: " << shared_secret << endl;
    // string shared_secret2 = generate_ecdh_key(pk_key_to_string(server_key), pub_key_to_string(client_key), "salt", "info");
    // cout << "Shared secret: " << shared_secret2 << endl;

    return 0;
}