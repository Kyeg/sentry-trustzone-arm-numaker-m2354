#include <string>
#include <iostream>
#include <gtest/gtest.h>

#include "this_device.hpp"
#include "other_device.hpp"
#include "this_person.hpp"
#include "current_session.hpp"
#include "../../resource/crypto/ecdh.hpp"
#include "../../resource/crypto/ecc.hpp"
#include "mbedtls/ecdsa.h"

// this_device.cpp test=======================================================

// 測試 key pair轉換

TEST(ThisDeviceTest, StringsToPpKeysTest)
{
    ThisDevice device;
    // 生成 key pair
    mbedtls_ecdsa_context keys = generate_key_pair();
    device.device_priv_key = pk_key_to_string(keys);
    device.device_pub_key = pub_key_to_string(keys);

    mbedtls_ecdsa_free(&keys); // 釋放記憶體

    // 轉換 key pair
    mbedtls_ecdsa_context key = device.strings_to_pp_keys();
    EXPECT_EQ(key.grp.nbits, 256); // 驗證 key 的大小是否為 256 位元
    mbedtls_ecdsa_free(&key);      // 釋放記憶體
}

// 測試 ThisDevice 轉換成 JSON 字串

TEST(ThisDeviceTest, ToJsonTest)
{
    ThisDevice device;
    device.device_priv_key = "device_priv_key";
    device.device_pub_key = "device_pub_key";
    device.owner_pub_key = "owner_pub_key";
    device.device_type = "device_type";
    device.device_name = "device_name";
    device.has_device_type = true;
    device.ticket_order = 1;

    std::string json_str = device.to_json();
    EXPECT_FALSE(json_str.empty()); // 測試轉換後的 JSON 字串不應為空
}

// 測試 JSON 字串轉換成 ThisDevice

TEST(ThisDeviceTest, JsonToThisDeviceTest)
{
    json j;
    j["device_priv_key"] = "device_priv_key";
    j["device_pub_key"] = "device_pub_key";
    j["owner_pub_key"] = "owner_pub_key";
    j["device_type"] = "device_type";
    j["device_name"] = "device_name";
    j["has_device_type"] = true;
    j["ticket_order"] = 1;

    ThisDevice device = json_to_this_device(j);
    EXPECT_EQ(device.device_priv_key, "device_priv_key");
    EXPECT_EQ(device.device_pub_key, "device_pub_key");
    EXPECT_EQ(device.owner_pub_key, "owner_pub_key");
    EXPECT_EQ(device.device_type, "device_type");
    EXPECT_EQ(device.device_name, "device_name");
    EXPECT_EQ(device.has_device_type, true);
    EXPECT_EQ(device.ticket_order, 1);
}

// other_device.cpp test=======================================================

// 測試轉換成 JSON 字串

TEST(OtherDeviceTest, ToJsonTest)
{
    OtherDevice device;
    device.device_id = "device_id";
    device.ticket_order = 1;
    device.device_u_ticket_for_owner = "device_u_ticket_for_owner";
    device.device_ownership_u_ticket_for_others = "device_ownership_u_ticket_for_others";
    device.device_access_u_ticket_for_others = "device_access_u_ticket_for_others";
    device.device_r_ticket_for_owner = "device_r_ticket_for_owner";
    device.device_ownership_r_ticket_for_others = "device_ownership_r_ticket_for_others";
    device.device_access_end_r_ticket_for_others = "device_access_end_r_ticket_for_others";

    std::string json_str = device.to_json();
    EXPECT_FALSE(json_str.empty()); // 測試轉換後的 JSON 字串不應為空
}

// 測試 JSON 字串轉換成 OtherDevice

TEST(OtherDeviceTest, JsonToOtherDeviceTest)
{
    json j;
    j["device_id"] = "device_id";
    j["ticket_order"] = 1;
    j["device_u_ticket_for_owner"] = "device_u_ticket_for_owner";
    j["device_ownership_u_ticket_for_others"] = "device_ownership_u_ticket_for_others";
    j["device_access_u_ticket_for_others"] = "device_access_u_ticket_for_others";
    j["device_r_ticket_for_owner"] = "device_r_ticket_for_owner";
    j["device_ownership_r_ticket_for_others"] = "device_ownership_r_ticket_for_others";
    j["device_access_end_r_ticket_for_others"] = "device_access_end_r_ticket_for_others";

    OtherDevice device = json_to_other_device(j);
    EXPECT_EQ(device.device_id, "device_id");
    EXPECT_EQ(device.ticket_order, 1);
    EXPECT_EQ(device.device_u_ticket_for_owner, "device_u_ticket_for_owner");
    EXPECT_EQ(device.device_ownership_u_ticket_for_others, "device_ownership_u_ticket_for_others");
    EXPECT_EQ(device.device_access_u_ticket_for_others, "device_access_u_ticket_for_others");
    EXPECT_EQ(device.device_r_ticket_for_owner, "device_r_ticket_for_owner");
    EXPECT_EQ(device.device_ownership_r_ticket_for_others, "device_ownership_r_ticket_for_others");
    EXPECT_EQ(device.device_access_end_r_ticket_for_others, "device_access_end_r_ticket_for_others");
}

// this_person.cpp test=======================================================

// 測試 key pair轉換

TEST(ThisPersonTest, StringsToPpKeysTest)
{
    ThisPerson person;
    // 生成 key pair
    mbedtls_ecdsa_context keys = generate_key_pair();
    person.person_priv_key = pk_key_to_string(keys);
    person.person_pub_key = pub_key_to_string(keys);

    mbedtls_ecdsa_free(&keys); // 釋放記憶體

    // 轉換 key pair
    mbedtls_ecdsa_context key = person.strings_to_pp_keys();
    EXPECT_EQ(key.grp.nbits, 256); // 驗證 key 的大小是否為 256 位元
    mbedtls_ecdsa_free(&key);      // 釋放記憶體
}

// 測試轉換成 JSON 字串

TEST(ThisPersonTest, ToJsonTest)
{
    ThisPerson person;
    person.person_priv_key = "person_priv_key";
    person.person_pub_key = "person_pub_key";

    std::string json_str = person.to_json();
    EXPECT_FALSE(json_str.empty()); // 測試轉換後的 JSON 字串不應為空
}

// 測試 JSON 字串轉換成 ThisPerson

TEST(ThisPersonTest, JsonToThisPersonTest)
{
    json j;
    j["person_priv_key"] = "person_priv_key";
    j["person_pub_key"] = "person_pub_key";

    ThisPerson person = json_to_this_person(j);
    EXPECT_EQ(person.person_priv_key, "person_priv_key");
    EXPECT_EQ(person.person_pub_key, "person_pub_key");
}

// current_session.cpp test=======================================================
// 測試轉換成 JSON 字串

TEST(CurrentSessionTest, ToJsonTest)
{
    CurrentSession session;
    session.current_u_ticket_id = "current_u_ticket_id";
    session.current_device_id = "current_device_id";
    session.current_holder_id = "current_holder_id";
    session.current_task_scope = "current_task_scope";

    std::string json_str = session.to_json();
    EXPECT_FALSE(json_str.empty()); // 測試轉換後的 JSON 字串不應為空
}

// 測試 JSON 字串轉換成 CurrentSession

TEST(CurrentSessionTest, JsonToCurrentSessionTest)
{
    json j;
    j["current_u_ticket_id"] = "current_u_ticket_id";
    j["current_device_id"] = "current_device_id";
    j["current_holder_id"] = "current_holder_id";
    j["current_task_scope"] = "current_task_scope";

    CurrentSession session = json_to_current_session(j);
    EXPECT_EQ(session.current_u_ticket_id, "current_u_ticket_id");
    EXPECT_EQ(session.current_device_id, "current_device_id");
    EXPECT_EQ(session.current_holder_id, "current_holder_id");
    EXPECT_EQ(session.current_task_scope, "current_task_scope");
}

// ============================================================================

int main(int argc, char **argv)
{
    cout << "Model test" << endl;
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
