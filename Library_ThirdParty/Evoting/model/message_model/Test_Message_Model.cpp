#include <string>
#include "r_ticket.hpp"
#include "u_ticket.hpp"
#include "message.hpp"

#include "gtest/gtest.h"

TEST(RTicketTest, SerializeRTicketTest)
{
    RTicket ticket;
    ticket.protocol_version = "1.0";
    ticket.r_ticket_id = "123456";
    ticket.r_ticket_type = r_ticket::TYPE_CRKE1_RTICKET;
    ticket.device_id = "device123";
    ticket.result = "success";
    ticket.ticket_order = 1;
    ticket.audit_start = "2021-01-01T00:00:00Z";
    ticket.audit_end = "2021-01-01T00:00:00Z";
    ticket.challenge_1 = "challenge1";
    ticket.challenge_2 = "challenge2";
    ticket.key_exchange_salt_1 = "salt1";
    ticket.key_exchange_salt_2 = "salt2";
    ticket.associated_plaintext_cmd = "cmd";
    ticket.ciphertext_cmd = "ciphertext_cmd";
    ticket.iv_cmd = "iv_cmd";
    ticket.gcm_authentication_tag_cmd = "tag_cmd";
    ticket.associated_plaintext_data = "data";
    ticket.ciphertext_data = "ciphertext_data";
    ticket.iv_data = "iv_data";
    ticket.gcm_authentication_tag_data = "tag_data";
    ticket.device_signature = "signature";

    string json_str = ticket.to_json_str();
    RTicket deserialized_ticket = rticket_from_json_str(json_str);

    EXPECT_EQ(deserialized_ticket.protocol_version, ticket.protocol_version);
    EXPECT_EQ(deserialized_ticket.r_ticket_id, ticket.r_ticket_id);
    EXPECT_EQ(deserialized_ticket.r_ticket_type, ticket.r_ticket_type);
    EXPECT_EQ(deserialized_ticket.device_id, ticket.device_id);
    EXPECT_EQ(deserialized_ticket.result, ticket.result);
    EXPECT_EQ(deserialized_ticket.ticket_order, ticket.ticket_order);
    EXPECT_EQ(deserialized_ticket.audit_start, ticket.audit_start);
    EXPECT_EQ(deserialized_ticket.audit_end, ticket.audit_end);
    EXPECT_EQ(deserialized_ticket.challenge_1, ticket.challenge_1);
    EXPECT_EQ(deserialized_ticket.challenge_2, ticket.challenge_2);
    EXPECT_EQ(deserialized_ticket.key_exchange_salt_1, ticket.key_exchange_salt_1);
    EXPECT_EQ(deserialized_ticket.key_exchange_salt_2, ticket.key_exchange_salt_2);
    EXPECT_EQ(deserialized_ticket.associated_plaintext_cmd, ticket.associated_plaintext_cmd);
    EXPECT_EQ(deserialized_ticket.ciphertext_cmd, ticket.ciphertext_cmd);
    EXPECT_EQ(deserialized_ticket.iv_cmd, ticket.iv_cmd);
    EXPECT_EQ(deserialized_ticket.gcm_authentication_tag_cmd, ticket.gcm_authentication_tag_cmd);
    EXPECT_EQ(deserialized_ticket.associated_plaintext_data, ticket.associated_plaintext_data);
    EXPECT_EQ(deserialized_ticket.ciphertext_data, ticket.ciphertext_data);
    EXPECT_EQ(deserialized_ticket.iv_data, ticket.iv_data);
    EXPECT_EQ(deserialized_ticket.gcm_authentication_tag_data, ticket.gcm_authentication_tag_data);
    EXPECT_EQ(deserialized_ticket.device_signature, ticket.device_signature);
}

TEST(UTicketTest, SerializeUTicketTest)
{
    UTicket ticket;
    ticket.protocol_version = "1.0";
    ticket.u_ticket_id = "123456";
    ticket.u_ticket_type = u_ticket::TYPE_INITIALIZATION_UTICKET;
    ticket.device_id = "device123";
    ticket.ticket_order = 1;
    ticket.holder_id = "holder123";
    ticket.task_scope = "scope123";
    ticket.issuer_signature = "signature";
    ticket.associated_plaintext_cmd = "cmd";
    ticket.ciphertext_cmd = "ciphertext_cmd";
    ticket.gcm_authentication_tag_cmd = "tag_cmd";
    ticket.iv_data = "iv_data";

    string json_str = ticket.to_json_str();
    UTicket deserialized_ticket = uticket_from_json_str(json_str);

    EXPECT_EQ(deserialized_ticket.protocol_version, ticket.protocol_version);
    EXPECT_EQ(deserialized_ticket.u_ticket_id, ticket.u_ticket_id);
    EXPECT_EQ(deserialized_ticket.u_ticket_type, ticket.u_ticket_type);
    EXPECT_EQ(deserialized_ticket.device_id, ticket.device_id);
    EXPECT_EQ(deserialized_ticket.ticket_order, ticket.ticket_order);
    EXPECT_EQ(deserialized_ticket.holder_id, ticket.holder_id);
    EXPECT_EQ(deserialized_ticket.task_scope, ticket.task_scope);
    EXPECT_EQ(deserialized_ticket.issuer_signature, ticket.issuer_signature);
    EXPECT_EQ(deserialized_ticket.associated_plaintext_cmd, ticket.associated_plaintext_cmd);
    EXPECT_EQ(deserialized_ticket.ciphertext_cmd, ticket.ciphertext_cmd);
    EXPECT_EQ(deserialized_ticket.gcm_authentication_tag_cmd, ticket.gcm_authentication_tag_cmd);
    EXPECT_EQ(deserialized_ticket.iv_data, ticket.iv_data);
}

TEST(MessageTest, SerializeMessageTest)
{
    Message msg;
    msg.message_operation = message::MESSAGE_RECV_AND_STORE;
    msg.message_type = "RTicket";
    msg.message_str = "{\"protocol_version\":\"1.0\",\"r_ticket_id\":\"123456\",\"r_ticket_type\":\"CRKE1_RTICKET\",\"device_id\":\"device123\",\"result\":\"success\",\"ticket_order\":1,\"audit_start\":\"2021-01-01T00:00:00Z\",\"audit_end\":\"2021-01-01T00:00:00Z\",\"challenge_1\":\"challenge1\",\"challenge_2\":\"challenge2\",\"key_exchange_salt_1\":\"salt1\",\"key_exchange_salt_2\":\"salt2\",\"associated_plaintext_cmd\":\"cmd\",\"ciphertext_cmd\":\"ciphertext_cmd\",\"iv_cmd\":\"iv_cmd\",\"gcm_authentication_tag_cmd\":\"tag_cmd\",\"associated_plaintext_data\":\"data\",\"ciphertext_data\":\"ciphertext_data\",\"iv_data\":\"iv_data\",\"gcm_authentication_tag_data\":\"tag_data\",\"device_signature\":\"signature\"}";

    string json_str = msg.to_json_str();
    Message deserialized_msg = message_from_json_str(json_str);

    EXPECT_EQ(deserialized_msg.message_operation, msg.message_operation);
    EXPECT_EQ(deserialized_msg.message_type, msg.message_type);
    EXPECT_EQ(deserialized_msg.message_str, msg.message_str);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
