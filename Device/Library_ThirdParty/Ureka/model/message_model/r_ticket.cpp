#include <string>
#include "r_ticket.hpp"
#include "u_ticket.hpp"
#include "message.hpp"

string RTicket::to_json_str() const
{
    json j;
    // Serialize all optional fields if they are set
    if (protocol_version != "")
        j["protocol_version"] = protocol_version;
    if (r_ticket_id != "")
        j["r_ticket_id"] = r_ticket_id;
    if (r_ticket_type != "")
        j["r_ticket_type"] = r_ticket_type;
    if (device_id != "")
        j["device_id"] = device_id;
    if (result != "")
        j["result"] = result;
    j["ticket_order"] = ticket_order;
    if (audit_start != "")
        j["audit_start"] = audit_start;
    if (audit_end != "")
        j["audit_end"] = audit_end;
    if (challenge_1 != "")
        j["challenge_1"] = challenge_1;
    if (challenge_2 != "")
        j["challenge_2"] = challenge_2;
    if (key_exchange_salt_1 != "")
        j["key_exchange_salt_1"] = key_exchange_salt_1;
    if (key_exchange_salt_2 != "")
        j["key_exchange_salt_2"] = key_exchange_salt_2;
    if (associated_plaintext_cmd != "")
        j["associated_plaintext_cmd"] = associated_plaintext_cmd;
    if (ciphertext_cmd != "")
        j["ciphertext_cmd"] = ciphertext_cmd;
    if (iv_cmd != "")
        j["iv_cmd"] = iv_cmd;
    if (gcm_authentication_tag_cmd != "")
        j["gcm_authentication_tag_cmd"] = gcm_authentication_tag_cmd;
    if (associated_plaintext_data != "")
        j["associated_plaintext_data"] = associated_plaintext_data;
    if (ciphertext_data != "")
        j["ciphertext_data"] = ciphertext_data;
    if (iv_data != "")
        j["iv_data"] = iv_data;
    if (gcm_authentication_tag_data != "")
        j["gcm_authentication_tag_data"] = gcm_authentication_tag_data;
    if (device_signature != "")
        j["device_signature"] = device_signature;
    // Add other fields similarly...

    return j.dump(4); // Indentation of 4 spaces
}

RTicket rticket_from_json_str(string json_str)
{
    json j = json::parse(json_str);

    // check every field and set it if it exists

    RTicket ticket;

    if (j.contains("protocol_version"))
        ticket.protocol_version = j["protocol_version"];
    if (j.contains("r_ticket_id"))
        ticket.r_ticket_id = j["r_ticket_id"];
    if (j.contains("r_ticket_type"))
        ticket.r_ticket_type = j["r_ticket_type"];
    if (j.contains("device_id"))
        ticket.device_id = j["device_id"];
    if (j.contains("result"))
        ticket.result = j["result"];
    if (j.contains("ticket_order"))
        ticket.ticket_order = j["ticket_order"];
    if (j.contains("audit_start"))
        ticket.audit_start = j["audit_start"];
    if (j.contains("audit_end"))
        ticket.audit_end = j["audit_end"];
    if (j.contains("challenge_1"))
        ticket.challenge_1 = j["challenge_1"];
    if (j.contains("challenge_2"))
        ticket.challenge_2 = j["challenge_2"];
    if (j.contains("key_exchange_salt_1"))
        ticket.key_exchange_salt_1 = j["key_exchange_salt_1"];
    if (j.contains("key_exchange_salt_2"))
        ticket.key_exchange_salt_2 = j["key_exchange_salt_2"];
    if (j.contains("associated_plaintext_cmd"))
        ticket.associated_plaintext_cmd = j["associated_plaintext_cmd"];
    if (j.contains("ciphertext_cmd"))
        ticket.ciphertext_cmd = j["ciphertext_cmd"];
    if (j.contains("iv_cmd"))
        ticket.iv_cmd = j["iv_cmd"];
    if (j.contains("gcm_authentication_tag_cmd"))
        ticket.gcm_authentication_tag_cmd = j["gcm_authentication_tag_cmd"];
    if (j.contains("associated_plaintext_data"))
        ticket.associated_plaintext_data = j["associated_plaintext_data"];
    if (j.contains("ciphertext_data"))
        ticket.ciphertext_data = j["ciphertext_data"];
    if (j.contains("iv_data"))
        ticket.iv_data = j["iv_data"];
    if (j.contains("gcm_authentication_tag_data"))
        ticket.gcm_authentication_tag_data = j["gcm_authentication_tag_data"];
    if (j.contains("device_signature"))
        ticket.device_signature = j["device_signature"];
    // Add other fields similarly...
    return ticket;
}

void RTicket::validate_json(const json &j)
{
    // Implement validation logic here
    // For example, check for required fields, types, etc.
}

std::string UTicket::to_json_str() const
{
    json j;
    if (protocol_version != "")
        j["protocol_version"] = protocol_version;
    if (u_ticket_id != "")
        j["u_ticket_id"] = u_ticket_id;
    if (u_ticket_type != "")
        j["u_ticket_type"] = u_ticket_type;
    if (device_id != "")
        j["device_id"] = device_id;
    j["ticket_order"] = ticket_order;
    if (holder_id != "")
        j["holder_id"] = holder_id;
    if (task_scope != "")
        j["task_scope"] = task_scope;
    if (issuer_signature != "")
        j["issuer_signature"] = issuer_signature;
    if (associated_plaintext_cmd != "")
        j["associated_plaintext_cmd"] = associated_plaintext_cmd;
    if (ciphertext_cmd != "")
        j["ciphertext_cmd"] = ciphertext_cmd;
    if (gcm_authentication_tag_cmd != "")
        j["gcm_authentication_tag_cmd"] = gcm_authentication_tag_cmd;
    if (iv_data != "")
        j["iv_data"] = iv_data;

    return j.dump(4); // Indentation of 4 spaces
}

UTicket uticket_from_json_str(std::string json_str)
{
    json j = json::parse(json_str);

    UTicket ticket;
    if (j.contains("protocol_version"))
        ticket.protocol_version = j["protocol_version"];
    if (j.contains("u_ticket_id"))
        ticket.u_ticket_id = j["u_ticket_id"];
    if (j.contains("u_ticket_type"))
        ticket.u_ticket_type = j["u_ticket_type"];
    if (j.contains("device_id"))
        ticket.device_id = j["device_id"];
    if (j.contains("ticket_order"))
        ticket.ticket_order = j["ticket_order"];
    if (j.contains("holder_id"))
        ticket.holder_id = j["holder_id"];
    if (j.contains("task_scope"))
        ticket.task_scope = j["task_scope"];
    if (j.contains("issuer_signature"))
        ticket.issuer_signature = j["issuer_signature"];
    if (j.contains("associated_plaintext_cmd"))
        ticket.associated_plaintext_cmd = j["associated_plaintext_cmd"];
    if (j.contains("ciphertext_cmd"))
        ticket.ciphertext_cmd = j["ciphertext_cmd"];
    if (j.contains("gcm_authentication_tag_cmd"))
        ticket.gcm_authentication_tag_cmd = j["gcm_authentication_tag_cmd"];
    if (j.contains("iv_data"))
        ticket.iv_data = j["iv_data"];

    return ticket;
}

void UTicket::validate_json(const json &j)
{
    // Implement validation logic here
    // For example, check for required fields, types, etc.
}

string Message::to_json_str() const
{
    json j;
    if (message_operation != "")
        j["message_operation"] = message_operation;
    if (message_type != "")
        j["message_type"] = message_type;
    if (message_str != "")
        j["message_str"] = message_str;

    return j.dump(4); // Indentation of 4 spaces
}

Message message_from_json_str(const std::string &json_str)
{
    json j = json::parse(json_str);
    // validate_json(j);÷
    Message msg;
    if (j.contains("message_operation"))
        msg.message_operation = j["message_operation"];
    if (j.contains("message_type"))
        msg.message_type = j["message_type"];
    if (j.contains("message_str"))
        msg.message_str = j["message_str"];
    return msg;
}

void Message::validate_json(const json &j)
{
    // Implement validation logic here
    // For example, check for required fields, types, etc.
}