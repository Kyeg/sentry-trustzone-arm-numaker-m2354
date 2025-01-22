
#include <string>
#include <map>
#include "current_session.hpp"
#include "other_device.hpp"
#include "this_device.hpp"
#include "this_person.hpp"
#include "ecdsa.h"
#include "myecdh.hpp"
#include "r_ticket.hpp"
#include "u_ticket.hpp"
#include "message.hpp"

string CurrentSession::to_json()
{
    json j;
    if (!current_u_ticket_id.empty())
        j["current_u_ticket_id"] = current_u_ticket_id;
    if (!current_device_id.empty())
        j["current_device_id"] = current_device_id;
    if (!current_holder_id.empty())
        j["current_holder_id"] = current_holder_id;
    if (!current_task_scope.empty())
        j["current_task_scope"] = current_task_scope;

    if (!challenge_1.empty())
        j["challenge_1"] = challenge_1;
    if (!challenge_2.empty())
        j["challenge_2"] = challenge_2;
    if (!key_exchange_salt_1.empty())
        j["key_exchange_salt_1"] = key_exchange_salt_1;
    if (!key_exchange_salt_2.empty())
        j["key_exchange_salt_2"] = key_exchange_salt_2;

    if (!current_session_key_str.empty())
        j["current_session_key_str"] = current_session_key_str;
    if (!plaintext_cmd.empty())
        j["plaintext_cmd"] = plaintext_cmd;
    if (!associated_plaintext_cmd.empty())
        j["associated_plaintext_cmd"] = associated_plaintext_cmd;
    if (!iv_cmd.empty())
        j["iv_cmd"] = iv_cmd;
    if (!ciphertext_cmd.empty())
        j["ciphertext_cmd"] = ciphertext_cmd;
    if (!gcm_authentication_tag_cmd.empty())
        j["gcm_authentication_tag_cmd"] = gcm_authentication_tag_cmd;

    if (!plaintext_data.empty())
        j["plaintext_data"] = plaintext_data;
    if (!associated_plaintext_data.empty())
        j["associated_plaintext_data"] = associated_plaintext_data;
    if (!iv_data.empty())
        j["iv_data"] = iv_data;
    if (!ciphertext_data.empty())
        j["ciphertext_data"] = ciphertext_data;
    return j.dump();
}

CurrentSession json_to_current_session(json j)
{
    CurrentSession session;

    if (j.find("current_u_ticket_id") != j.end())
        session.current_u_ticket_id = j["current_u_ticket_id"];
    if (j.find("current_device_id") != j.end())
        session.current_device_id = j["current_device_id"];
    if (j.find("current_holder_id") != j.end())
        session.current_holder_id = j["current_holder_id"];
    if (j.find("current_task_scope") != j.end())
        session.current_task_scope = j["current_task_scope"];

    if (j.find("challenge_1") != j.end())
        session.challenge_1 = j["challenge_1"];
    if (j.find("challenge_2") != j.end())
        session.challenge_2 = j["challenge_2"];
    if (j.find("key_exchange_salt_1") != j.end())
        session.key_exchange_salt_1 = j["key_exchange_salt_1"];
    if (j.find("key_exchange_salt_2") != j.end())
        session.key_exchange_salt_2 = j["key_exchange_salt_2"];

    if (j.find("current_session_key_str") != j.end())
        session.current_session_key_str = j["current_session_key_str"];
    if (j.find("plaintext_cmd") != j.end())
        session.plaintext_cmd = j["plaintext_cmd"];
    if (j.find("associated_plaintext_cmd") != j.end())
        session.associated_plaintext_cmd = j["associated_plaintext_cmd"];
    if (j.find("iv_cmd") != j.end())
        session.iv_cmd = j["iv_cmd"];
    if (j.find("ciphertext_cmd") != j.end())
        session.ciphertext_cmd = j["ciphertext_cmd"];
    if (j.find("gcm_authentication_tag_cmd") != j.end())
        session.gcm_authentication_tag_cmd = j["gcm_authentication_tag_cmd"];

    if (j.find("plaintext_data") != j.end())
        session.plaintext_data = j["plaintext_data"];
    if (j.find("associated_plaintext_data") != j.end())
        session.associated_plaintext_data = j["associated_plaintext_data"];
    if (j.find("iv_data") != j.end())
        session.iv_data = j["iv_data"];
    if (j.find("ciphertext_data") != j.end())
        session.ciphertext_data = j["ciphertext_data"];
    if (j.find("gcm_authentication_tag_data") != j.end())
        session.gcm_authentication_tag_data = j["gcm_authentication_tag_data"];

    return session;
}

string OtherDevice::to_json()
{
    json j;
    j["device_id"] = device_id;
    j["ticket_order"] = ticket_order;
    // j["device_u_ticket_for_owner"] = device_u_ticket_for_owner;
    // j["device_ownership_u_ticket_for_others"] = device_ownership_u_ticket_for_others;
    // j["device_access_u_ticket_for_others"] = device_access_u_ticket_for_others;
    // j["device_r_ticket_for_owner"] = device_r_ticket_for_owner;
    // j["device_ownership_r_ticket_for_others"] = device_ownership_r_ticket_for_others;
    // j["device_access_end_r_ticket_for_others"] = device_access_end_r_ticket_for_others;
    return j.dump();
}

OtherDevice json_to_other_device(json j)
{
    OtherDevice device;
    device.device_id = j["device_id"];
    device.ticket_order = j["ticket_order"];
    device.device_u_ticket_for_owner = j["device_u_ticket_for_owner"];
    device.device_ownership_u_ticket_for_others = j["device_ownership_u_ticket_for_others"];
    device.device_access_u_ticket_for_others = j["device_access_u_ticket_for_others"];
    device.device_r_ticket_for_owner = j["device_r_ticket_for_owner"];
    device.device_ownership_r_ticket_for_others = j["device_ownership_r_ticket_for_others"];
    device.device_access_end_r_ticket_for_others = j["device_access_end_r_ticket_for_others"];
    return device;
}

mbedtls_ecdsa_context ThisDevice::strings_to_pp_keys()
{
    return turn_string_to_key(device_priv_key, device_pub_key);
}

string ThisDevice::to_json()
{
    json j;
    j["device_priv_key"] = device_priv_key;
    j["device_pub_key"] = device_pub_key;
    j["owner_pub_key"] = owner_pub_key;
    j["device_type"] = device_type;
    j["device_name"] = device_name;
    j["has_device_type"] = has_device_type;
    j["ticket_order"] = ticket_order;
    return j.dump();
}

ThisDevice json_to_this_device(json j)
{
    ThisDevice device;
    device.device_priv_key = j["device_priv_key"];
    device.device_pub_key = j["device_pub_key"];
    device.owner_pub_key = j["owner_pub_key"];
    device.device_type = j["device_type"];
    device.device_name = j["device_name"];
    device.has_device_type = j["has_device_type"];
    device.ticket_order = j["ticket_order"];
    return device;
}

mbedtls_ecdsa_context ThisPerson::strings_to_pp_keys()
{
    return turn_string_to_key(person_priv_key, person_pub_key);
}

// turn class into json
string ThisPerson::to_json()
{
    // use nlohmann json library
    json j;
    j["person_priv_key"] = person_priv_key;
    j["person_pub_key"] = person_pub_key;
    string json_str = j.dump();
    return json_str;
}

ThisPerson json_to_this_person(json j)
{
    ThisPerson person;
    person.person_priv_key = j["person_priv_key"];
    person.person_pub_key = j["person_pub_key"];
    return person;
}

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

Message message_from_json_str(const string &json_str)
{
    printf("info: inside message_from_json_str %s\n", json_str.c_str());
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