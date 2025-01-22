#include "u_ticket.hpp"

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