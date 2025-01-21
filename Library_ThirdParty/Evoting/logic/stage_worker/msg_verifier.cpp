#include "msg_verifier.hpp"
#include "msg_verifier_u_ticket.hpp"
#include "msg_verifier_r_ticket.hpp"
#include "msg_verifier_message.hpp"
#include "myecdh.hpp"

extern "C"
{
    extern int verify_signature(const char *message, const unsigned char *signature, mbedtls_ecdsa_context keys, int signature_len);
}

pair<UTicket, RTicket> MsgVerifier::self_classify_message_is_defined_type(string arbitrary_json)
{
    printf("info %s is classifying message...\n", shared_data->this_device.device_name.c_str());

    MessageVerifier message_verifier(shared_data->this_device);
    printf("do you finish verifying msg?\n");
    Message message_in = message_verifier.verify_json_schema(arbitrary_json);
    message_in = message_verifier.verify_message_operation(message_in);
    message_in = message_verifier.verify_message_type(message_in);
    message_in = message_verifier.verify_message_str(message_in);

    printf("do you finish verifying msg?\n");

    if (message_in.message_type == u_ticket::MESSAGE_TYPE)
    {
        return make_pair(self_classify_u_ticket_is_defined_type(message_in.message_str), RTicket());
    }
    else if (message_in.message_type == r_ticket::MESSAGE_TYPE)
    {
        return make_pair(UTicket(), self_classify_r_ticket_is_defined_type(message_in.message_str));
    }
    else
    {
        printf("throw\n");
        throw std::runtime_error("-> FAILURE: CLASSIFY_MESSAGE_IS_DEFINED_TYPE");
    }
}

UTicket MsgVerifier::self_classify_u_ticket_is_defined_type(string arbitrary_json)
{
    printf("info %s is classifying u_ticket...\n", shared_data->this_device.device_name.c_str());

    ThisDevice this_device;
    UTicketVerifier u_ticket_verifier(this_device);

    // cout << "info: " << arbitrary_json << "\n";

    UTicket u_ticket_in = u_ticket_verifier.verify_json_schema(arbitrary_json);
    u_ticket_in = u_ticket_verifier.verify_protocol_version(u_ticket_in);
    u_ticket_in = u_ticket_verifier.verify_u_ticket_id(u_ticket_in);
    u_ticket_in = u_ticket_verifier.verify_u_ticket_type(u_ticket_in);
    u_ticket_in = u_ticket_verifier.has_device_id(u_ticket_in);

    string u_ticket_str = u_ticket_in.to_json_str();

    return u_ticket_in;
}

RTicket MsgVerifier::self_classify_r_ticket_is_defined_type(string arbitrary_json)
{
    printf("info %s is classifying r_ticket...\n", shared_data->this_device.device_name.c_str());

    RTicketVerifier r_ticket_verifier(shared_data->this_device);

    RTicket r_ticket_in = r_ticket_verifier.verify_json_schema(arbitrary_json);
    r_ticket_in = r_ticket_verifier.verify_protocol_version(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_r_ticket_type(r_ticket_in);
    r_ticket_in = r_ticket_verifier.has_device_id(r_ticket_in);

    return r_ticket_in;
}

void MsgVerifier::verify_u_ticket_can_execute(UTicket u_ticket_in)
{
    // cout << "show me your ass: " << u_ticket_in.to_json_str();
    printf("info %s is verifying u_ticket can execute\n", shared_data->this_device.device_name.c_str());

    UTicketVerifier u_ticket_verifier(shared_data->this_device);

    u_ticket_in = u_ticket_verifier.verify_device_id(u_ticket_in);
    u_ticket_in = u_ticket_verifier.verify_ticket_order(u_ticket_in);
    u_ticket_in = u_ticket_verifier.verify_holder_id(u_ticket_in);
    u_ticket_in = u_ticket_verifier.verify_task_scope(u_ticket_in);
    u_ticket_in = u_ticket_verifier.verify_ps(u_ticket_in);
    u_ticket_in = u_ticket_verifier.verify_issuer_signature(u_ticket_in);

    return;
}

void MsgVerifier::verify_u_ticket_has_executed_through_r_ticket(RTicket r_ticket_in, UTicket audit_start_ticket, UTicket audit_end_ticket)
{
    printf("info %s is verifying u_ticket has exectued through r_ticket\n", shared_data->this_device.device_name.c_str());

    RTicketVerifier r_ticket_verifier(shared_data->this_device, audit_start_ticket, audit_end_ticket, shared_data->device_table, shared_data->current_session);

    r_ticket_in = r_ticket_verifier.verify_device_id(r_ticket_in);

    // cout << "debug: " << "r_ticket_in result: " << r_ticket_in.result << "\n";
    // cout << "debug: " << "r_ticket_in: " << r_ticket_in.to_json_str() << "\n";
    r_ticket_in = r_ticket_verifier.verify_result(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_ticket_order(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_audit_start(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_audit_end(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_cr_key(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_ps(r_ticket_in);
    r_ticket_in = r_ticket_verifier.verify_device_signature(r_ticket_in);

    return;
}

void MsgVerifier::verify_cmd_is_in_task_scope(string cmd)
{
    string success_msg = "-> SUCCESS: VERIFY_CMD_IN_TASK_SCOPE";
    string failure_msg = "-> FAILURE: VERIFY_CMD_IN_TASK_SCOPE";

    json task_scope = json::parse(shared_data->current_session.current_task_scope);

    // if (task_scope.find("ALL") == "allow")

    if (task_scope.find("ALL") != task_scope.end() && task_scope["ALL"] == "allow")
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else if (cmd == "HELLO-1" && (task_scope.find("SAY-HELLO-1") != task_scope.end() && task_scope["SAY-HELLO-1"] == "allow"))
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else if (cmd == "HELLO-2" && (task_scope.find("SAY-HELLO-2") != task_scope.end() && task_scope["SAY-HELLO-2"] == "allow"))
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else if (cmd == "HELLO-3" && (task_scope.find("SAY-HELLO-3") != task_scope.end() && task_scope["SAY-HELLO-3"] == "allow"))
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        printf("error: %s\n", failure_msg.c_str());
        throw std::runtime_error(failure_msg);
    }

    return;
}

UTicket UTicketVerifier::verify_json_schema(string arbitrary_json)
{
    string success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA";
    string fail_msg = "-> FAILURE: VERIFY_JSON_SCHEMA";

    UTicket u_ticket_in;
    try
    {
        u_ticket_in = uticket_from_json_str(arbitrary_json);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(fail_msg + ": " + e.what());
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_protocol_version(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PROTOCOL_VERSION";
    string fail_msg = "-> FAILURE: VERIFY_PROTOCOL_VERSION";

    if (u_ticket_in.protocol_version == u_ticket::PROTOCOL_VERSION)
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_u_ticket_id(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_U_TICKET_ID";
    string fail_msg = "-> FAILURE: VERIFY_U_TICKET_ID";

    UTicket ticket_without_id_and_sig = u_ticket_in;

    ticket_without_id_and_sig.u_ticket_id = "";
    ticket_without_id_and_sig.issuer_signature = "";

    string ticket_without_id_and_sig_str = ticket_without_id_and_sig.to_json_str();

    unsigned char sha256_hash[32];
    string hash_str = "";

    if (mbedtls_sha256_ret((const unsigned char *)ticket_without_id_and_sig_str.c_str(), ticket_without_id_and_sig_str.length(), sha256_hash, 0) == 0)
    {
        hash_str = byte_to_hex(sha256_hash, 32);
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    if (hash_str == u_ticket_in.u_ticket_id)
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return u_ticket_in;
}

UTicket UTicketVerifier::verify_u_ticket_type(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_U_TICKET_TYPE";
    string fail_msg = "-> FAILURE: VERIFY_U_TICKET_TYPE";

    if (u_ticket::LEGAL_UTICKET_TYPES.find(u_ticket_in.u_ticket_type) != u_ticket::LEGAL_UTICKET_TYPES.end())
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::has_device_id(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: HAS_DEVICE_ID";
    string fail_msg = "-> FAILURE: HAS_DEVICE_ID";

    if (u_ticket_in.device_id != "")
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_device_id(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_DEVICE_ID";
    string fail_msg = "-> FAILURE: VERIFY_DEVICE_ID";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        if (u_ticket_in.device_id == "no_id")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (
        u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (u_ticket_in.device_id == this_device.device_pub_key)
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_ticket_order(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_TICKET_ORDER";
    string fail_msg = "-> FAILURE: VERIFY_TICKET_ORDER";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        if (this_device.ticket_order == 0)
        {
            if (u_ticket_in.ticket_order == 0)
            {
                printf("%s\n", success_msg.c_str());
            }
            else
            {
                throw std::runtime_error(fail_msg);
            }
        }
        else if (this_device.ticket_order > 0)
        {
            printf("-> FAILURE: VERIFY_TICKET_ORDER: IOT_DEVICE ALREADY INITIALIZED\n");
            throw std::runtime_error("-> FAILURE: VERIFY_TICKET_ORDER: IOT_DEVICE ALREADY INITIALIZED");
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        if (this_device.ticket_order == u_ticket_in.ticket_order)
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_holder_id(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_HOLDER_ID";
    string fail_msg = "-> FAILURE: VERIFY_HOLDER_ID";

    if (
        u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
    {
        if (u_ticket_in.holder_id != "")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (
        u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        if (u_ticket_in.holder_id == this_device.owner_pub_key)
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_task_scope(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_TASK_SCOPE";
    string fail_msg = "-> FAILURE: VERIFY_TASK_SCOPE";

    if (
        u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        printf("%s\n", success_msg.c_str());
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
    {
        if (u_ticket_in.task_scope != "")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        json j;
        j["ALL"] = "allow";
        if (u_ticket_in.task_scope == j.dump())
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_ps(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PS";
    string fail_msg = "-> FAILURE: VERIFY_PS";

    if (
        u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        printf("%s\n", success_msg.c_str());
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (u_ticket_in.associated_plaintext_cmd != "" && u_ticket_in.ciphertext_cmd != "" && u_ticket_in.iv_data != "" && u_ticket_in.gcm_authentication_tag_cmd != "")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return u_ticket_in;
}

UTicket UTicketVerifier::verify_issuer_signature(UTicket u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_ISSUER_SIGNATURE";
    string fail_msg = "-> FAILURE: VERIFY_ISSUER_SIGNATURE";

    if (
        u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        printf("%s\n", success_msg.c_str());
    }
    else if (
        u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        if (self_verify_issuer_signature_on_u_ticket(u_ticket_in, this_device.owner_pub_key))
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
            ;
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }

    return u_ticket_in;
}

bool UTicketVerifier::self_verify_issuer_signature_on_u_ticket(UTicket signed_u_ticket, string public_key)
{
    string success_msg = "-> SUCCESS: SELF_VERIFY_ISSUER_SIGNATURE_ON_U_TICKET";
    string fail_msg = "-> FAILURE: SELF_VERIFY_ISSUER_SIGNATURE_ON_U_TICKET";

    string issuer_signature = hex_to_byte(signed_u_ticket.issuer_signature);
    signed_u_ticket.issuer_signature = "";

    mbedtls_ecdsa_context keys = turn_string_to_key("", public_key);

    // verify signature
    if (verify_signature(signed_u_ticket.to_json_str().c_str(), (unsigned char *)issuer_signature.c_str(), keys, issuer_signature.length()))
    {
        printf("%s\n", success_msg.c_str());
        return true;
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
        return false;
    }
}

RTicket RTicketVerifier::verify_json_schema(string arbitrary_json)
{
    string success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA";
    string failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA";
    // Verify JSON Schema
    RTicket r_ticket_in;
    try
    {
        r_ticket_in = rticket_from_json_str(arbitrary_json);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(failure_msg + " : " + e.what());
    }

    return r_ticket_in;
}

RTicket RTicketVerifier::verify_protocol_version(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PROTOCOL_VERSION";
    string failure_msg = "-> FAILURE: VERIFY_PROTOCOL_VERSION";
    // Verify Protocol Version
    if (r_ticket_in.protocol_version == u_ticket::PROTOCOL_VERSION)
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }

    return r_ticket_in;
}

RTicket RTicketVerifier::verify_r_ticket_id(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_R_TICKET_ID";
    string failure_msg = "-> FAILURE: VERIFY_R_TICKET_ID";
    // Verify R-Ticket ID (Hash-based)
    RTicket r_ticket_out = r_ticket_in;

    r_ticket_out.r_ticket_id = "";
    r_ticket_out.device_signature = "";

    unsigned char hash[32];
    string hash_str = "";
    string message = r_ticket_out.to_json_str();

    if (mbedtls_sha256_ret((const unsigned char *)message.c_str(), message.length(), hash, 0) != 0)
    {
        throw std::runtime_error(failure_msg);
    }
    else
    {
        printf("info: %s\n", success_msg.c_str());
        hash_str = byte_to_hex(hash, 32);
        r_ticket_in.r_ticket_id = hash_str;
    }

    if (hash_str == r_ticket_in.r_ticket_id)
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }

    return r_ticket_in;
}

RTicket RTicketVerifier::verify_r_ticket_type(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_R_TICKET_TYPE";
    string failure_msg = "-> FAILURE: VERIFY_R_TICKET_TYPE";
    // Verify R-Ticket Type

    if (r_ticket::LEGAL_RTICKET_TYPES.find(r_ticket_in.r_ticket_type) != r_ticket::LEGAL_RTICKET_TYPES.end())
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }

    return r_ticket_in;
}

RTicket RTicketVerifier::has_device_id(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: HAS_DEVICE_ID";
    string failure_msg = "-> FAILURE: HAS_DEVICE_ID";
    // Check if R-Ticket has Device ID
    if (r_ticket_in.device_id != "")
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }

    return r_ticket_in;
}

RTicket RTicketVerifier::verify_device_id(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_DEVICE_ID";
    string failure_msg = "-> FAILURE: VERIFY_DEVICE_ID";
    // Verify Device ID
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        // u_ticket_device_id = "no_id"
        // r_ticket_device_id = "newly_created_device public key string"

        printf("info: %s\n", success_msg.c_str());
        return r_ticket_in;
    }
    else if (
        r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (r_ticket_in.device_id == audit_start_ticket.device_id)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket::LEGAL_CRKE_TYPES.find(r_ticket_in.r_ticket_type) != r_ticket::LEGAL_CRKE_TYPES.end())
    {
        if (r_ticket_in.device_id == current_session.current_device_id)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else
    {
        throw std::runtime_error(failure_msg);
        return r_ticket_in;
    }
}

RTicket RTicketVerifier::verify_result(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_RESULT";
    string failure_msg = "-> FAILURE: VERIFY_RESULT";
    // Verify Result
    if (r_ticket_in.result.find("SUCCESS") != string::npos)
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }

    return r_ticket_in;
}

// verify_ticket_order
RTicket RTicketVerifier::verify_ticket_order(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_TICKET_ORDER";
    string failure_msg = "-> FAILURE: VERIFY_TICKET_ORDER";
    // Verify Ticket Order
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        if (r_ticket_in.ticket_order == 1)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (r_ticket_in.ticket_order == device_table[r_ticket_in.device_id].ticket_order + 1)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET || r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET || r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
    {
        if (r_ticket_in.ticket_order == device_table[r_ticket_in.device_id].ticket_order)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        if (r_ticket_in.ticket_order == this_device.ticket_order)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else
    {

        throw std::runtime_error(failure_msg);
        return r_ticket_in;
    }
}

// verify_audi_start

RTicket RTicketVerifier::verify_audit_start(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_AUDIT_START";
    string failure_msg = "-> FAILURE: VERIFY_AUDIT_START";
    // Verify Audit Start
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (r_ticket_in.audit_start == audit_start_ticket.u_ticket_id)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket::LEGAL_CRKE_TYPES.find(r_ticket_in.r_ticket_type) != r_ticket::LEGAL_CRKE_TYPES.end())
    {
        if (r_ticket_in.audit_start == current_session.current_u_ticket_id)
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else
    {
        throw std::runtime_error(failure_msg);

        return r_ticket_in;
    }
}

RTicket RTicketVerifier::verify_audit_end(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_AUDIT_END";
    string failure_msg = "-> FAILURE: VERIFY_AUDIT_END";
    // Verify Audit End
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (r_ticket_in.audit_end == "ACCESS_END")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    return r_ticket_in;
}

RTicket RTicketVerifier::verify_cr_key(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_CR_KEY";
    string failure_msg = "-> FAILURE: VERIFY_CR_KEY";
    // Verify CR Key
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
    {
        if (r_ticket_in.challenge_1 != "" && r_ticket_in.key_exchange_salt_1 != "")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        if (r_ticket_in.challenge_2 != "" && r_ticket_in.challenge_1 != "" && r_ticket_in.key_exchange_salt_2 != "")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
    {
        if (r_ticket_in.challenge_2 != "")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else
    {
        throw std::runtime_error(failure_msg);

        return r_ticket_in;
    }
}

RTicket RTicketVerifier::verify_ps(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PS";
    string failure_msg = "-> FAILURE: VERIFY_PS";
    // Verify PS
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
    {
        if (r_ticket_in.iv_cmd != "")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        if (r_ticket_in.associated_plaintext_cmd != "" && r_ticket_in.ciphertext_cmd != "" && r_ticket_in.iv_data != "" && r_ticket_in.gcm_authentication_tag_cmd != "")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
    {
        if (r_ticket_in.associated_plaintext_data != "" && r_ticket_in.ciphertext_data != "" && r_ticket_in.iv_cmd != "" && r_ticket_in.gcm_authentication_tag_data != "")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
    {
        if (r_ticket_in.associated_plaintext_data != "" && r_ticket_in.ciphertext_data != "" && r_ticket_in.iv_cmd != "" && r_ticket_in.gcm_authentication_tag_data != "")
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else
    {
        throw std::runtime_error(failure_msg);

        return r_ticket_in;
    }
}

RTicket RTicketVerifier::verify_device_signature(RTicket r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_DEVICE_SIGNATURE";
    string failure_msg = "-> FAILURE: VERIFY_DEVICE_SIGNATURE";
    // Verify Device Signature
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET || r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {

        // TODO : something should be checked
        if (self_verify_device_signature_on_r_ticket(r_ticket_in, r_ticket_in.device_id))
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        if (self_verify_device_signature_on_r_ticket(r_ticket_in, current_session.current_holder_id))
        {
            printf("info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
        return r_ticket_in;
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
    {
        // no device_signature
        printf("info: %s\n", success_msg.c_str());
        return r_ticket_in;
    }
    else
    {
        throw std::runtime_error(failure_msg);

        return r_ticket_in;
    }
}

bool RTicketVerifier::self_verify_device_signature_on_r_ticket(RTicket signed_r_ticket, string public_key)
{
    string success_msg = "-> SUCCESS: SELF_VERIFY_DEVICE_SIGNATURE_ON_R_TICKET";
    string failure_msg = "-> FAILURE: SELF_VERIFY_DEVICE_SIGNATURE_ON_R_TICKET";
    // Verify ECC Signature on RTicket

    string signature_tmp = hex_to_byte(signed_r_ticket.device_signature);
    signed_r_ticket.device_signature = "";

    string message = signed_r_ticket.to_json_str();

    mbedtls_ecdsa_context ctx = turn_string_to_key("", public_key);

    int ret = verify_signature(message.c_str(), (const unsigned char *)signature_tmp.c_str(), ctx, signature_tmp.length());

    if (ret == 1)
    {
        printf("info: %s\n", success_msg.c_str());
        return true;
    }
    else
    {
        throw std::runtime_error(failure_msg);
        return false;
    }
}

Message MessageVerifier::verify_json_schema(string arbitrary_json)
{
    string success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA";
    string fail_msg = "-> FAIL: VERIFY_JSON_SCHEMA";
    printf("info: %s\n", success_msg.c_str());
    printf("info: %s\n", arbitrary_json.c_str());
    Message message_in;
    try
    {
        message_in = message_from_json_str(arbitrary_json);
    }
    catch (const std::exception &e)
    {
        printf("catch your shit\n");
        throw std::runtime_error(fail_msg + " : " + e.what());
    }

    return message_in;
}

Message MessageVerifier::verify_message_operation(Message message_in)
{
    string success_msg = "-> SUCCESS: VERIFY_MESSAGE_OPERATION";
    string fail_msg = "-> FAIL: VERIFY_MESSAGE_OPERATION";

    if (message_in.message_operation == message::MESSAGE_RECV_AND_STORE || message_in.message_operation == message::MESSAGE_VERIFY_AND_EXECUTE)
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }

    return message_in;
}

Message MessageVerifier::verify_message_type(Message message_in)
{
    string success_msg = "-> SUCCESS: VERIFY_MESSAGE_TYPE";
    string fail_msg = "-> FAIL: VERIFY_MESSAGE_TYPE";

    if (message_in.message_type == "UTICKET" || message_in.message_type == "RTICKET")
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }

    return message_in;
}

Message MessageVerifier::verify_message_str(Message message_in)
{
    string success_msg = "-> SUCCESS: VERIFY_MESSAGE_STR";
    string fail_msg = "-> FAIL: VERIFY_MESSAGE_STR";

    if (message_in.message_str != "")
    {
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }

    return message_in;
}