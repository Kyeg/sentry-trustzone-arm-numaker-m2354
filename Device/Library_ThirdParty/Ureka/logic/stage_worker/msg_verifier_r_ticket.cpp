#include <string>
#include <map>
#include "myecdh.hpp"
#include "msg_verifier_r_ticket.hpp"

using namespace std;
// json
using json = nlohmann::json;

extern "C"
{
    extern int verify_signature(const char *message, const unsigned char *signature, mbedtls_ecdsa_context ctx, int signature_len);
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