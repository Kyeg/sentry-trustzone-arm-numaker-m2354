
#include "myecdh.hpp"
#include "msg_verifier_u_ticket.hpp"

using namespace std;

extern "C"
{
    extern int verify_signature(const char *message, const unsigned char *signature, mbedtls_ecdsa_context keys, int signature_len);
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