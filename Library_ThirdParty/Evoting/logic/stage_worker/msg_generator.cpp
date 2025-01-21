#include "msg_generator.hpp"
#include "msg_generator_r_ticket.hpp"
#include "msg_generator_u_ticket.hpp"
#include "executor.hpp"
#include "r_ticket.hpp"
#include "u_ticket.hpp"

#include "myecdh.hpp"
#include "generated_msg_storer.hpp"
#include "msg_verifier.hpp"
#include "msg_verifier_u_ticket.hpp"
#include "msg_verifier_r_ticket.hpp"
#include "msg_verifier_message.hpp"
#include "received_msg_storer.hpp"

#include "msg_sender.hpp"
#include "msg_receiver.hpp"
#include "flow_apply_u_ticket.hpp"
#include "flow_issue_u_ticket.hpp"
#include "flow_issue_u_token.hpp"
#include "flow_open_session.hpp"
#include "device_controller.hpp"

#ifdef __cplusplus
extern "C"
{
#endif
    extern int verify_signature(const char *message, const unsigned char *signature, mbedtls_ecdsa_context keys, int signature_len);
    extern size_t sign_message(const char *message, mbedtls_ecdsa_context key, unsigned char *signature);
    extern mbedtls_ecdsa_context generate_key_pair();
    void pub_key_to_string(mbedtls_ecdsa_context key, char *ret_key);
    void pk_key_to_string(mbedtls_ecdsa_context key, char *ret_key);
#ifdef __cplusplus
}
#endif

string MsgGenerator::self_generate_xxx_u_ticket(string arbitrary_dict)
{
    printf("info: %s is generating u_ticket\n", shared_data->this_device.device_name.c_str());

    UTicketGenerator u_ticket_generator = UTicketGenerator(
        shared_data->this_device,
        shared_data->this_person,
        shared_data->device_table);

    UTicket generated_u_ticket = u_ticket_generator.generate_arbitrary_u_ticket(arbitrary_dict);

    return generated_u_ticket.to_json_str();
}

string MsgGenerator::self_generate_xxx_r_ticket(string arbitrary_dict)
{
    printf("info: %s is generating r_ticket\n", shared_data->this_device.device_name.c_str());
    // cout << "info  come here" << shared_data->this_device.to_json() << endl;
    RTicketGenerator r_ticket_generator = RTicketGenerator(
        shared_data->this_device,
        shared_data->this_person,
        shared_data->device_table);

    // cout << "info  come here" << r_ticket_generator.this_device.to_json() << endl;

    RTicket generated_r_ticket = r_ticket_generator.generate_arbitrary_r_ticket(arbitrary_dict);

    return generated_r_ticket.to_json_str();
}

RTicket RTicketGenerator::generate_arbitrary_r_ticket(string arbitrary_dict)
{
    string success_msg = "-> SUCCESS: GENERATE_RITICKET";
    string failure_msg = "-> FAILURE: GENERATE_RITICKET";
    /*####################################################
    # Unsigned RTicket
    ####################################################*/

    // TODO, something RTicket(**arbitrary_dict) was written
    RTicket new_r_ticket = rticket_from_json_str(arbitrary_dict);

    // "device"
    if (
        new_r_ticket.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || new_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || new_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET || new_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET || new_r_ticket.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN || new_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        new_r_ticket.ticket_order = this_device.ticket_order;
        // cout << "this device type" << this_device.to_json() << "\n";
        // cout << "fuck off ticket order: " << new_r_ticket.ticket_order << " " << this_device.ticket_order <<"\n";
        // "holder"
    }
    else if (new_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        new_r_ticket.ticket_order = device_table[new_r_ticket.device_id].ticket_order;
    }
    else
    {
        printf("Error: Unkown RTicket type\n");
        exit(1);
    }

    new_r_ticket.r_ticket_id = generate_sha256_hash_bytes(new_r_ticket.to_json_str());

    /*####################################################
    # Signed RTicket
    ######################################################
    # Generate Signature

    # "device"*/

    if (
        new_r_ticket.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || new_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || new_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET || new_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET || new_r_ticket.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN || new_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        new_r_ticket = self_add_device_signature_on_r_ticket(new_r_ticket, this_device.strings_to_pp_keys());
        // log ("info", success_msg);
        printf("info: %s\n", success_msg.c_str());
    }
    else if (new_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        new_r_ticket = self_add_device_signature_on_r_ticket(new_r_ticket, this_person.strings_to_pp_keys());
        // log ("info", success_msg);
        printf("info: %s\n", success_msg.c_str());
    }
    else if (new_r_ticket.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
    {
        // log ("error", failure_msg);
        printf("error: %s\n", failure_msg.c_str());
        exit(1);
    }

    return new_r_ticket;
}

RTicket RTicketGenerator::self_add_device_signature_on_r_ticket(RTicket unsigned_r_ticket, mbedtls_ecdsa_context key)
{

    // Generate Signature
    unsigned char *signature = (unsigned char *)malloc(500);
    size_t sig_len = sign_message(unsigned_r_ticket.to_json_str().c_str(), key, signature);

    string signature_str = byte_to_hex(signature, sig_len);

    // Add Signature
    unsigned_r_ticket.device_signature = signature_str;

    return unsigned_r_ticket;
}

UTicket UTicketGenerator::generate_arbitrary_u_ticket(string arbitrary_dict)
{
    string success_msg = "-> SUCCESS: GENERATE_UITICKET";
    string failure_msg = "-> FAILURE: GENERATE_UITICKET";
    /*####################################################
    # Unsigned UTicket
    ####################################################*/

    // TODO, something UTicket(**arbitrary_dict) was written
    UTicket new_u_ticket = uticket_from_json_str(arbitrary_dict);

    if (new_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        new_u_ticket.ticket_order = 0;
    }
    else
    {
        new_u_ticket.ticket_order = device_table[new_u_ticket.device_id].ticket_order;
    }

    // cout << "info: " << "new_u_ticket = " << new_u_ticket.to_json_str() << endl;

    // Generate UTicket Id (Hash-based)
    new_u_ticket.u_ticket_id = generate_sha256_hash_bytes(new_u_ticket.to_json_str());

    /*####################################################
    # Signed UTicket
    ######################################################
    # Generate Signature

    # "device"*/

    if (
        new_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || new_u_ticket.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET || new_u_ticket.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || new_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        // no issuer signature
        printf("info: %s\n", success_msg.c_str());
    }
    else if (new_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || new_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
    {
        new_u_ticket = self_add_issuer_signature_on_u_ticket(new_u_ticket, this_person.strings_to_pp_keys());
        // log ("info", success_msg);
        printf("info: %s\n", success_msg.c_str());
    }
    else
    {
        // log ("error", failure_msg);
        printf("error: %s\n", failure_msg.c_str());
        exit(1);
    }

    // cout << "info: " << "new_u_ticket = " << new_u_ticket.to_json_str() << endl;

    return new_u_ticket;
}

UTicket UTicketGenerator::self_add_issuer_signature_on_u_ticket(UTicket unsigned_u_ticket, mbedtls_ecdsa_context key)
{

    // Generate Signature
    unsigned char *signature = (unsigned char *)malloc(500);
    size_t sig_len = sign_message(unsigned_u_ticket.to_json_str().c_str(), key, signature);
    // Convert signature to string
    string new_sig = byte_to_hex(signature, sig_len);
    // Add Signature
    unsigned_u_ticket.issuer_signature = new_sig;

    return unsigned_u_ticket;
}

pair<UTicket, RTicket> MsgVerifier::self_classify_message_is_defined_type(string arbitrary_json)
{
    printf("info %s is classifying message...\n", shared_data->this_device.device_name.c_str());

    MessageVerifier message_verifier(shared_data->this_device);

    Message message_in = message_verifier.verify_json_schema(arbitrary_json);
    message_in = message_verifier.verify_message_operation(message_in);
    message_in = message_verifier.verify_message_type(message_in);
    message_in = message_verifier.verify_message_str(message_in);

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
        throw invalid_argument("message type is not defined");
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

    Message message_in;
    try
    {
        message_in = message_from_json_str(arbitrary_json);
    }
    catch (const std::exception &e)
    {
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

void Executor::self_change_state(string new_state)
{
    shared_data->state = new_state;
}

bool Executor::self_initialize_state()
{
    if (shared_data->this_device.device_type == this_device::IOT_DEVICE)
    {
        self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        return true;
    }
    else if (shared_data->this_device.device_type == this_device::USER_AGENT_OR_CLOUD_SERVER)
    {
        self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);
        return true;
    }

    return false;
}

bool Executor::self_execute_one_time_set_time_device_type_and_name(string device_type, string device_name)
{
    /*####################################################
    # Determine device type name, but still be uninitialized
    # Determine device name (for test)
    ####################################################*/
    shared_data->this_device.device_type = device_type;
    shared_data->this_device.device_name = device_name;
    shared_data->this_device.has_device_type = true;

    /*####################################################
    # Initial Order
    ####################################################*/

    // [STAGE: (O)]
    UTicket u_ticket;
    RTicket r_ticket;
    self_execute_update_ticket_order("has-type", 0, u_ticket, r_ticket);

    /*####################################################
    # Storage
    ####################################################*/

    // TODO
    return true;
}

void Executor::self_execute_one_time_initialize_agent_or_server()
{
    /*####################################################
    # Start Process Measurement
    ####################################################*/
    // measure_helper.measure_process_perf_start();

    printf("info: %s is initializing...\n", shared_data->this_device.device_name.c_str());

    /*####################################################
    # TODO: New way for _execute_one_time_intialize_agent_or_server()
    #         + DM: Apply Initialization Ticket
    #         + DM: Apply Personal Key Gen Ticket
    #         + DO: Generate Personal Key
    #         + DO: Request Ownership Ticket from DM
    ####################################################*/

    if (shared_data->this_device.device_type != this_device::USER_AGENT_OR_CLOUD_SERVER)
    {
        // FAILURE: (VRESET)
        printf("-> FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION\n");
        throw std::runtime_error("-> FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION");
        return;
    }

    if (shared_data->this_device.ticket_order != 0)
    {
        // FAILURE: (VUT)
        printf("-> FAILURE: VERIFY_TICKET_ORDER: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED\n");
        throw std::runtime_error("-> FAILURE: VERIFY_TICKET_ORDER: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED");
        return;
    }

    /*####################################################
    # Initialize Device Id
    ####################################################*/

    // CRYPTO
    mbedtls_ecdsa_context pp_key = generate_key_pair();

    // RAM
    char *device_pk_ch = (char *)malloc(500);
    char *device_pb_ch = (char *)malloc(500);
    pk_key_to_string(pp_key, device_pk_ch);
    pub_key_to_string(pp_key, device_pb_ch);
    string device_priv_key = string(device_pk_ch);
    string device_pub_key = string(device_pb_ch);
    shared_data->this_device.device_priv_key = device_priv_key;
    shared_data->this_device.device_pub_key = device_pub_key;

    /*####################################################
    # Initialize Personal Id
    ####################################################*/

    // CRYPTO
    mbedtls_ecdsa_context personal_key = generate_key_pair();

    // RAM

    char *personal_pk_ch = (char *)malloc(500);
    char *personal_pb_ch = (char *)malloc(500);
    pk_key_to_string(personal_key, personal_pk_ch);
    pub_key_to_string(personal_key, personal_pb_ch);
    string personal_priv_key = string(personal_pk_ch);
    string personal_pub_key = string(personal_pb_ch);
    shared_data->this_person.person_priv_key = personal_priv_key;
    shared_data->this_person.person_pub_key = personal_pub_key;

    /*####################################################
    # Initialize Device Owner
    ####################################################*/

    // RAM
    shared_data->this_device.owner_pub_key = shared_data->this_person.person_pub_key;

    // [STAGE: (O)]
    UTicket u_ticket;
    RTicket r_ticket;
    self_execute_update_ticket_order("agent-initialization", 0, u_ticket, r_ticket);

    /*####################################################
    # Storage
    ####################################################*/
    // TODO

    /*####################################################
    # End Process Measurement
    ####################################################*/
    // measure_helper.measure_recv_cli_perf_time("_execute_one_time_intialize_agent_or_server");
}

void Executor::self_execute_xxx_u_ticket(UTicket u_ticket_in)
{
    RTicket no_use_r_ticket;
    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_one_time_initialize_iot_device(u_ticket_in);

        // [STAGE: (O)]
        self_execute_update_ticket_order("device-verify-uticket", 1, u_ticket_in, no_use_r_ticket);
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_ownership_transfer(u_ticket_in);

        // [STAGE: (O)]
        self_execute_update_ticket_order("device-verify-uticket", 1, u_ticket_in, no_use_r_ticket);
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_cr_ke(1, u_ticket_in, no_use_r_ticket, "device");
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        // [STAGE: (VTK)(VTS)]
        // [STAGE: (E)]
        self_execute_ps("recv-utoken", 1, u_ticket_in, no_use_r_ticket, "", "");

        // Date Processing
        string *data_processing_result = self_execute_data_processing(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd);

        string plaintext_data = data_processing_result[0];
        string associated_plaintext_data = data_processing_result[1];

        // Update Session: PS-Data
        self_execute_ps("send-rtoken", 1, u_ticket_in, no_use_r_ticket, plaintext_data, associated_plaintext_data);

        if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (VTK)]
            if (shared_data->current_session.plaintext_cmd == "ACCESS_END")
            {
                shared_data->result_message = "-> SUCCESS: VERIFY_ACCESS_END";

                // [STAGE: (O)]
                self_execute_update_ticket_order("device-verify-uticket", 1, u_ticket_in, no_use_r_ticket);
            }
            else
            {
                shared_data->result_message = "-> FAILURE: VERIFY_ACCESS_END";
                printf("-> FAILURE: VERIFY_ACCESS_END\n");
            }
        }
        else
        {
            printf("should not be here (self_execute_xxx_u_ticket)\n");
        }
    }
}

void Executor::self_execute_xxx_r_ticket(RTicket r_ticket_in, string comm_end)
{
    UTicket no_use_u_ticket;
    if (comm_end == "holder-or-device")
    {
        if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (O)]
            self_execute_update_ticket_order("holder-or-issuer-verify-rticket", 2, no_use_u_ticket, r_ticket_in);
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
        {
            // [STAGE: (E)]
            self_execute_cr_ke(2, no_use_u_ticket, r_ticket_in, "holder");
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
        {
            // [STAGE: (E)]
            self_execute_cr_ke(2, no_use_u_ticket, r_ticket_in, "device");
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
        {
            // [STAGE: (E)]
            self_execute_cr_ke(2, no_use_u_ticket, r_ticket_in, "holder");
        }
        else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
        {
            // [STAGE: (E)]
            self_execute_ps("recv-rtoken", 2, no_use_u_ticket, r_ticket_in, "", "");
        }
        else
        {
            printf("should not be here (self_execute_xxx_r_ticket)\n");
        }
    }
    else if (comm_end == "issuer")
    {
        if (r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // not owner anymore, delete this device in table
            shared_data->device_table.erase(r_ticket_in.device_id);

            /*############################################
            # Storage
            ############################################*/

            // TODO
        }
        else if (r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // still owner, but keep/delete device_access_u_ticket_for_others in table
            shared_data->device_table[r_ticket_in.device_id].device_access_u_ticket_for_others = "";
            shared_data->device_table[r_ticket_in.device_id].device_access_end_r_ticket_for_others = "";
            // [STAGE: (O)]
            self_execute_update_ticket_order("holder-or-issuer-verify-rticket", 2, no_use_u_ticket, r_ticket_in);

            /*############################################
            # Storage
            ############################################*/

            // TODO
        }
        else
        {
            printf("should not be here (self_execute_xxx_r_ticket)\n");
        }
    }
}

void Executor::self_execute_one_time_initialize_iot_device(UTicket u_ticket_in)
{
    printf("info: %s is initializing...\n", shared_data->this_device.device_name.c_str());

    if (shared_data->this_device.device_type != this_device::IOT_DEVICE)
    {
        // FAILURE: (VRESET)
        printf("-> FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION\n");
        return;
    }

    /*####################################################
    # Initialize Device Id
    ####################################################*/
    // CRYPTO
    mbedtls_ecdsa_context pp_key = generate_key_pair();

    // RAM
    char *device_pk_ch = (char *)malloc(500);
    char *device_pb_ch = (char *)malloc(500);
    pk_key_to_string(pp_key, device_pk_ch);
    pub_key_to_string(pp_key, device_pb_ch);
    string device_priv_key = string(device_pk_ch);
    string device_pub_key = string(device_pb_ch);
    shared_data->this_device.device_priv_key = device_priv_key;
    shared_data->this_device.device_pub_key = device_pub_key;

    /*####################################################
    # Initialize Device Owner
    ####################################################*/

    // RAM
    shared_data->this_device.owner_pub_key = u_ticket_in.holder_id;

    /*####################################################
    # Storage
    ####################################################*/

    // TODO
}

void Executor::self_execute_ownership_transfer(UTicket u_ticket_in)
{
    printf("info: %s is transferring ownership...\n", shared_data->this_device.device_name.c_str());

    /*####################################################
    # Update Device Owner
    ####################################################*/

    // RAM
    shared_data->this_device.owner_pub_key = u_ticket_in.holder_id;

    /*####################################################
    # Storage
    ####################################################*/

    // TODO
}

void Executor::self_execute_cr_ke(int UR, UTicket u_ticket_in, RTicket r_ticket_in, string comm_end, string cmd)
{
    printf("info: %s is executing cr_ke...\n", shared_data->this_device.device_name.c_str());

    UTicket no_use_u_ticket;
    RTicket no_use_r_ticket;
    if (UR == 1 &&
        (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET))
    {
        if (comm_end == "holder")
        {
            // Update session: Access UT
            shared_data->current_session.current_u_ticket_id = u_ticket_in.u_ticket_id;
            shared_data->current_session.current_device_id = u_ticket_in.device_id;
            shared_data->current_session.current_holder_id = u_ticket_in.holder_id;
            shared_data->current_session.current_task_scope = u_ticket_in.task_scope;

            // Update Session: PS-Cmd(Input: Plaintext, Associated-Plaintext)
            self_execute_ps("send-ut", 0, no_use_u_ticket, no_use_r_ticket, cmd, "");
        }
        else if (comm_end == "device")
        {
            // Update session: Access UT
            shared_data->current_session.current_u_ticket_id = u_ticket_in.u_ticket_id;
            shared_data->current_session.current_device_id = u_ticket_in.device_id;
            shared_data->current_session.current_holder_id = u_ticket_in.holder_id;
            shared_data->current_session.current_task_scope = u_ticket_in.task_scope;

            // Update Session: CR
            shared_data->current_session.challenge_1 = generate_random_str(32);

            // Update Session: KE
            shared_data->current_session.key_exchange_salt_1 = generate_random_str(32);

            // Update Session: PS-Cmd
            self_execute_ps("recv-ut-and-send-crke1", 0, no_use_u_ticket, no_use_r_ticket, "", "");
        }
        else
        {
            printf("should not be here (self_execute_cr_ke)\n");
        }
    }
    else if (UR == 2 && r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
    {

        // Update Session: CR
        shared_data->current_session.challenge_1 = r_ticket_in.challenge_1;
        shared_data->current_session.challenge_2 = generate_random_str(32);

        // Update Session: KE
        shared_data->current_session.key_exchange_salt_1 = r_ticket_in.key_exchange_salt_1;
        shared_data->current_session.key_exchange_salt_2 = generate_random_str(32);

        string current_session_key_byte = self_execute_generate_session_key(
            shared_data->current_session.key_exchange_salt_1,
            shared_data->current_session.key_exchange_salt_2,
            shared_data->this_person.person_priv_key,
            shared_data->current_session.current_device_id);

        shared_data->current_session.current_session_key_str = current_session_key_byte;

        // Update Session: PS-Cmd
        self_execute_ps("recv-crke1-and-send-crke2", 2, no_use_u_ticket, r_ticket_in, "", "");
    }
    else if (UR == 2 && r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        // Update Session: CR
        shared_data->current_session.challenge_2 = r_ticket_in.challenge_2;

        // Update Session: KE
        shared_data->current_session.key_exchange_salt_2 = r_ticket_in.key_exchange_salt_2;

        string current_session_key_byte = self_execute_generate_session_key(
            shared_data->current_session.key_exchange_salt_1,
            shared_data->current_session.key_exchange_salt_2,
            shared_data->this_device.device_priv_key,
            shared_data->current_session.current_holder_id);

        shared_data->current_session.current_session_key_str = current_session_key_byte;

        // Update Session: PS-Cmd
        self_execute_ps("recv-crke2", 2, no_use_u_ticket, r_ticket_in, "", "");

        string *data_processing_result = self_execute_data_processing(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd);

        string plaintext_data = data_processing_result[0];
        string associated_plaintext_data = data_processing_result[1];

        // Update Session: PS-Data

        self_execute_ps("send-crke3", 2, no_use_u_ticket, r_ticket_in, plaintext_data, associated_plaintext_data);
    }
    else if (UR == 2 && r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
    {
        // Update Session: PS-Data
        self_execute_ps("recv-crke3", 2, no_use_u_ticket, r_ticket_in, "", "");
    }
    else
    {
        printf("should not be here (self_execute_cr_ke)\n");
    }
}

string Executor::self_execute_generate_session_key(string salt_1, string salt_2, string priv_key, string pub_key)
{
    string shared_salt_bytes;
    for (int i = 0; i < salt_1.size(); i++)
    {
        shared_salt_bytes += salt_1[i] & salt_2[i];
    }

    string current_session_key = generate_ecdh_key(priv_key, pub_key, shared_salt_bytes, "");

    return current_session_key;
}

void Executor::self_execute_ps(string executing_case, int UR, UTicket u_ticket_in, RTicket r_ticket_in, string plaintext, string associated_plaintext)
{
    printf("info: %s is executing ps...\n", shared_data->this_device.device_name.c_str());

    if (executing_case == "send-ut")
    {
        // Update Session: PS-Cmd (input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_cmd = plaintext;
        shared_data->current_session.associated_plaintext_cmd = "additional unencrypted cmd";
    }
    else if (executing_case == "recv-ut-and-send-crke1")
    {
        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "recv-crke1-and-send-crke2")
    {
        // Update Session: PS-Cmd (Input: this-IV)
        if (UR == 1)
        {
            printf("should not be here (self_execute_ps) (recv-crke1-and-send-crke2)\n");
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_cmd = r_ticket_in.iv_cmd;
        }

        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        shared_data->current_session.ciphertext_cmd = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_cmd = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_data = self_gen_next_iv();
    }
    else if (executing_case == "recv-crke2")
    {
        // Update Session: PS-Data
        if (UR == 1)
        {
            shared_data->current_session.ciphertext_cmd = u_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = u_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = u_ticket_in.gcm_authentication_tag_cmd;
        }
        else if (UR == 2)
        {
            shared_data->current_session.ciphertext_cmd = r_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = r_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = r_ticket_in.gcm_authentication_tag_cmd;
        }

        // [STAGE: (VTK)(VTS)]
        // Update Session: PS-cmd (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.gcm_authentication_tag_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        msg_verifier.verify_cmd_is_in_task_scope(decrypted_plaintext);

        // Update Session: PS-Cmd (Output: plaintext)
        shared_data->current_session.plaintext_cmd = decrypted_plaintext;
    }
    else if (executing_case == "send-crke3")
    {
        // update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            shared_data->current_session.iv_data = u_ticket_in.iv_data;
        }
        else if (UR == 2)
        {
            printf("should not be here (self_execute_ps) (send-crke3)\n");
            shared_data->current_session.iv_data = r_ticket_in.iv_data;
        }

        // Update Session: PS-Cmd (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_data = plaintext;
        shared_data->current_session.associated_plaintext_data = associated_plaintext;

        // Update Session: PS-Data(Encryption)
        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data(Output: CipherText, GCM-Authentication-Tag)
        shared_data->current_session.ciphertext_data = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_data = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "recv-crke3")
    {
        // Update Session: PS-Cmd(Input: This-IV)
        if (UR == 1)
        {
            printf("should not be here (self_execute_ps) (recv-crke3)\n");
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_cmd = r_ticket_in.iv_cmd;
            // Update Session: PS-Data (input: ciphertext, associated_plaintext, gcm_authentication_tag)
            shared_data->current_session.ciphertext_data = r_ticket_in.ciphertext_data;
            shared_data->current_session.associated_plaintext_data = r_ticket_in.associated_plaintext_data;
            shared_data->current_session.gcm_authentication_tag_data = r_ticket_in.gcm_authentication_tag_data;
        }

        // [STAGE: (VTK)]
        // Update Session: PS-Data (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.gcm_authentication_tag_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data (Output: plaintext)
        shared_data->current_session.plaintext_data = decrypted_plaintext;
        // PS
    }
    else if (executing_case == "send-utoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        // Update Session: PS-Cmd (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_cmd = plaintext;
        shared_data->current_session.associated_plaintext_cmd = "additional unencrypted cmd";

        // Update Session: PS-Cmd (Encryption)
        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        // Update Session: PS-Cmd (Output: ciphertext, gcm_authentication_tag)
        shared_data->current_session.ciphertext_cmd = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_cmd = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_data = self_gen_next_iv();
    }
    else if (executing_case == "recv-utoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        // Update Session: PS-Cmd (Input: ciphertext, associated_plaintext, gcm_authentication_tag)
        if (UR == 1)
        {
            shared_data->current_session.ciphertext_cmd = u_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = u_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = u_ticket_in.gcm_authentication_tag_cmd;
        }
        else if (UR == 2)
        {
            shared_data->current_session.ciphertext_cmd = r_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd = r_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd = r_ticket_in.gcm_authentication_tag_cmd;
        }

        // [STAGE: (VTK)(VTS)]
        // Update Session: PS-Cmd (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.gcm_authentication_tag_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd);

        if (UR == 1 && u_ticket_in.u_ticket_type != u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            msg_verifier.verify_cmd_is_in_task_scope(decrypted_plaintext);
        }
        else
        {
            printf("should not be here (self_execute_ps) (recv-utoken)\n");
        }

        // Update Session: PS-Cmd (Output: plaintext)
        shared_data->current_session.plaintext_cmd = decrypted_plaintext;
    }
    else if (executing_case == "send-rtoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            shared_data->current_session.iv_data = u_ticket_in.iv_data;
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_data = r_ticket_in.iv_data;
        }

        // Update Session: PS-DATA (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_data = plaintext;
        shared_data->current_session.associated_plaintext_data = associated_plaintext;

        // Update Session: PS-Data (Encryption)
        string *encrypted_plaintext = self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data (Output: ciphertext, gcm_authentication_tag)
        shared_data->current_session.ciphertext_data = encrypted_plaintext[0];
        shared_data->current_session.gcm_authentication_tag_data = encrypted_plaintext[1];

        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "recv-rtoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            printf("should not be here (self_execute_ps) (recv-rtoken)\n");
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_cmd = r_ticket_in.iv_cmd;
            // Update Session: PS-Data (Input: ciphertext, associated_plaintext, gcm_authentication_tag)
            shared_data->current_session.ciphertext_data = r_ticket_in.ciphertext_data;
            shared_data->current_session.associated_plaintext_data = r_ticket_in.associated_plaintext_data;
            shared_data->current_session.gcm_authentication_tag_data = r_ticket_in.gcm_authentication_tag_data;
        }

        // [STAGE: (VTK)]
        // Update Session: PS-Data (Decryption)
        string decrypted_plaintext = self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.gcm_authentication_tag_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_data);

        // Update Session: PS-Data (Output: plaintext)
        shared_data->current_session.plaintext_data = decrypted_plaintext;
    }
    else
    {
        printf("%s\n", executing_case.c_str());
        throw std::runtime_error("should not be here (self_execute_ps)");
    }

    /*############################################
    # Storage
    ############################################*/

    // TODO
}

string *Executor::self_execute_encrypt_plaintext(string plaintext, string associated_plaintext, string session_key, string iv)
{
    printf("info: %s is encrypting plaintext...\n", shared_data->this_device.device_name.c_str());

    string *encrypted_plaintext = new string[2];

    // CRYPTO
    encrypted_plaintext = gcm_encrypt(plaintext, associated_plaintext, session_key, iv);

    return encrypted_plaintext;
}

string Executor::self_execute_decrypt_ciphertext(string ciphertext, string associated_plaintext, string gcm_authentication_tag, string session_key, string iv)
{
    printf("info: %s is decrypting ciphertext...\n", shared_data->this_device.device_name.c_str());

    try
    {
        // CRYPTO
        string decrypted_plaintext = gcm_decrypt(ciphertext, associated_plaintext, gcm_authentication_tag, session_key, iv);

        shared_data->result_message = "-> SUCCESS: VERIFY_IV_AND_HMAC";

        return decrypted_plaintext;
    }
    catch (const std::exception &e)
    {
        string error_message = e.what();
        shared_data->result_message = "-> FAILURE: VERIFY_IV_AND_HMAC";
        printf("error: %s\n", error_message.c_str());
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("should not be here (self_execute_decrypt_ciphertext)");
    }
}

string *Executor::self_execute_data_processing(string plaintext_cmd, string associated_plaintext_cmd)
{
    printf("info: %s is executing application...\n", shared_data->this_device.device_name.c_str());

    string plaintext_data = "DATA: " + plaintext_cmd;
    associated_plaintext_cmd = "DATA: " + associated_plaintext_cmd;

    string *data_processing_result = new string[2];

    data_processing_result[0] = plaintext_data;
    data_processing_result[1] = associated_plaintext_cmd;

    return data_processing_result;
}

/*####################################################
# [STAGE: (O)] Update Ticket Order
#   Update Ticket Order after:
#       "has-type": Intial Ticket Order = 0
#       "agent-initialization": Ticket Order = 1 after device/agent is initialized
#       "holder-generate-or-receive-uticket": Generate or Receive UTicket (expected ticket order)
#       "device-verify-uticket": Verify UTicket & End TX (actual ticket order)
#       "holder-or-issuer-verify-rticket": Verify RTicket (actual ticket order)
####################################################*/

void Executor::self_execute_update_ticket_order(string updating_case, int UR, UTicket u_ticket_in, RTicket r_ticket_in)
{
    printf("info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());

    if (updating_case == "has-type")
    {
        shared_data->this_device.ticket_order = 0;
    }
    else if (updating_case == "agent-initialization")
    {
        shared_data->this_device.ticket_order += 1;
    }
    else if (updating_case == "holder-generate-or-receive-uticket")
    {
        // Receive UTicket
        if (UR == 1 && (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET))
        {
            shared_data->device_table[u_ticket_in.device_id].ticket_order = u_ticket_in.ticket_order;
        }
        else
        {
            printf("should not be here (self_execute_update_ticket_order)\n");
        }
    }
    else if (updating_case == "device-verify-uticket")
    {
        // Execute UTicket
        if (UR == 1 && (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN))
        {
            shared_data->this_device.ticket_order += 1;
            printf("info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());
        }
        else
        {
            printf("should not be here (self_execute_update_ticket_order)\n");
        }
    }
    else if (updating_case == "holder-or-issuer-verify-rticket")
    {
        // Execute RTicket
        if (UR == 2 && (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN))
        {
            shared_data->device_table[r_ticket_in.device_id].ticket_order = r_ticket_in.ticket_order;
            printf("info: %d\n", r_ticket_in.ticket_order);
            printf("info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());
        }
        else
        {
            printf("should not be here (self_execute_update_ticket_order)\n");
        }
    }
    else
    {
        printf("should not be here (self_execute_update_ticket_order)\n");
    }

    /*############################################
    # Storage
    ############################################*/

    // TODO
}

void GeneratedMsgStorer::store_generated_xxx_u_ticket(const string generated_u_ticket_json)
{
    try
    {
        // [STAGE: (VR)]
        // cout << "debug: " << "GeneratedMsgStorer::store_generated_xxx_u_ticket" << "\n";
        UTicket generated_u_ticket = uticket_from_json_str(generated_u_ticket_json);
        if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
        {
            // Holder (for Owner)
            string device_id_for_initialization_u_ticket = "no_id";
            // OtherDevice new_device(device_id_for_initialization_u_ticket, generated_u_ticket_json);
            shared_data->device_table[device_id_for_initialization_u_ticket] = OtherDevice(device_id_for_initialization_u_ticket, generated_u_ticket_json);
        }
        else if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // Issuer (for Others)
            string device_id_for_u_ticket = generated_u_ticket.device_id;
            shared_data->device_table[device_id_for_u_ticket].device_ownership_u_ticket_for_others = generated_u_ticket_json;
        }
        else if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // Holder (for Owner)
            string device_id_for_u_ticket = generated_u_ticket.device_id;
            shared_data->device_table[generated_u_ticket.device_id].device_u_ticket_for_owner = generated_u_ticket_json;
        }
        else if (generated_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
        {
            // Issuer (for Others)
            string device_id_for_u_ticket = generated_u_ticket.device_id;
            shared_data->device_table[device_id_for_u_ticket].device_access_u_ticket_for_others = generated_u_ticket_json;
        }
        else
        {
            throw runtime_error("Not implemented yet");
        }

        //////////////////////////////////////////////////////
        // Storage
        //////////////////////////////////////////////////////
        // simple_storage.store_storage(
        //     shared_data->this_device,
        //     shared_data->device_table,
        //     shared_data->this_person,
        //     shared_data->current_session
        // );
    }
    catch (const std::runtime_error &error)
    {
        shared_data->result_message = error.what();
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

ReceivedMsgStorer::ReceivedMsgStorer(SharedData *shared_data,
                                     SimpleStorage *simple_storage)
    : shared_data(shared_data), simple_storage(simple_storage) {};

void ReceivedMsgStorer::store_received_xxx_u_ticket(const UTicket &received_u_ticket)
{
    try
    {
        std::string received_u_ticket_json = received_u_ticket.to_json_str();

        if (received_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
            received_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
        {
            shared_data->device_table[received_u_ticket.device_id] = OtherDevice(
                received_u_ticket.device_id,
                received_u_ticket_json);
        }
        else
        {
            throw std::runtime_error("Shouldn't Reach Here");
        }

        // Storage
        // simple_storage->storeStorage(
        //     shared_data->this_device,
        //     shared_data->device_table,
        //     shared_data->this_person,
        //     shared_data->current_session
        // );
    }
    catch (const std::exception &)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

void ReceivedMsgStorer::store_received_xxx_r_ticket(const RTicket &received_r_ticket)
{
    try
    {
        std::string received_r_ticket_json = received_r_ticket.to_json_str();

        if (received_r_ticket.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
        {
            std::string created_device_id = received_r_ticket.device_id;
            shared_data->device_table[created_device_id] = OtherDevice(
                created_device_id,
                shared_data->device_table["no_id"].device_u_ticket_for_owner,
                received_r_ticket_json);
        }
        else if (received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            if (shared_data->device_table[received_r_ticket.device_id].device_ownership_u_ticket_for_others.empty())
            {
                shared_data->device_table[received_r_ticket.device_id].device_r_ticket_for_owner = received_r_ticket_json;
            }
            else
            {
                shared_data->device_table[received_r_ticket.device_id].device_ownership_r_ticket_for_others = received_r_ticket_json;
            }
        }
        else if (received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            if (shared_data->device_table[received_r_ticket.device_id].device_access_u_ticket_for_others.empty())
            {
                shared_data->device_table[received_r_ticket.device_id].device_r_ticket_for_owner = received_r_ticket_json;
            }
            else
            {
                shared_data->device_table[received_r_ticket.device_id].device_access_end_r_ticket_for_others = received_r_ticket_json;
            }
        }
        else
        {
            throw std::runtime_error("Shouldn't Reach Here");
        }

        // Storage
        // simple_storage->storeStorage(
        //     shared_data->this_device,
        //     shared_data->device_table,
        //     shared_data->this_person,
        //     shared_data->current_session
        // );
    }
    catch (const std::exception &)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

MsgSender::MsgSender(SharedData *shared_data)
    : shared_data(shared_data) {}

void MsgSender::start_simulated_comm()
{
    shared_data->simulated_comm_completed_flag = false;
}

void MsgSender::complete_simulated_comm()
{
    shared_data->simulated_comm_completed_flag = true;
}

void MsgSender::wait_simulated_comm_completed()
{
    if (Environment::DEPLOYMENT_ENV == "TEST")
    {
        // while (!shared_data->simulated_comm_completed_flag) {
        //     std::this_thread::sleep_for(std::chrono::milliseconds(Environment::SIMULULATED_COMM_INTERRUPT_CYCLE_TIME));
        // }
    }
    else if (Environment::DEPLOYMENT_ENV == "PRODUCTION")
    {
        // shared_data->simulated_comm_receiver_thread.join();
    }
}

// void MsgSender::start_bluetooth_comm() {
//     shared_data->connection_socket.acceptConnection();
// }

// void MsgSender::complete_bluetooth_comm() {
//     shared_data->connection_socket.closeConnection();
// }

void MsgSender::send_xxx_message(const std::string &message_operation,
                                 const std::string &message_type,
                                 const std::string &sent_message_json)
{
    // 生成消息
    if ((message_operation == message::MESSAGE_RECV_AND_STORE || message_operation == message::MESSAGE_VERIFY_AND_EXECUTE) &&
        (message_type == u_ticket::MESSAGE_TYPE || message_type == r_ticket::MESSAGE_TYPE))
    {

        Message message_request;
        message_request.message_operation = message_operation;
        message_request.message_type = message_type;
        message_request.message_str = sent_message_json;

        try
        {
            std::string new_message_json = message_request.to_json_str();

            if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
            {
                // simpleLog("info", "+ " + shared_data->this_device.device_name + " is sending message to " +
                //           shared_data->simulated_comm_channel.end->shared_data->this_device.device_name + "...");
                // cout << "info: + " << shared_data->this_device.device_name << " is sending message to " << shared_data->simulated_comm_channel.end->shared_data->this_device.device_name << "..." << "\n";
                // 模拟网络延迟
                for (int i = 0; i < Environment::SIMULULATED_COMM_DELAY_COUNT; ++i)
                {
                    printf("info: Simulated Comm Delay\n");
                    // if (Environment::DEPLOYMENT_ENV == "PRODUCTION") {
                    //     std::this_thread::sleep_for(std::chrono::milliseconds(Environment::SIMULULATED_COMM_DELAY_DURATION));
                    // }
                }

                // shared_data->simulated_comm_channel.sender_queue.push(new_message_json);
                SIMULATED_GLOBAL_CHANNEL = new_message_json;
            }
            else
            {
                // simpleLog("info", "+ " + shared_data->this_device.device_name + " is sending message to BT_address or BT_name...");
                printf("shold not reach here\n");
                // shared_data->connection_socket.sendMessage(new_message_json);
            }
        }
        catch (const std::exception &error)
        {
            throw std::runtime_error("Weird M-Request: " + std::string(error.what()));
        }
    }
    else
    {
        throw std::runtime_error("Weird M-Request");
    }
}

MsgReceiver::MsgReceiver(
    SharedData *shared_data,
    // measure_helper* measure_helper,
    MsgVerifier *msg_verifier,
    Executor *executor,
    MsgSender *msg_sender,
    FlowIssueUTicket *flow_issuer_issue_u_ticket,
    FlowApplyUTicket *flow_apply_u_ticket,
    FlowOpenSession *flow_open_session,
    FlowIssueUToken *flow_issue_u_token) : shared_data(shared_data),
                                           // measure_helper_(measure_helper),
                                           msg_verifier(msg_verifier),
                                           executor(executor),
                                           msg_sender(msg_sender),
                                           flow_issuer_issue_u_ticket(flow_issuer_issue_u_ticket),
                                           flow_apply_u_ticket(flow_apply_u_ticket),
                                           flow_open_session(flow_open_session),
                                           flow_issue_u_token(flow_issue_u_token) {};

void MsgReceiver::create_simulated_comm_connection()
{
    // shared_data_->simulated_comm_channel.end = end;
    // shared_data->simulated_comm_channel.sender_queue = end->shared_data->simulated_comm_channel.receiver_queue;

    // shared_data_->simulated_comm_receiver_thread = std::thread(&MsgReceiver::recv_xxx_message, this);
    // shared_data_->simulated_comm_receiver_thread.detach();
}

void MsgReceiver::accept_bluetooth_comm()
{
    // 实现蓝牙通信接受逻辑
}

void MsgReceiver::close_bluetooth_connection()
{
    // 实现关闭蓝牙连接逻辑
}

void MsgReceiver::close_bluetooth_acception()
{
    // 实现关闭蓝牙接受逻辑
}

void MsgReceiver::recv_xxx_message()
{
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
    {
        msg_sender->start_simulated_comm();
    }
    else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
    {
        // msg_sender->start_bluetooth_comm();
    }

    /* while (true) { */
    // 检查通信是否完成的逻辑

    try
    {
        std::string received_message_with_header;

        if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
        {
            if (shared_data->simulated_comm_completed_flag == true)
            {
                /* break; */
            }
        }
        else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
        {
            // 蓝牙通信接收消息逻辑
            /* break; */
        }

        // [STAGE (R)]

        if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
        {
            if (Environment::DEPLOYMENT_ENV == "TEST")
            {
                received_message_with_header = SIMULATED_GLOBAL_CHANNEL;
                SIMULATED_GLOBAL_CHANNEL = "";
                // shared_data->simulated_comm_channel.receiver_queue.pop();
            }
            else if (Environment::DEPLOYMENT_ENV == "PRODUCTION")
            {
                // received_message_with_header = shared_data->simulated_comm_channel.receiver_queue.front();
                // shared_data->simulated_comm_channel.receiver_queue.pop();
            }
        }
        else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
        {
            // received_message_with_header = shared_data->connection_socket.receiveMessage();
        }
        if (received_message_with_header == "")
        {
            throw std::runtime_error("Received message is empty");
        }
        // 消息大小测量
        // measure_helper_->measure_message_size("_recv_message", received_message_with_header);

        // 开始处理性能测量
        // measure_helper_->measure_process_perf_start();

        // 消息验证和分类
        pair<UTicket, RTicket> received_message = msg_verifier->self_classify_message_is_defined_type(received_message_with_header);

        if (received_message.first.u_ticket_type != "")
        {
            // [STAGE (U)]
            shared_data->received_message_json = received_message.first.to_json_str();
        }
        else if (received_message.second.r_ticket_type != "")
        {
            // [STAGE (R)]
            shared_data->received_message_json = received_message.second.to_json_str();
        }

        printf("cli Received Message: %s\n", received_message_with_header.c_str());
        // TODO:
        // IOT device
        printf("device_type: %s state: %s\n", shared_data->this_device.device_type.c_str(), shared_data->state.c_str());
        if (shared_data->state == this_device::STATE_DEVICE_WAIT_FOR_UT)
        {
            flow_apply_u_ticket->self_device_recv_u_ticket(received_message.first);
        }
        else if (shared_data->state == this_device::STATE_DEVICE_WAIT_FOR_CRKE2)
        {
            flow_open_session->self_device_recv_cr_ke_2(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_DEVICE_WAIT_FOR_CMD)
        {
            flow_issue_u_token->self_device_recv_cmd(received_message.first);
        }
        /*USER_AGENT_OR_CLOUD_SERVER */ else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT)
        {
            if (received_message.first.u_ticket_type != "")
            {
                printf("Received U Ticket\n");
                flow_issuer_issue_u_ticket->self_holder_recv_u_ticket(received_message.first);
            }
            else if (received_message.second.r_ticket_type != "")
            {
                flow_issuer_issue_u_ticket->self_issuer_recv_r_ticket(received_message.second);
            }
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_RT)
        {
            flow_apply_u_ticket->self_holder_recv_r_ticket(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_CRKE1)
        {
            flow_open_session->self_holder_recv_cr_ke_1(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_CRKE3)
        {
            flow_open_session->self_holder_recv_cr_ke_3(received_message.second);
        }
        else if (shared_data->state == this_device::STATE_AGENT_WAIT_FOR_DATA)
        {
            flow_issue_u_token->self_holder_recv_data(received_message.second);
        }
        else
        {
            throw std::runtime_error("(MsgReceiver) Shouldn't Reach Here");
        }
    }
    catch (const std::runtime_error &error)
    {
        shared_data->result_message = error.what();
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
    /* } */
}

void FlowApplyUTicket::holder_apply_u_ticket(string device_id, string cmd)
{
    // [STAGE: (VL)(L)]
    string stored_u_ticket_json = shared_data->device_table[device_id].device_u_ticket_for_owner;

    // [STAGE: (VR)]
    UTicket stored_u_ticket = msg_verifier->self_classify_u_ticket_is_defined_type(stored_u_ticket_json);

    if (stored_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || stored_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        // [STAGE: (C)]
        executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_RT);
    }
    else if (stored_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || stored_u_ticket.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        // [STAGE: (E)]
        RTicket empty_r_ticket;
        executor->self_execute_cr_ke(1, stored_u_ticket, empty_r_ticket, "holder", cmd);

        // [STAGE: (C)]
        executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_CRKE1);
    }

    // [STAGE: (S)]
    msg_sender->send_xxx_message(
        message::MESSAGE_VERIFY_AND_EXECUTE,
        u_ticket::MESSAGE_TYPE,
        stored_u_ticket_json);
}

void FlowApplyUTicket::self_device_recv_u_ticket(UTicket received_u_ticket)
{
    try
    {
        // [STAGE: (R)(VR)]
        // [STAGE: (SR)]
        // no need to optionally _store_received_xxx_u_ticket

        // [STAGE: (VUT)]
        msg_verifier->verify_u_ticket_can_execute(received_u_ticket);
        shared_data->result_message = " -> SUCCESS: VERIFY_UT_CAN_EXECUTE";

        // UT-RT
        if (received_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || received_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            //[STAGE: (EO)]
            executor->self_execute_xxx_u_ticket(received_u_ticket);
            // [STAGE: (C)]
            executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        }
        else if (received_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || received_u_ticket.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // [STAGE: (E)]
            RTicket empty_r_ticket;
            executor->self_execute_cr_ke(1, received_u_ticket, empty_r_ticket, "device");

            // [STAGE: (C)]
            executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CRKE2);
        }
        else
        {
            throw invalid_argument("should not reach here");
        }

        // error
        //  TODO

        if (received_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || received_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // [STAGE: (G)(S)]
            self_device_send_r_ticket(
                received_u_ticket.u_ticket_type,
                received_u_ticket.u_ticket_id,
                shared_data->result_message);
        }
        else if (received_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || received_u_ticket.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // [STAGE: (G)(S)]
            flow_open_session->self_device_send_cr_ke_1(shared_data->result_message);
        }
        else
        {
            throw invalid_argument("should not reach here");
        }
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        // [STAGE: (C)]
        executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);

        if (received_u_ticket.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || received_u_ticket.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // [STAGE: (G)(S)]
            self_device_send_r_ticket(
                received_u_ticket.u_ticket_type,
                received_u_ticket.u_ticket_id,
                shared_data->result_message);
        }
        else if (received_u_ticket.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET || received_u_ticket.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // [STAGE: (G)(S)]
            flow_open_session->self_device_send_cr_ke_1(shared_data->result_message);
        }
        else
        {
            throw invalid_argument("should not reach here");
        }
    }
}

void FlowApplyUTicket::self_device_send_r_ticket(string u_ticket_type, string u_ticket_id, string result_message)
{
    // [STAGE: (G)]
    json generated_request;
    generated_request["r_ticket_type"] = u_ticket_type;
    generated_request["device_id"] = shared_data->this_device.device_pub_key;
    generated_request["result"] = result_message;

    if (u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        if (result_message.find("SUCCESS") != string::npos)
        {
            generated_request["audit_start"] = u_ticket_id;
        }
    }
    else if (u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (result_message.find("SUCCESS") != string::npos)
        {
            generated_request["audit_start"] = shared_data->current_session.current_u_ticket_id;
            generated_request["audit_end"] = "ACCESS_END";
        }
    }
    else
    {
        throw invalid_argument("self_device_send_r_ticket: should not reach here");
    }
    std::string generated_r_ticket_json = msg_generator->self_generate_xxx_r_ticket(generated_request.dump());
    // cout << "debug: generated_r_ticket_json: " << generated_r_ticket_json << "\n";
    //  [STAGE: (S)]
    msg_sender->send_xxx_message(
        message::MESSAGE_VERIFY_AND_EXECUTE,
        r_ticket::MESSAGE_TYPE,
        generated_r_ticket_json);
}

void FlowApplyUTicket::self_holder_recv_r_ticket(RTicket received_r_ticket)
{
    //[STAGE: (R)(VR)]
    //[STAGE: (SR)]
    try
    {
        received_msg_storer->store_received_xxx_r_ticket(received_r_ticket);

        if (received_r_ticket.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET || received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET || received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (VL)(L)]
            std::string store_u_ticket_json = shared_data->device_table[received_r_ticket.device_id].device_u_ticket_for_owner;
            //[STAGE: (VR)]
            UTicket store_u_ticket = msg_verifier->self_classify_u_ticket_is_defined_type(store_u_ticket_json);

            // [STAGE: (VRT)]
            msg_verifier->verify_u_ticket_has_executed_through_r_ticket(received_r_ticket, store_u_ticket, UTicket());

            // [STAGE: (E)(O)]
            // cout << "debug: r_ticket_type: " << received_r_ticket.r_ticket_type << "\n";
            executor->self_execute_xxx_r_ticket(received_r_ticket, "holder-or-device");
            shared_data->result_message = "-> SUCCESS: VERIFY_UT_HAS_EXECUTED";
            // [STAGE: (C)]
            executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);
        }
        else
        {
            throw invalid_argument("self_holder_recv_r_ticket: should not reach here");
        }
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
    }
}

FlowIssueUTicket::FlowIssueUTicket(
    SharedData *shared_data,
    ReceivedMsgStorer *received_msg_storer,
    MsgVerifier *msg_verifier,
    Executor *executor,
    MsgGenerator *msg_generator,
    GeneratedMsgStorer *generated_msg_storer,
    MsgSender *msg_sender) : shared_data(shared_data),
                             received_msg_storer(received_msg_storer),
                             msg_verifier(msg_verifier),
                             executor(executor),
                             msg_generator(msg_generator),
                             generated_msg_storer(generated_msg_storer),
                             msg_sender(msg_sender) {}

void FlowIssueUTicket::issuer_issue_u_ticket_to_herself(const std::string &device_id, const std::string &arbitrary_dict)
{
    try
    {
        // [STAGE: (VL)]
        if (shared_data->device_table.find(device_id) != shared_data->device_table.end() || device_id == "no_id")
        {
            // [STAGE: (G)]
            std::string generated_u_ticket_json = msg_generator->self_generate_xxx_u_ticket(arbitrary_dict);

            // //cout << "debug: " << "generated_u_ticket_json = " << generated_u_ticket_json << "\n";
            // [STAGE: (SG)]
            generated_msg_storer->store_generated_xxx_u_ticket(generated_u_ticket_json);
            // //cout << "debug: " << "generated_u_ticket_json = " << generated_u_ticket_json << "\n";
            // [STAGE: (O)]
            RTicket r_ticket_in;
            executor->self_execute_update_ticket_order("holder-generate-or-receive-uticket", 1, uticket_from_json_str(generated_u_ticket_json), r_ticket_in);
        }
    }
    catch (const std::runtime_error &)
    {
        printf("error: FAILURE: (VUREQ)\n");
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

void FlowIssueUTicket::issuer_issue_u_ticket_to_holder(const std::string &device_id, const std::string &arbitrary_dict)
{
    try
    {
        // [STAGE: (VL)]
        if (shared_data->device_table.find(device_id) != shared_data->device_table.end())
        {
            // [STAGE: (G)]
            std::string generated_u_ticket_json = msg_generator->self_generate_xxx_u_ticket(arbitrary_dict);
            // [STAGE: (SG)]
            generated_msg_storer->store_generated_xxx_u_ticket(generated_u_ticket_json);
            // [STAGE: (S)]
            msg_sender->send_xxx_message(message::MESSAGE_RECV_AND_STORE, u_ticket::MESSAGE_TYPE, generated_u_ticket_json);
        }
    }
    catch (const std::out_of_range &)
    {
        shared_data->result_message = "FAILURE: (VL)";
        throw std::runtime_error(shared_data->result_message);
    }
    catch (const std::runtime_error &)
    {
        printf("error: FAILURE: (VUREQ)\n");
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish UT-UT~~ (issuer)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish UT-UT~~ (issuer)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
    {
        msg_sender->complete_simulated_comm();
    }
}

void FlowIssueUTicket::self_holder_recv_u_ticket(const UTicket &received_u_ticket)
{
    try
    {
        // [STAGE: (R)(VR)]

        // [STAGE: (SR)]
        received_msg_storer->store_received_xxx_u_ticket(received_u_ticket);

        // [STAGE: (O)]
        RTicket empty_r_ticket;
        executor->self_execute_update_ticket_order("holder-generate-or-receive-uticket", 1, received_u_ticket, empty_r_ticket);
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // [STAGE: (G)(S)]
    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish UT-UT~~ (holder)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish UT-UT~~ (holder)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
    {
        msg_sender->complete_simulated_comm();
    }
}

void FlowIssueUTicket::holder_send_r_ticket_to_issuer(const std::string &device_id)
{

    try
    {
        // [STAGE: (VL)(L)]
        std::string stored_r_ticket_json = shared_data->device_table[device_id].device_r_ticket_for_owner;

        // [STAGE: (S)]
        msg_sender->send_xxx_message(message::MESSAGE_RECV_AND_STORE, r_ticket::MESSAGE_TYPE, stored_r_ticket_json);
    }
    catch (const std::out_of_range &)
    {
        shared_data->result_message = "FAILURE: (VL)";
        throw std::runtime_error(shared_data->result_message);
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish RT-RT~~ (holder)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish RT-RT~~ (holder)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
    {
        msg_sender->complete_simulated_comm();
    }
}

void FlowIssueUTicket::self_issuer_recv_r_ticket(const RTicket &received_r_ticket)
{
    try
    {
        // [STAGE: (R)(VR)]

        // [STAGE: (SR)]
        received_msg_storer->store_received_xxx_r_ticket(received_r_ticket);

        if (received_r_ticket.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
            received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
            received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {

            std::string stored_u_ticket_json;
            if (received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
            {
                stored_u_ticket_json = shared_data->device_table.at(received_r_ticket.device_id).device_ownership_u_ticket_for_others;
            }
            else if (received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
            {
                stored_u_ticket_json = shared_data->device_table.at(received_r_ticket.device_id).device_access_u_ticket_for_others;
            }
            else
            {
                throw std::runtime_error("Shouldn't Reach Here");
            }
            // simple_log("debug", "Corresponding UTicket: " + stored_u_ticket_json);
            // //cout << "debug: Corresponding UTicket: " << stored_u_ticket_json << "\n";

            UTicket stored_u_ticket = msg_verifier->self_classify_u_ticket_is_defined_type(stored_u_ticket_json);

            UTicket empty_u_ticket;
            msg_verifier->verify_u_ticket_has_executed_through_r_ticket(received_r_ticket, stored_u_ticket, empty_u_ticket);

            executor->self_execute_xxx_r_ticket(received_r_ticket, "issuer");
            shared_data->result_message = "-> SUCCESS: VERIFY_UT_HAS_EXECUTED";

            executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);
        }
        else
        {
            throw std::runtime_error("Not implemented yet");
        }
    }
    catch (const std::out_of_range &)
    {
        shared_data->result_message = "FAILURE: (VL)";
        throw std::runtime_error(shared_data->result_message);
    }
    catch (const std::runtime_error &error)
    {
        shared_data->result_message = "FAILURE: (VR)(VRT)";
        throw std::runtime_error(shared_data->result_message);
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // simple_log("debug", "result_message = " + shared_data->result_message);
    // //cout << "debug: result_message = " << shared_data->result_message << "\n";

    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish RT-RT~~ (issuer)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish RT-RT~~ (issuer)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
    {
        msg_sender->complete_simulated_comm();
    }
}

void FlowIssueUToken::holder_send_cmd(const std::string &device_id, const std::string &cmd, bool access_end)
{
    try
    {
        // [STAGE: (VL)]
        if (shared_data->device_table.find(device_id) != shared_data->device_table.end())
        {
            //  [STAGE: (E)]
            executor->self_execute_ps("send-utoken", 0, UTicket(), RTicket(), cmd, "");
            std::string u_ticket_type;

            if (!access_end)
            {
                // [STAGE: (C)]
                executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_DATA);
                // [STAGE: (G)]
                u_ticket_type = u_ticket::TYPE_CMD_UTOKEN;
            }
            else
            {
                // [STAGE: (C)]
                executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_RT);
                // [STAGE: (G)]
                u_ticket_type = u_ticket::TYPE_ACCESS_END_UTOKEN;
            }
            // [STAGE: (G)]
            json generated_request;
            generated_request["device_id"] = shared_data->current_session.current_device_id;
            generated_request["u_ticket_type"] = u_ticket_type;
            generated_request["associated_plaintext_cmd"] = shared_data->current_session.associated_plaintext_cmd;
            generated_request["ciphertext_cmd"] = shared_data->current_session.ciphertext_cmd;
            generated_request["gcm_authentication_tag_cmd"] = shared_data->current_session.gcm_authentication_tag_cmd;
            generated_request["iv_data"] = shared_data->current_session.iv_data;

            std::string generated_u_ticket_json = msg_generator->self_generate_xxx_u_ticket(generated_request.dump());

            // [STAGE: (S)]
            msg_sender->send_xxx_message(message::MESSAGE_VERIFY_AND_EXECUTE, u_ticket::MESSAGE_TYPE, generated_u_ticket_json);
        }
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = "FAILURE: (VL)";
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}
void FlowIssueUToken::self_device_recv_cmd(const UTicket &received_u_token)
{
    try
    {
        // [STAGE: (R)(VR)]
        // [STAGE: (VUT)]
        msg_verifier->verify_u_ticket_can_execute(received_u_token);
        // [STAGE: (VTK)(VTS)]
        // [STAGE: (E)]
        executor->self_execute_xxx_u_ticket(received_u_token);

        printf("received_u_token: %s\n", received_u_token.to_json_str().c_str());
        shared_data->result_message = "-> SUCCESS: VERIFY_UT_CAN_EXECUT";

        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN)
        {
            // [STAGE: (C)]
            executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);
        }
        else if (received_u_token.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (C)]
            executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        }
        else
        {
            throw std::runtime_error("Shouldn't Reach Here");
        }

        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN)
        {
            // [STAGE: (G)(S)]
            self_device_send_data(shared_data->result_message);
        }
        else if (received_u_token.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (G)(S)]
            flow_apply_u_ticket->self_device_send_r_ticket(received_u_token.u_ticket_type, received_u_token.u_ticket_id, shared_data->result_message);
        }
        else
        {
            throw std::runtime_error("Shouldn't Reach Here");
        }
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);
        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN)
        {
            // [STAGE: (G)(S)]
            self_device_send_data(shared_data->result_message);
        }
        else if (received_u_token.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (G)(S)]
            flow_apply_u_ticket->self_device_send_r_ticket(received_u_token.u_ticket_type, received_u_token.u_ticket_id, shared_data->result_message);
        }
        else
        {
            throw std::runtime_error("Shouldn't Reach Here");
        }
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}
void FlowIssueUToken::self_device_send_data(const std::string &result_message)
{
    try
    {
        // [STAGE: (G)]
        json generated_request;
        if (result_message.find("SUCCESS") != std::string::npos)
        {
            generated_request["r_ticket_type"] = r_ticket::TYPE_DATA_RTOKEN;
            generated_request["device_id"] = shared_data->this_device.device_pub_key;
            generated_request["result"] = result_message;
            generated_request["audit_start"] = shared_data->current_session.current_u_ticket_id;
            generated_request["associated_plaintext_data"] = shared_data->current_session.associated_plaintext_data;
            generated_request["ciphertext_data"] = shared_data->current_session.ciphertext_data;
            generated_request["gcm_authentication_tag_data"] = shared_data->current_session.gcm_authentication_tag_data;
            generated_request["iv_cmd"] = shared_data->current_session.iv_cmd;
        }
        else
        {
            generated_request["r_ticket_type"] = r_ticket::TYPE_DATA_RTOKEN;
            generated_request["device_id"] = shared_data->this_device.device_pub_key;
            generated_request["result"] = result_message;
        }

        std::string generated_r_ticket_json = msg_generator->self_generate_xxx_r_ticket(generated_request.dump());

        // [STAGE: (S)]
        msg_sender->send_xxx_message(message::MESSAGE_VERIFY_AND_EXECUTE, r_ticket::MESSAGE_TYPE, generated_r_ticket_json);
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = "FAILURE: (C)";
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}
void FlowIssueUToken::self_holder_recv_data(const RTicket &received_r_token)
{
    try
    {
        // [STAGE: (R)(VR)]

        // Query Corresponding UTicket
        // [STAGE: (VL)(L)]
        std::string device_id = received_r_token.device_id;
        std::string stored_u_ticket_json = shared_data->device_table[device_id].device_u_ticket_for_owner;
        // [STAGE: (VR)]
        UTicket stored_u_ticket = msg_verifier->self_classify_u_ticket_is_defined_type(stored_u_ticket_json);
        // [STAGE: (VRT)]
        msg_verifier->verify_u_ticket_has_executed_through_r_ticket(received_r_token, stored_u_ticket, UTicket());

        // [STAGE: (VTK)]
        // [STAGE: (E)]
        executor->self_execute_xxx_r_ticket(received_r_token, "holder-or-device");
        shared_data->result_message = "-> SUCCESS: VERIFY_UT_HAS_EXECUTED";

        // [STAGE: (C)]
        executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = "FAILURE: (VR)";
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

bool check_result(string target, string result_message)
{
    return result_message.find(target) != string::npos;
}

void FlowOpenSession::self_device_send_cr_ke_1(string result_message)
{
    // [STAGE: (G)]
    // if "SUCCESS" in result_message:
    // cout << "Are you here? " << result_message << "\n";
    string generated_r_ticket;

    json r_ticket_request;
    if (check_result("SUCCESS", result_message))
    {
        r_ticket_request["r_ticket_type"] = r_ticket::TYPE_CRKE1_RTICKET;
        r_ticket_request["device_id"] = shared_data->this_device.device_pub_key;
        r_ticket_request["result"] = result_message;
        r_ticket_request["audit_start"] = shared_data->current_session.current_u_ticket_id;
        r_ticket_request["challenge_1"] = shared_data->current_session.challenge_1;
        r_ticket_request["key_exchange_salt_1"] = shared_data->current_session.key_exchange_salt_1;
        // cout << "Are you here? " << shared_data->current_session.iv_cmd << "\n";
        r_ticket_request["iv_cmd"] = shared_data->current_session.iv_cmd;
    }
    else
    {
        r_ticket_request["r_ticket_type"] = r_ticket::TYPE_CRKE1_RTICKET;
        r_ticket_request["device_id"] = shared_data->this_device.device_pub_key;
        r_ticket_request["result"] = result_message;
    }

    // cout << "Are you here? " << r_ticket_request.dump() << "\n";

    generated_r_ticket = msg_generator->self_generate_xxx_r_ticket(r_ticket_request.dump());

    // [STAGE: (S)]
    msg_sender->send_xxx_message(
        message::MESSAGE_VERIFY_AND_EXECUTE,
        r_ticket::MESSAGE_TYPE,
        generated_r_ticket);
}

void FlowOpenSession::self_holder_recv_cr_ke_1(RTicket received_r_ticket)
{
    try
    {
        // [STAGE: (R)(VR)]
        // [STAGE: (VRT)]
        UTicket empty_u_ticket;
        msg_verifier->verify_u_ticket_has_executed_through_r_ticket(received_r_ticket, empty_u_ticket, empty_u_ticket);

        // [STAGE: (E)]
        executor->self_execute_xxx_r_ticket(received_r_ticket, "holder-or-device");

        shared_data->result_message = "SUCCESS: VERIFY_UT_HAS_EXECUTED";

        // [STAGE: (C)]
        executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_CRKE3);

        // [STAGE: (G)(S)]
        self_holder_send_cr_ke_2(shared_data->result_message);

        // TODO: try and error
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

void FlowOpenSession::self_holder_send_cr_ke_2(string result_message)
{
    // [STAGE: (G)]
    // if "SUCCESS" in result_message:
    json r_ticket_request;

    r_ticket_request["r_ticket_type"] = r_ticket::TYPE_CRKE2_RTICKET;
    r_ticket_request["device_id"] = shared_data->current_session.current_device_id;
    r_ticket_request["result"] = result_message;
    r_ticket_request["audit_start"] = shared_data->current_session.current_u_ticket_id;
    r_ticket_request["challenge_1"] = shared_data->current_session.challenge_1;
    r_ticket_request["challenge_2"] = shared_data->current_session.challenge_2;
    r_ticket_request["key_exchange_salt_2"] = shared_data->current_session.key_exchange_salt_2;
    r_ticket_request["associated_plaintext_cmd"] = shared_data->current_session.associated_plaintext_cmd;
    r_ticket_request["ciphertext_cmd"] = shared_data->current_session.ciphertext_cmd;
    r_ticket_request["gcm_authentication_tag_cmd"] = shared_data->current_session.gcm_authentication_tag_cmd;
    r_ticket_request["iv_data"] = shared_data->current_session.iv_data;

    string generated_r_ticket = msg_generator->self_generate_xxx_r_ticket(r_ticket_request.dump());

    // [STAGE: (S)]
    msg_sender->send_xxx_message(
        message::MESSAGE_VERIFY_AND_EXECUTE,
        r_ticket::MESSAGE_TYPE,
        generated_r_ticket);
}

void FlowOpenSession::self_device_recv_cr_ke_2(RTicket received_r_ticket)
{
    try
    {
        // [STAGE: (VRT)]
        UTicket empty_u_ticket;
        msg_verifier->verify_u_ticket_has_executed_through_r_ticket(received_r_ticket, empty_u_ticket, empty_u_ticket);

        // [STAGE: (E)]
        executor->self_execute_xxx_r_ticket(received_r_ticket, "holder-or-device");

        shared_data->result_message = "SUCCESS: VERIFY_UT_HAS_EXECUTED";

        // [STAGE: (C)]
        executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);

        // [STAGE: (G)(S)]
        self_device_send_cr_ke_3(shared_data->result_message);
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        // [STATE: (G)(S)]
        self_device_send_cr_ke_3(shared_data->result_message);
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

void FlowOpenSession::self_device_send_cr_ke_3(string result_message)
{
    // [STAGE: (G)]
    // if "SUCCESS" in result_message:
    json r_ticket_request;

    if (check_result("SUCCESS", result_message))
    {
        r_ticket_request["r_ticket_type"] = r_ticket::TYPE_CRKE3_RTICKET;
        r_ticket_request["device_id"] = shared_data->this_device.device_pub_key;
        r_ticket_request["result"] = result_message;
        r_ticket_request["audit_start"] = shared_data->current_session.current_u_ticket_id;
        r_ticket_request["challenge_2"] = shared_data->current_session.challenge_2;
        r_ticket_request["key_exchange_salt_2"] = shared_data->current_session.key_exchange_salt_2;
        r_ticket_request["associated_plaintext_data"] = shared_data->current_session.associated_plaintext_data;
        r_ticket_request["ciphertext_data"] = shared_data->current_session.ciphertext_data;
        r_ticket_request["gcm_authentication_tag_data"] = shared_data->current_session.gcm_authentication_tag_data;
        r_ticket_request["iv_cmd"] = shared_data->current_session.iv_cmd;
    }
    else
    {
        r_ticket_request["r_ticket_type"] = r_ticket::TYPE_CRKE3_RTICKET;
        r_ticket_request["device_id"] = shared_data->this_device.device_pub_key;
        r_ticket_request["result"] = result_message;
    }

    string generated_r_ticket = msg_generator->self_generate_xxx_r_ticket(r_ticket_request.dump());

    // [STAGE: (S)]
    msg_sender->send_xxx_message(
        message::MESSAGE_VERIFY_AND_EXECUTE,
        r_ticket::MESSAGE_TYPE,
        generated_r_ticket);
}

void FlowOpenSession::self_holder_recv_cr_ke_3(RTicket received_r_ticket)
{
    try
    {
        // [STAGE: (R)(VR)]
        // [STAGE: (VRT)]
        UTicket empty_u_ticket;
        msg_verifier->verify_u_ticket_has_executed_through_r_ticket(received_r_ticket, empty_u_ticket, empty_u_ticket);

        // [STAGE: (E)]
        executor->self_execute_xxx_r_ticket(received_r_ticket, "holder-or-device");

        shared_data->result_message = "SUCCESS: VERIFY_UT_HAS_EXECUTED";

        // [STAGE: (C)]
        executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);

        // cout << "debug: " << shared_data->this_device.device_name << " manually finish CR-KE~~ (holder)\n";
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

DeviceController::DeviceController(const std::string &device_type, const std::string &device_name)
{
    initialize();

    // 设置设备类型（必须在加载存储后进行）
    if (!shared_data->this_device.has_device_type)
    {
        executor->self_execute_one_time_set_time_device_type_and_name(device_type, device_name);
        printf("info: Set device type and name to %s, %s\n", device_type.c_str(), device_name.c_str());
    }

    // 设置初始化状态
    executor->self_initialize_state();

    // simple_log("info", "+ Here is a " + shared_data->this_device.device_name + "...");
    printf("info: Here is a %s...\n", shared_data->this_device.device_name.c_str());
}

DeviceController::~DeviceController()
{
    cleanup();
}

void DeviceController::reboot_device()
{
    // simple_log("info", "+ Reboot " + shared_data->this_device.device_name + "...");
    printf("info: Reboot %s...\n", shared_data->this_device.device_name.c_str());
    cleanup();
    initialize();
}

void DeviceController::initialize()
{
    // 初始化所有组件
    shared_data = new SharedData();
    simple_storage = new SimpleStorage(shared_data->this_device.device_name);
    // measure_helper = new MeasureHelper(shared_data);

    // 初始化 Stage Workers
    received_msg_storer = new ReceivedMsgStorer(shared_data, simple_storage);
    msg_verifier = new MsgVerifier(shared_data);
    executor = new Executor(shared_data /*, simple_storage, msg_verifier*/);
    msg_generator = new MsgGenerator(shared_data);
    generated_msg_storer = new GeneratedMsgStorer(shared_data /*, *simple_storage*/);
    msg_sender = new MsgSender(shared_data);

    // 初始化 Flows
    flow_issuer_issue_u_ticket = new FlowIssueUTicket(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender);
    flow_open_session = new FlowOpenSession(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender);
    flow_apply_u_ticket = new FlowApplyUTicket(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender, flow_open_session);
    flow_issue_u_token = new FlowIssueUToken(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender, flow_apply_u_ticket);

    // 初始化 MsgReceiver
    msg_receiver = new MsgReceiver(shared_data, msg_verifier, executor, msg_sender, flow_issuer_issue_u_ticket, flow_apply_u_ticket, flow_open_session, flow_issue_u_token);

    // 加载存储
    simple_storage->load_storage(shared_data->this_device, shared_data->device_table, shared_data->this_person, shared_data->current_session);
}

void DeviceController::cleanup()
{
    delete msg_receiver;
    // delete flow_issue_u_token;
    // delete flow_apply_u_ticket;
    // delete flow_open_session;
    delete flow_issuer_issue_u_ticket;
    delete msg_sender;
    delete generated_msg_storer;
    delete msg_generator;
    delete executor;
    delete msg_verifier;
    delete received_msg_storer;
    // delete  _helper;
    delete simple_storage;
    delete shared_data;
}