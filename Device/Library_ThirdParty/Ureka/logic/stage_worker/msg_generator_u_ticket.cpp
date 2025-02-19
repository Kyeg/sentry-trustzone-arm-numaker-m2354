#include "msg_generator_u_ticket.hpp"
#include <string>
#include <cstdlib>

#include "ecdsa.h"
#include "sha256.h"

// #include "../../model/data_model/this_device.hpp"
// #include "../../model/data_model/this_person.hpp"
// #include "../../model/data_model/other_device.hpp"
#include "myecdh.hpp"

using namespace std;

extern "C"
{
    extern size_t sign_message(const char *message, mbedtls_ecdsa_context key, unsigned char *signature);
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