#include "msg_generator_r_ticket.hpp"
#include <string>
#include <cstdlib>

#include "ecdsa.h"
#include "sha256.h"
#include "r_ticket.hpp"
#include "u_ticket.hpp"

#include "myecdh.hpp"

using namespace std;

extern "C"
{
    extern size_t sign_message(const char *message, mbedtls_ecdsa_context key, unsigned char *signature);
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