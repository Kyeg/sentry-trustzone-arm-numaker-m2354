#ifndef MSG_VERIFIER_R_TICKET_HPP
#define MSG_VERIFIER_R_TICKET_HPP
#include "current_session.hpp"
#include "other_device.hpp"
#include "r_ticket.hpp"
#include "this_device.hpp"
#include "u_ticket.hpp"
#include <string>

using namespace std;

class RTicketVerifier {
  public:
    ThisDevice this_device;
    UTicket audit_start_ticket;
    UTicket audit_end_ticket;
    map<string, OtherDevice> device_table;
    CurrentSession current_session;

    RTicketVerifier(ThisDevice this_device, UTicket audit_start_ticket,
                    UTicket audit_end_ticket,
                    map<string, OtherDevice> device_table,
                    CurrentSession current_session) {
        this->this_device = this_device;
        this->audit_start_ticket = audit_start_ticket;
        this->audit_end_ticket = audit_end_ticket;
        this->device_table = device_table;
        this->current_session = current_session;
    };

    RTicketVerifier(ThisDevice this_device) {
        this->this_device = this_device;
    };

    RTicket verify_json_schema(const string &arbitrary_json);

    RTicket verify_protocol_version(RTicket r_ticket_in);

    RTicket verify_r_ticket_id(RTicket r_ticket_in);

    RTicket verify_r_ticket_type(RTicket r_ticket_in);

    RTicket has_device_id(RTicket r_ticket_in);

    RTicket verify_device_id(RTicket r_ticket_in);

    RTicket verify_result(RTicket r_ticket_in);

    RTicket verify_ticket_order(RTicket r_ticket_in);

    RTicket verify_audit_start(RTicket r_ticket_in);

    RTicket verify_audit_end(RTicket r_ticket_in);

    RTicket verify_cr_key(RTicket r_ticket_in);

    RTicket verify_ps(RTicket r_ticket_in);

    RTicket verify_device_signature(RTicket r_ticket_in);

    /*####################################################
    # Verify ECC Signature on RTicket
    ####################################################*/

    bool self_verify_device_signature_on_r_ticket(RTicket signed_r_ticket,
                                                  const string &public_key);
};

#endif