#ifndef MSG_VERIFIER_HPP
#define MSG_VERIFIER_HPP
#include <string>
#include "shared_data.hpp"
#include "u_ticket.hpp"
#include "r_ticket.hpp"
#include "msg_verifier_u_ticket.hpp"
#include "msg_verifier_r_ticket.hpp"
#include "msg_verifier_message.hpp"

class MsgVerifier
{
public:
    SharedData *shared_data;

    MsgVerifier(SharedData *shared_data) : shared_data(shared_data) {};

    MsgVerifier() {};

    MsgVerifier(const MsgVerifier &msg_verifier)
    {
        shared_data = msg_verifier.shared_data;
    }

    /*####################################################
    # [STAGE: (V)] Verify Message & Execute
    #   (VR): classify_message_is_defined_type
    #   (VL): has_u_ticket_in_device_table
    #   (VUT): verify_u_ticket_can_execute
    #   (VRT): verify_u_ticket_has_executed_through_r_ticket
    #   (VTK): verify_token_through_hmac (when _execute_decrypt_ciphertext)
    #   (VTS): verify_cmd_is_in_task_scope
    ####################################################*/

    pair<UTicket, RTicket> self_classify_message_is_defined_type(string arbitrary_json);

    UTicket self_classify_u_ticket_is_defined_type(string arbitrary_json);

    RTicket self_classify_r_ticket_is_defined_type(string arbitrary_json);

    void verify_u_ticket_can_execute(UTicket u_ticket_in);

    void verify_u_ticket_has_executed_through_r_ticket(RTicket r_ticket_in, UTicket audit_start_ticket, UTicket audit_end_ticket);

    void verify_cmd_is_in_task_scope(string cmd);
};

#endif // MSG_VERIFIER_HPP