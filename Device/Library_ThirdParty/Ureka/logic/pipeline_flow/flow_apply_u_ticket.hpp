#ifndef FLOW_APPLY_U_TICKET_HPP
#define FLOW_APPLY_U_TICKET_HPP

#include <string>
#include "shared_data.hpp"
#include "current_session.hpp"
#include "msg_verifier.hpp"
#include "executor.hpp"
#include "msg_generator.hpp"
#include "r_ticket.hpp"
#include "u_ticket.hpp"
#include "flow_open_session.hpp"

class FlowApplyUTicket
{
private:
    SharedData *shared_data;
    // MeasureHelper measure_helper;
    MsgVerifier *msg_verifier;
    Executor *executor;
    MsgGenerator *msg_generator;
    MsgSender *msg_sender;
    FlowOpenSession *flow_open_session;

public:
    /*####################################################
    # [PIPELINE FLOW]
    #
    # APY (No CR):
    #       holder_apply_u_ticket() -> _device_recv_u_ticket()
    #       _holder_recv_r_ticket() <- _device_send_r_ticket()
    ####################################################*/

    FlowApplyUTicket(SharedData *shared_data, MsgVerifier *msg_verifier, Executor *executor, MsgGenerator *msg_generator, MsgSender *msg_sender, FlowOpenSession *flow_open_session)
    {
        this->shared_data = shared_data;
        // this->measure_helper = measure_helper;
        this->msg_verifier = msg_verifier;
        this->executor = executor;
        this->msg_generator = msg_generator;
        this->msg_sender = msg_sender;
        this->flow_open_session = flow_open_session;
    }

    // void holder_apply_u_ticket(string device_id, string cmd = "");

    void self_device_recv_u_ticket(UTicket received_u_ticket);

    void self_device_send_r_ticket(string u_ticket_type, string u_ticket_id, string result_message);

    // void self_holder_recv_r_ticket(RTicket received_r_ticket);
};

#endif // FLOW_APPLY_U_TICKET_HPP