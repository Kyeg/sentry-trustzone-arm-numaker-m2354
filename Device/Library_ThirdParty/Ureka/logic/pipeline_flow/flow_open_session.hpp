#ifndef FLOW_OPEN_SESSION_HPP
#define FLOW_OPEN_SESSION_HPP

#include "shared_data.hpp"
#include "current_session.hpp"
#include "msg_verifier.hpp"
#include "executor.hpp"
#include "msg_generator.hpp"
#include "r_ticket.hpp"
#include "generated_msg_storer.hpp"
#include "received_msg_storer.hpp"
#include "msg_sender.hpp"

#include <string>

using namespace std;

class FlowOpenSession
{
private:
    SharedData *shared_data;
    MsgVerifier *msg_verifier;
    Executor *executor;
    MsgGenerator *msg_generator;
    MsgSender *msg_sender;

public:
    /*####################################################
    # [PIPELINE FLOW]
    #
    # APY (CR-KE):
    #       holder_apply_u_ticket() -> _device_recv_u_ticket()
    #       _holder_recv_cr_ke_1() <- _device_send_cr_ke_1()
    #       _holder_send_cr_ke_2() -> _device_recv_cr_ke_2()
    #       _holder_recv_cr_ke_3() <- _device_send_cr_ke_3()
    ####################################################*/

    FlowOpenSession(SharedData *shared_data, MsgVerifier *msg_verifier, Executor *executor, MsgGenerator *msg_generator, MsgSender *msg_sender)
    {
        this->shared_data = shared_data;
        // this->measure_helper = measure_helper;
        this->msg_verifier = msg_verifier;
        this->executor = executor;
        this->msg_generator = msg_generator;
        this->msg_sender = msg_sender;
    }

    void self_device_send_cr_ke_1(string result_message);
    // void self_holder_recv_cr_ke_1(RTicket received_r_ticket);
    // void self_holder_send_cr_ke_2(string result_message);
    void self_device_recv_cr_ke_2(RTicket received_r_ticket);
    void self_device_send_cr_ke_3(string result_message);
    // void self_holder_recv_cr_ke_3(RTicket received_r_ticket);
};

#endif // FLOW_OPEN_SESSION_HPP