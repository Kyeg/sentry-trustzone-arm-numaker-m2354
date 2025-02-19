#ifndef FLOW_ISSUE_U_TOKEN_HPP
#define FLOW_ISSUE_U_TOKEN_HPP

#include "shared_data.hpp"
#include "received_msg_storer.hpp"
#include "msg_verifier.hpp"
#include "executor.hpp"
#include "msg_generator.hpp"
#include "generated_msg_storer.hpp"
#include "msg_sender.hpp"
#include "flow_apply_u_ticket.hpp"

class FlowIssueUToken
{
private:
    SharedData *shared_data;
    // MeasureHelper measure_helper;
    MsgVerifier *msg_verifier;
    Executor *executor;
    MsgGenerator *msg_generator;
    MsgSender *msg_sender;
    FlowApplyUTicket *flow_apply_u_ticket;

public:
    FlowIssueUToken(SharedData *shared_data, MsgVerifier *msg_verifier, Executor *executor, MsgGenerator *msg_generator, MsgSender *msg_sender, FlowApplyUTicket *flow_apply_u_ticket)
    {
        this->shared_data = shared_data;
        // this->measure_helper = measure_helper;
        this->msg_verifier = msg_verifier;
        this->executor = executor;
        this->msg_generator = msg_generator;
        this->msg_sender = msg_sender;
        this->flow_apply_u_ticket = flow_apply_u_ticket;
    }

    // void holder_send_cmd(const std::string& device_id, const std::string& cmd, bool access_end = false);
    void self_device_recv_cmd(UTicket &received_u_token);
    void self_device_send_data(const std::string &result_message);
    // void self_holder_recv_data(const RTicket& received_r_token);
};

// flow_issue_u_token = new FlowIssueUToken(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender, flow_apply_u_ticket);

#endif