#ifndef FLOW_ISSUE_U_TICKET_HPP
#define FLOW_ISSUE_U_TICKET_HPP
#include "shared_data.hpp"
// #include "measure_helper.hpp"
#include "msg_verifier.hpp"
#include "executor.hpp"
#include "msg_generator.hpp"
#include "msg_sender.hpp"
#include "u_ticket.hpp"
#include "r_ticket.hpp"
#include "environment.hpp"
#include <string>

class FlowIssueUTicket
{
public:
    FlowIssueUTicket(
        SharedData *shared_data,
        MsgVerifier *msg_verifier,
        Executor *executor,
        MsgGenerator *msg_generator,
        MsgSender *msg_sender);

    void issuer_issue_u_ticket_to_herself(const std::string &device_id, const std::string &arbitrary_dict);
    void issuer_issue_u_ticket_to_holder(const std::string &device_id, const std::string &arbitrary_dict);
    void self_holder_recv_u_ticket(const UTicket &received_u_ticket);
    void holder_send_r_ticket_to_issuer(const std::string &device_id);
    void self_issuer_recv_r_ticket(const RTicket &received_r_ticket);

private:
    SharedData *shared_data;
    MsgVerifier *msg_verifier;
    Executor *executor;
    MsgGenerator *msg_generator;
    MsgSender *msg_sender;
};

#endif