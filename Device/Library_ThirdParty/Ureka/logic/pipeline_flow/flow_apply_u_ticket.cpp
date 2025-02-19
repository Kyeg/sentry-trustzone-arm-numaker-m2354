#include "flow_apply_u_ticket.hpp"
#include "flow_issue_u_ticket.hpp"
#include "flow_issue_u_token.hpp"
#include "flow_open_session.hpp"

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