#include "flow_open_session.hpp"

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