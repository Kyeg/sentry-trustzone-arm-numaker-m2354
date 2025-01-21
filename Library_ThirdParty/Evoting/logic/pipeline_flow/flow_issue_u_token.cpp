#include "flow_issue_u_token.hpp"
void FlowIssueUToken::holder_send_cmd(const std::string& device_id, const std::string& cmd, bool access_end) {
    try {
        // [STAGE: (VL)]
        if (shared_data->device_table.find(device_id) != shared_data->device_table.end()) {
            //  [STAGE: (E)]
            executor->self_execute_ps("send-utoken", 0, UTicket(), RTicket(), cmd, "");
            std::string u_ticket_type;

            if (!access_end) {
                // [STAGE: (C)]
                executor->self_change_state(this_device::STATE_AGENT_WAIT_FOR_DATA);
                // [STAGE: (G)]
                u_ticket_type = u_ticket::TYPE_CMD_UTOKEN;
            } else {
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
    } catch (const std::runtime_error& e) {
        shared_data->result_message = "FAILURE: (VL)";
        throw;
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}
void FlowIssueUToken::self_device_recv_cmd(const UTicket& received_u_token) {
    try {
        // [STAGE: (R)(VR)]
        // [STAGE: (VUT)]
        msg_verifier->verify_u_ticket_can_execute(received_u_token);
        // [STAGE: (VTK)(VTS)]
        // [STAGE: (E)]
        executor->self_execute_xxx_u_ticket(received_u_token);
        
        printf("received_u_token: %s\n", received_u_token.to_json_str().c_str());
        shared_data->result_message = "-> SUCCESS: VERIFY_UT_CAN_EXECUT";

        
        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN) {
            // [STAGE: (C)]
            executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);
        } else if (received_u_token.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN) {
            // [STAGE: (C)]
            executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        } else {
            throw std::runtime_error("Shouldn't Reach Here");
        }



        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN) {
            // [STAGE: (G)(S)]
            self_device_send_data(shared_data->result_message);
        }else if (received_u_token.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN) {
            // [STAGE: (G)(S)]
            flow_apply_u_ticket->self_device_send_r_ticket(received_u_token.u_ticket_type, received_u_token.u_ticket_id, shared_data->result_message);
        } else {
            throw std::runtime_error("Shouldn't Reach Here");
        }
    } catch (const std::runtime_error& e) {
        shared_data->result_message = e.what();
        executor->self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);
        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN) {
            // [STAGE: (G)(S)]
            self_device_send_data(shared_data->result_message);
        }else if (received_u_token.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN) {
            // [STAGE: (G)(S)]
            flow_apply_u_ticket->self_device_send_r_ticket(received_u_token.u_ticket_type, received_u_token.u_ticket_id, shared_data->result_message);
        } else {
            throw std::runtime_error("Shouldn't Reach Here");
        }
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}
void FlowIssueUToken::self_device_send_data(const std::string& result_message) {
    try {
        // [STAGE: (G)]
        json generated_request;
        if (result_message.find("SUCCESS") != std::string::npos) {
            generated_request["r_ticket_type"] = r_ticket::TYPE_DATA_RTOKEN;
            generated_request["device_id"] = shared_data->this_device.device_pub_key;
            generated_request["result"] = result_message;
            generated_request["audit_start"] = shared_data->current_session.current_u_ticket_id;
            generated_request["associated_plaintext_data"] = shared_data->current_session.associated_plaintext_data;
            generated_request["ciphertext_data"] = shared_data->current_session.ciphertext_data;
            generated_request["gcm_authentication_tag_data"] = shared_data->current_session.gcm_authentication_tag_data;
            generated_request["iv_cmd"] = shared_data->current_session.iv_cmd;
        } else {
            generated_request["r_ticket_type"] = r_ticket::TYPE_DATA_RTOKEN;
            generated_request["device_id"] = shared_data->this_device.device_pub_key;
            generated_request["result"] = result_message;
        }

        std::string generated_r_ticket_json = msg_generator->self_generate_xxx_r_ticket(generated_request.dump());

        

        // [STAGE: (S)]
        msg_sender->send_xxx_message(message::MESSAGE_VERIFY_AND_EXECUTE, r_ticket::MESSAGE_TYPE, generated_r_ticket_json);

    } catch (const std::runtime_error& e) {
        shared_data->result_message = "FAILURE: (C)";
        throw;
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}
void FlowIssueUToken::self_holder_recv_data(const RTicket& received_r_token) {
    try {
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

    } catch (const std::runtime_error& e) {
        shared_data->result_message = "FAILURE: (VR)";
        throw;
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}