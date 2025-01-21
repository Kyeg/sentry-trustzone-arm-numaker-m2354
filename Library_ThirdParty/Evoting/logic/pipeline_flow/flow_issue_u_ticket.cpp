#include "flow_issue_u_ticket.hpp"

#include <stdexcept>

FlowIssueUTicket::FlowIssueUTicket(
    SharedData* shared_data,
    ReceivedMsgStorer* received_msg_storer,
    MsgVerifier* msg_verifier,
    Executor* executor,
    MsgGenerator* msg_generator,
    GeneratedMsgStorer* generated_msg_storer,
    MsgSender* msg_sender
) : shared_data(shared_data),
    received_msg_storer(received_msg_storer),
    msg_verifier(msg_verifier),
    executor(executor),
    msg_generator(msg_generator),
    generated_msg_storer(generated_msg_storer),
    msg_sender(msg_sender) {}

void FlowIssueUTicket::issuer_issue_u_ticket_to_herself(const std::string& device_id, const std::string& arbitrary_dict) {
    try {
        // [STAGE: (VL)]
        if (shared_data->device_table.find(device_id) != shared_data->device_table.end() || device_id == "no_id") {
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
    } catch (const std::runtime_error&) {
        printf("error: FAILURE: (VUREQ)\n");
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

void FlowIssueUTicket::issuer_issue_u_ticket_to_holder(const std::string& device_id, const std::string& arbitrary_dict) {
    try {
        // [STAGE: (VL)]
        if (shared_data->device_table.find(device_id) != shared_data->device_table.end()) {
            // [STAGE: (G)]
            std::string generated_u_ticket_json = msg_generator->self_generate_xxx_u_ticket(arbitrary_dict);
            // [STAGE: (SG)]
            generated_msg_storer->store_generated_xxx_u_ticket(generated_u_ticket_json);
            // [STAGE: (S)]
            msg_sender->send_xxx_message(message::MESSAGE_RECV_AND_STORE, u_ticket::MESSAGE_TYPE, generated_u_ticket_json);
        }
    } catch (const std::out_of_range&) {
        shared_data->result_message = "FAILURE: (VL)";
        throw std::runtime_error(shared_data->result_message);
    } catch (const std::runtime_error&) {
        printf("error: FAILURE: (VUREQ)\n");
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish UT-UT~~ (issuer)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish UT-UT~~ (issuer)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED") {
        msg_sender->complete_simulated_comm();
    }
}

void FlowIssueUTicket::self_holder_recv_u_ticket(const UTicket& received_u_ticket) {
    try {
        // [STAGE: (R)(VR)]

        // [STAGE: (SR)]
        received_msg_storer->store_received_xxx_u_ticket(received_u_ticket);

        // [STAGE: (O)]
        RTicket empty_r_ticket;
        executor->self_execute_update_ticket_order("holder-generate-or-receive-uticket", 1, received_u_ticket, empty_r_ticket);
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // [STAGE: (G)(S)]
    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish UT-UT~~ (holder)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish UT-UT~~ (holder)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED") {
        msg_sender->complete_simulated_comm();
    }
}

void FlowIssueUTicket::holder_send_r_ticket_to_issuer(const std::string& device_id) {

    try {
        // [STAGE: (VL)(L)]
        std::string stored_r_ticket_json = shared_data->device_table[device_id].device_r_ticket_for_owner;


        // [STAGE: (S)]
        msg_sender->send_xxx_message(message::MESSAGE_RECV_AND_STORE, r_ticket::MESSAGE_TYPE, stored_r_ticket_json);
    } catch (const std::out_of_range&) {
        shared_data->result_message = "FAILURE: (VL)";
        throw std::runtime_error(shared_data->result_message);
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish RT-RT~~ (holder)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish RT-RT~~ (holder)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED") {
        msg_sender->complete_simulated_comm();
    }
}

void FlowIssueUTicket::self_issuer_recv_r_ticket(const RTicket& received_r_ticket) {
    try {
        // [STAGE: (R)(VR)]

        // [STAGE: (SR)]
        received_msg_storer->store_received_xxx_r_ticket(received_r_ticket);

        if (received_r_ticket.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
            received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
            received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN) {
            
            std::string stored_u_ticket_json;
            if (received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET) {
                stored_u_ticket_json = shared_data->device_table.at(received_r_ticket.device_id).device_ownership_u_ticket_for_others;
            } else if (received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN) {
                stored_u_ticket_json = shared_data->device_table.at(received_r_ticket.device_id).device_access_u_ticket_for_others;
            } else {
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
        } else {
            throw std::runtime_error("Not implemented yet");
        }
    } catch (const std::out_of_range&) {
        shared_data->result_message = "FAILURE: (VL)";
        throw std::runtime_error(shared_data->result_message);
    } catch (const std::runtime_error& error) {
        shared_data->result_message = "FAILURE: (VR)(VRT)";
        throw std::runtime_error(shared_data->result_message);
    } catch (...) {
        throw std::runtime_error("Shouldn't Reach Here");
    }

    // simple_log("debug", "result_message = " + shared_data->result_message);
    // //cout << "debug: result_message = " << shared_data->result_message << "\n";

    // simple_log("debug", "+ " + shared_data->this_device.device_name + " manually finish RT-RT~~ (issuer)");
    // //cout << "debug: + " << shared_data->this_device.device_name << " manually finish RT-RT~~ (issuer)" << "\n";
    if (Environment::COMMUNICATION_CHANNEL == "SIMULATED") {
        msg_sender->complete_simulated_comm();
    }
}